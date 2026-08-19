//! Query traversal: what a `SELECT` — or any query nested inside another
//! statement — puts in scope, and the walk that reaches every rewrite site
//! inside it.
//!
//! Two jobs meet here. Building the [`TableScope`] a predicate resolves names
//! against is one: which relations a `FROM`, its joins, its derived tables and
//! its CTEs bring into scope, and under which aliases. Walking a query so that
//! every place a predicate can hide — a join constraint, a `WHERE`, a
//! `HAVING`, a set operation's two halves, a derived table's own query — is
//! visited is the other.
//!
//! The walk is deliberately exhaustive rather than clever: a shape it fails to
//! descend into is a predicate relayed unrewritten, which is the silent
//! wrong-rows failure the whole rewrite exists to prevent.

use sqlparser::ast::{
    Expr, GroupByExpr, Ident, JoinConstraint, JoinOperator, ObjectName, Query, Select, SelectItem,
    SetExpr, TableFactor, TableWithJoins,
};

use crate::portal::ParamTransforms;

use super::catalog::{normalize, Columns, ReadColumns};
use super::scope::{computed_protected_column, expr_shape, ScopedTable, TableScope};
use super::unprotected::Unprotected;
use super::{QueryRewriter, Rejection};

impl QueryRewriter {
    /// [`Self::table`] for scope building: both directions of one table from a
    /// single lookup, so an unresolvable `search_path` is reported once rather
    /// than once per direction. See [`WriteCatalog::scoped`](super::catalog::WriteCatalog::scoped).
    ///
    /// The `search_path` guard is the read direction's, which is the wider of
    /// the two: a table whose only protected column is mask-only is not in
    /// [`WriteCatalog::may_be_protected`](super::catalog::WriteCatalog::may_be_protected) at all, and a scope that dropped it
    /// on an untrusted `search_path` would leave the projection check blind to
    /// the one case where the stored value is the plaintext.
    fn scoped_table(
        &self,
        name: &ObjectName,
    ) -> Result<Option<(&Columns, &ReadColumns)>, Rejection> {
        if self.search_path_trusted || name.0.len() > 1 {
            return Ok(self.catalog.scoped(name));
        }
        if self.catalog.may_protect_reads(name) {
            self.unprotected(&Unprotected::SearchPath(name))?;
        }
        Ok(None)
    }

    /// Walks a query: CTE bodies, set-operation branches and the select
    /// itself, so a searchable predicate is rewritten wherever it sits.
    pub(super) fn rewrite_query(
        &self,
        query: &mut Query,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let mut changed = false;
        if let Some(with) = query.with.as_mut() {
            for cte in &mut with.cte_tables {
                changed |= self.rewrite_query(&mut cte.query, params)?;
            }
        }
        changed |= self.rewrite_set_expr(&mut query.body, params)?;
        if let Some(order_by) = query.order_by.as_mut() {
            for order in &mut order_by.exprs {
                changed |= self.rewrite_nested_queries(&mut order.expr, params)?;
            }
        }
        Ok(changed)
    }

    fn rewrite_set_expr(
        &self,
        body: &mut SetExpr,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        match body {
            SetExpr::Select(select) => self.rewrite_select(select, params),
            SetExpr::Query(query) => self.rewrite_query(query, params),
            SetExpr::SetOperation { left, right, .. } => {
                let left = self.rewrite_set_expr(left, params)?;
                let right = self.rewrite_set_expr(right, params)?;
                Ok(left | right)
            }
            // A data-modifying CTE: `WITH x AS (INSERT ... RETURNING ...)`.
            SetExpr::Insert(statement) | SetExpr::Update(statement) => {
                self.rewrite_statement(statement, params)
            }
            SetExpr::Values(_) | SetExpr::Table(_) => Ok(false),
        }
    }

    fn rewrite_select(
        &self,
        select: &mut Select,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let scope = self.scope(&select.from)?;
        let mut changed = self.rewrite_join_conditions(&mut select.from, &scope, params)?;
        changed |= self.rewrite_derived_tables(&mut select.from, params)?;
        for predicate in [select.selection.as_mut(), select.having.as_mut()].into_iter().flatten() {
            changed |= self.rewrite_predicate(predicate, &scope, params)?;
        }
        // Subqueries sitting in an *expression* rather than in FROM. These
        // carry their own FROM, so they are walked by `rewrite_query` against
        // their own scope; the predicate pass above deliberately stops at the
        // subquery boundary, which is what keeps each query rewritten once.
        // A protected column computed over in the projection loses its table
        // identity on the way back, so the read path cannot act on it. Decided
        // here, where the statement still says which column it was.
        for item in &select.projection {
            if let Some((column, expr)) = computed_protected_column(item, &scope) {
                self.unprotected(&Unprotected::ComputedColumn { column, shape: expr_shape(expr) })?;
            }
        }
        for expr in select_expressions(select) {
            changed |= self.rewrite_nested_queries(expr, params)?;
        }
        Ok(changed)
    }

    /// Rewrites the derived tables of a relation list against their own
    /// scopes.
    ///
    /// A derived table carries its own FROM, so its predicates belong to its
    /// own traversal rather than the enclosing one. Every clause that holds
    /// relations needs this pass, not only `SELECT`: `UPDATE ... FROM (SELECT
    /// ...)` and `DELETE ... USING (SELECT ...)` walked their own `WHERE` but
    /// never descended into the subquery next to it, so a searchable equality
    /// in there was left comparing plaintext against the stored form — no
    /// rewrite, no signal, and no rows.
    pub(super) fn rewrite_derived_tables<'from>(
        &self,
        from: impl IntoIterator<Item = &'from mut TableWithJoins>,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let mut changed = false;
        for table in from {
            for factor in std::iter::once(&mut table.relation)
                .chain(table.joins.iter_mut().map(|join| &mut join.relation))
            {
                match factor {
                    TableFactor::Derived { subquery, .. } => {
                        changed |= self.rewrite_query(subquery, params)?;
                    }
                    // A derived table inside a parenthesised join, e.g.
                    // `FROM (users JOIN (SELECT ... WHERE email = '…') s ON …)`.
                    // See [`Self::scope_of`] for why the nesting hides it.
                    TableFactor::NestedJoin { table_with_joins, .. } => {
                        changed |= self.rewrite_derived_tables(
                            std::iter::once(&mut **table_with_joins),
                            params,
                        )?;
                    }
                    _ => {}
                }
            }
        }
        Ok(changed)
    }

    /// Rewrites the `ON` conditions of a relation list against the enclosing
    /// scope, descending into parenthesised joins.
    ///
    /// A join constraint over a searchable column is as much a rewrite site as
    /// a `WHERE` is, and the constraints of a join written as
    /// `FROM (a JOIN b ON …)` live in the [`TableFactor::NestedJoin`]'s own
    /// [`TableWithJoins`] — never in the top-level `joins` list a flat pass
    /// looks at.
    pub(super) fn rewrite_join_conditions<'from>(
        &self,
        from: impl IntoIterator<Item = &'from mut TableWithJoins>,
        scope: &TableScope<'_>,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let mut changed = false;
        for table in from {
            changed |= self.rewrite_nested_join(&mut table.relation, scope, params)?;
            for join in &mut table.joins {
                changed |= self.rewrite_nested_join(&mut join.relation, scope, params)?;
                if let Some(constraint) = join_condition(&mut join.join_operator) {
                    changed |= self.rewrite_selection(constraint, scope, params)?;
                }
            }
        }
        Ok(changed)
    }

    /// The [`Self::rewrite_join_conditions`] step for one factor: recurse when
    /// it is a parenthesised join, and do nothing otherwise.
    fn rewrite_nested_join(
        &self,
        factor: &mut TableFactor,
        scope: &TableScope<'_>,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let TableFactor::NestedJoin { table_with_joins, .. } = factor else { return Ok(false) };
        self.rewrite_join_conditions(std::iter::once(&mut **table_with_joins), scope, params)
    }

    /// Collects the protected tables visible to a predicate, with their
    /// aliases, so column references can be resolved.
    ///
    /// Takes an iterator rather than a slice because the relations a predicate
    /// sees are not always contiguous: `UPDATE ... FROM` keeps its second
    /// relation in a field of its own, next to the target.
    pub(super) fn scope<'from>(
        &self,
        from: impl IntoIterator<Item = &'from TableWithJoins>,
    ) -> Result<TableScope<'_>, Rejection> {
        let mut tables = Vec::new();
        for table_with_joins in from {
            self.scope_of(table_with_joins, &mut tables)?;
        }
        Ok(TableScope { tables })
    }

    /// Adds one relation and its joins to a scope, descending into the
    /// parenthesised joins sqlparser keeps as [`TableFactor::NestedJoin`].
    ///
    /// `FROM (users JOIN orders ON orders.id = users.id)` parses as a single
    /// `NestedJoin` holding the whole join rather than as two `Table` factors,
    /// so a walk that stops at the top level finds no table at all: every
    /// protected table inside the parentheses drops out of the scope, and a
    /// predicate over one is neither rewritten into an index match nor raised
    /// as an [`Unprotected`] site — so `reject` relayed it verbatim and the
    /// comparison matched no row. The parentheses only group the join; the
    /// names inside them are in scope for the enclosing query exactly as they
    /// would be without them, which is why the nesting is flattened away here.
    fn scope_of<'a>(
        &'a self,
        table_with_joins: &TableWithJoins,
        tables: &mut Vec<ScopedTable<'a>>,
    ) -> Result<(), Rejection> {
        let factors = std::iter::once(&table_with_joins.relation)
            .chain(table_with_joins.joins.iter().map(|join| &join.relation));
        for factor in factors {
            match factor {
                TableFactor::Table { name, alias, .. } => {
                    let Some((columns, read_columns)) = self.scoped_table(name)? else { continue };
                    tables.push(ScopedTable {
                        alias: alias.as_ref().map(|alias| normalize(&alias.name)),
                        name: name.0.iter().map(normalize).collect(),
                        columns,
                        read_columns,
                    });
                }
                TableFactor::NestedJoin { table_with_joins, .. } => {
                    self.scope_of(table_with_joins, tables)?;
                }
                // A derived table brings its own scope, and a set-returning
                // function, `UNNEST` or `JSON_TABLE` names no base table the
                // catalog could resolve.
                _ => {}
            }
        }
        Ok(())
    }

    /// Every protected table a `COPY (query) TO STDOUT` would read, gathered
    /// from the query's own FROM clauses, its derived tables, its CTE bodies
    /// and both branches of a set operation. Names are reported once each,
    /// however many times the query mentions them.
    ///
    /// The *table* is what is reported, not the column. A COPY query's
    /// projection is arbitrary SQL — `SELECT *`, a function call, a reference
    /// to a CTE that selects the column three levels down — so "does this
    /// stream a protected column" is not answerable from the statement text,
    /// and answering "no" wrongly is the failure that leaks. Naming the table
    /// is also what the table-form `COPY t TO STDOUT` already does, so the two
    /// forms of one statement now behave alike.
    ///
    /// This walk recognises one table shape [`Self::scope`] does not — the
    /// `PIVOT`/`UNPIVOT`/`MATCH_RECOGNIZE` wrappers — because the consequence
    /// of missing one differs. There, a missed table leaves a predicate
    /// unrewritten, which the client sees as an empty result; here it hands
    /// the client a protected column's stored bytes. (The parenthesised join
    /// used to be the second such shape; [`Self::scope_of`] descends into it
    /// now, since the empty result it caused was no safer.)
    pub(super) fn copied_protected_tables(&self, query: &Query) -> Result<Vec<String>, Rejection> {
        let mut found = Vec::new();
        self.collect_copied_tables(query, &mut found)?;
        Ok(found)
    }

    fn collect_copied_tables(
        &self,
        query: &Query,
        found: &mut Vec<String>,
    ) -> Result<(), Rejection> {
        if let Some(with) = query.with.as_ref() {
            for cte in &with.cte_tables {
                self.collect_copied_tables(&cte.query, found)?;
            }
        }
        self.collect_copied_tables_in(&query.body, found)
    }

    fn collect_copied_tables_in(
        &self,
        body: &SetExpr,
        found: &mut Vec<String>,
    ) -> Result<(), Rejection> {
        match body {
            SetExpr::Select(select) => {
                for table in &select.from {
                    let factors = std::iter::once(&table.relation)
                        .chain(table.joins.iter().map(|join| &join.relation));
                    for factor in factors {
                        self.collect_copied_tables_from(factor, found)?;
                    }
                }
            }
            SetExpr::Query(query) => self.collect_copied_tables(query, found)?,
            SetExpr::SetOperation { left, right, .. } => {
                self.collect_copied_tables_in(left, found)?;
                self.collect_copied_tables_in(right, found)?;
            }
            // `TABLE t`, the shorthand for `SELECT * FROM t`, which the parser
            // keeps as a pair of bare strings rather than an `ObjectName`.
            //
            // sqlparser 0.53 cannot actually reach this arm from a COPY
            // source: `parse_as_table` reads three tokens unconditionally and
            // so overruns the closing paren, leaving `COPY (TABLE t) TO
            // STDOUT` unparseable — which is a site of its own, so the shape
            // is refused under `reject` today by a different name. The arm is
            // here so a later parser fix cannot quietly open a hole.
            SetExpr::Table(table) => {
                let Some(name) = table.table_name.as_ref() else { return Ok(()) };
                let parts = table.schema_name.iter().chain(std::iter::once(name));
                let name = ObjectName(parts.map(|part| Ident::new(part.as_str())).collect());
                self.record_copied_table(&name, found)?;
            }
            // A data-modifying CTE writes; it is the write path's own sites
            // that cover it, and its rows are not what COPY streams.
            SetExpr::Insert(_) | SetExpr::Update(_) | SetExpr::Values(_) => {}
        }
        Ok(())
    }

    fn collect_copied_tables_from(
        &self,
        factor: &TableFactor,
        found: &mut Vec<String>,
    ) -> Result<(), Rejection> {
        match factor {
            TableFactor::Table { name, .. } => self.record_copied_table(name, found),
            TableFactor::Derived { subquery, .. } => self.collect_copied_tables(subquery, found),
            TableFactor::NestedJoin { table_with_joins, .. } => {
                let factors = std::iter::once(&table_with_joins.relation)
                    .chain(table_with_joins.joins.iter().map(|join| &join.relation));
                for factor in factors {
                    self.collect_copied_tables_from(factor, found)?;
                }
                Ok(())
            }
            TableFactor::Pivot { table, .. }
            | TableFactor::Unpivot { table, .. }
            | TableFactor::MatchRecognize { table, .. } => {
                self.collect_copied_tables_from(table, found)
            }
            // Set-returning functions, `UNNEST`, `JSON_TABLE`: none of them
            // names a table the catalog could resolve.
            _ => Ok(()),
        }
    }

    fn record_copied_table(
        &self,
        name: &ObjectName,
        found: &mut Vec<String>,
    ) -> Result<(), Rejection> {
        // The read-direction lookup: a query source only exists in the `TO`
        // direction, and a mask-only table read this way streams the plaintext
        // its mask exists to hide. See [`WriteCatalog::protects_reads`].
        if !self.reads_protected(name)? {
            return Ok(());
        }
        let name = name.to_string();
        if !found.contains(&name) {
            found.push(name);
        }
        Ok(())
    }
}

/// The `ON` condition of a join, when it has one.
fn join_condition(operator: &mut JoinOperator) -> Option<&mut Expr> {
    let constraint = match operator {
        JoinOperator::Inner(constraint)
        | JoinOperator::LeftOuter(constraint)
        | JoinOperator::RightOuter(constraint)
        | JoinOperator::FullOuter(constraint)
        | JoinOperator::Semi(constraint)
        | JoinOperator::LeftSemi(constraint)
        | JoinOperator::RightSemi(constraint)
        | JoinOperator::Anti(constraint)
        | JoinOperator::LeftAnti(constraint)
        | JoinOperator::RightAnti(constraint)
        | JoinOperator::AsOf { constraint, .. } => constraint,
        JoinOperator::CrossJoin | JoinOperator::CrossApply | JoinOperator::OuterApply => {
            return None
        }
    };
    match constraint {
        JoinConstraint::On(expr) => Some(expr),
        JoinConstraint::Using(_) | JoinConstraint::Natural | JoinConstraint::None => None,
    }
}

/// The expression positions of a `SELECT` that can hold a nested query and are
/// not already swept elsewhere.
///
/// `WHERE` and `HAVING` are deliberately absent: they go through
/// `rewrite_predicate`, which sweeps them as part of rewriting them. Listing
/// them here as well would walk each of their subqueries twice.
fn select_expressions(select: &mut Select) -> impl Iterator<Item = &mut Expr> {
    let projection = select.projection.iter_mut().filter_map(|item| match item {
        SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => Some(expr),
        SelectItem::QualifiedWildcard(..) | SelectItem::Wildcard(_) => None,
    });
    let group_by = match &mut select.group_by {
        GroupByExpr::Expressions(exprs, _) => Some(exprs.iter_mut()),
        GroupByExpr::All(_) => None,
    };
    let join_constraints = select.from.iter_mut().flat_map(|table| {
        table.joins.iter_mut().filter_map(|join| join_condition(&mut join.join_operator))
    });
    projection.chain(group_by.into_iter().flatten()).chain(join_constraints)
}
