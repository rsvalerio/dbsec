//! Resolving a column reference in a statement to the transform that protects it.
//!
//! A predicate names columns; the catalog is keyed by `(schema, table,
//! column)`. Bridging the two is the whole job here, and the hard part is
//! that a statement may not say which table a bare name belongs to.
//!
//! Ambiguity is answered explicitly rather than by picking a winner:
//! [`ColumnResolution`] separates "exactly one protected table has this
//! column" from "more than one does" and from "none does". A bare name that
//! two protected tables both carry is reported as an unprotected site, because
//! guessing which one was meant would rewrite a predicate against the wrong
//! blind index and silently match nothing.
//!
//! A scope carries both directions of the catalog, because the two questions
//! asked of it have different right answers for a mask-only column: a
//! predicate over one needs no rewrite, while projecting a computation over
//! one leaks the value the mask exists to hide. Predicate resolution goes
//! through [`ColumnResolution`]; the projection check goes through
//! [`ScopedTable::read_columns`].

use std::borrow::Cow;
use std::sync::Arc;

use dbsec_core::transform::FieldTransform;
use sqlparser::ast::{Expr, FunctionArg, FunctionArgExpr, Ident, SelectItem};

use super::catalog::{normalize, Columns, ReadColumns};

pub(super) struct ScopedTable<'a> {
    pub(super) alias: Option<String>,
    /// The table's name parts, normalized — owned so the scope does not
    /// borrow the statement it was built from, which the rewrite mutates.
    pub(super) name: Vec<String>,
    /// The write direction: the columns a statement here has to seal. Empty
    /// for a table whose only protection is a read-path mask.
    ///
    /// Borrowed from the catalog for a base table, and owned for a derived one
    /// — `FROM (SELECT body FROM notes) s` exposes a *computed* set of columns
    /// under the names the subquery gave them, which no catalog entry holds.
    pub(super) columns: Cow<'a, Columns>,
    /// The read direction: every column name the read path protects here,
    /// mask-only ones included. See [`ReadColumns`].
    pub(super) read_columns: Cow<'a, ReadColumns>,
}

/// Protected tables a predicate can reference.
pub(super) struct TableScope<'a> {
    pub(super) tables: Vec<ScopedTable<'a>>,
}

/// What a scope made of a column reference.
///
/// Ambiguity is a case of its own rather than a second spelling of "not
/// found": an unqualified name matching a protected column in two relations
/// cannot be rewritten — guessing which table's blind index to compare against
/// is exactly the wrong-rows outcome the rewrite exists to prevent — but it
/// still *is* a predicate over a protected column, so it has to reach
/// [`QueryRewriter::unprotected`](super::QueryRewriter::unprotected).
/// Collapsing it into "no protected column here" left the comparison relayed
/// with nothing but a log line, refused by nothing, matching no row.
enum ColumnResolution<'a> {
    /// Exactly one protected column in scope carries this name.
    One(&'a Arc<dyn FieldTransform>),
    /// More than one does, and no rewrite can choose between them.
    Ambiguous,
    /// No protected column in scope carries this name.
    Unknown,
}

impl TableScope<'_> {
    /// Resolves a (possibly qualified) column reference to its transform.
    fn resolve(&self, idents: &[Ident]) -> ColumnResolution<'_> {
        let Some((column, qualifiers)) = idents.split_last() else {
            return ColumnResolution::Unknown;
        };
        let column = normalize(column);
        let mut matches = self
            .tables
            .iter()
            .filter(|table| table.matches(qualifiers))
            .filter_map(|table| table.columns.get(&column));
        let Some(transform) = matches.next() else { return ColumnResolution::Unknown };
        if matches.next().is_some() {
            ColumnResolution::Ambiguous
        } else {
            ColumnResolution::One(transform)
        }
    }

    /// The transform protecting a (possibly qualified) column reference, if
    /// exactly one in scope carries the name.
    ///
    /// [`ColumnResolution::Ambiguous`] answers `None` here on purpose: this is
    /// used to carry a column out of a derived table, and a name two protected
    /// relations inside it both claim cannot be attributed to either. The read
    /// direction still carries it — see [`Self::resolves_read`], where one
    /// candidate and two are the same answer.
    pub(super) fn transform_of(&self, idents: &[Ident]) -> Option<&Arc<dyn FieldTransform>> {
        match self.resolve(idents) {
            ColumnResolution::One(transform) => Some(transform),
            ColumnResolution::Ambiguous | ColumnResolution::Unknown => None,
        }
    }

    /// Whether a (possibly qualified) column reference names a column the
    /// *read* path protects.
    ///
    /// Deliberately not a [`ColumnResolution`]. Ambiguity matters to the write
    /// direction because it has to pick a blind index to compare against, and
    /// picking wrong matches the wrong rows. Here nothing is rewritten: the
    /// only question is whether the value leaving the server is one the read
    /// path was supposed to open or mask, and "some protected table in scope
    /// carries this name" already answers it. Two candidates are the same
    /// answer as one.
    pub(super) fn resolves_read(&self, idents: &[Ident]) -> bool {
        let Some((column, qualifiers)) = idents.split_last() else { return false };
        let column = normalize(column);
        self.tables
            .iter()
            .filter(|table| table.matches(qualifiers))
            .any(|table| table.read_columns.contains(&column))
    }
}

impl ScopedTable<'_> {
    pub(super) fn matches(&self, qualifiers: &[Ident]) -> bool {
        match qualifiers {
            [] => true,
            [qualifier] => {
                let qualifier = normalize(qualifier);
                self.alias.as_deref() == Some(qualifier.as_str())
                    || self.name.last().is_some_and(|last| *last == qualifier)
            }
            _ => {
                // schema.table (or longer): compare the trailing parts.
                let want: Vec<String> = qualifiers.iter().map(normalize).collect();
                self.name.len() >= want.len()
                    && self.name[self.name.len() - want.len()..] == want[..]
            }
        }
    }
}

/// How a scope resolves an expression that may be a column reference.
fn resolve_column<'a>(scope: &'a TableScope<'_>, expr: &Expr) -> ColumnResolution<'a> {
    match expr {
        Expr::Identifier(ident) => scope.resolve(std::slice::from_ref(ident)),
        Expr::CompoundIdentifier(idents) => scope.resolve(idents),
        _ => ColumnResolution::Unknown,
    }
}

/// The transform of a column reference that resolves to exactly one protected
/// column. An ambiguous one deliberately does not: see [`ColumnResolution`].
pub(super) fn column_ref<'a>(
    scope: &'a TableScope<'_>,
    expr: &Expr,
) -> Option<&'a Arc<dyn FieldTransform>> {
    match resolve_column(scope, expr) {
        ColumnResolution::One(transform) => Some(transform),
        ColumnResolution::Ambiguous | ColumnResolution::Unknown => None,
    }
}

/// The direct sub-expressions of `expr`, for read-only walks.
///
/// The mutable twin of this lives in
/// [`QueryRewriter::rewrite_nested_queries`](super::QueryRewriter::rewrite_nested_queries);
/// it stops at query boundaries because it hands them to `rewrite_query`,
/// whereas this one descends into them, since a protected column referenced
/// inside a subquery is still projected out of it.
fn expr_operands(expr: &Expr) -> Vec<&Expr> {
    match expr {
        Expr::BinaryOp { left, right, .. }
        | Expr::AnyOp { left, right, .. }
        | Expr::AllOp { left, right, .. }
        | Expr::IsDistinctFrom(left, right)
        | Expr::IsNotDistinctFrom(left, right) => vec![left, right],
        Expr::UnaryOp { expr: inner, .. }
        | Expr::Nested(inner)
        | Expr::Cast { expr: inner, .. }
        | Expr::IsNull(inner)
        | Expr::IsNotNull(inner)
        | Expr::IsTrue(inner)
        | Expr::IsNotTrue(inner)
        | Expr::IsFalse(inner)
        | Expr::IsNotFalse(inner)
        | Expr::Collate { expr: inner, .. } => vec![inner],
        Expr::InList { expr: operand, list, .. } => {
            std::iter::once(operand.as_ref()).chain(list.iter()).collect()
        }
        Expr::Between { expr: operand, low, high, .. } => vec![operand, low, high],
        Expr::Like { expr: operand, pattern, .. }
        | Expr::ILike { expr: operand, pattern, .. }
        | Expr::SimilarTo { expr: operand, pattern, .. } => vec![operand, pattern],
        Expr::Tuple(items) => items.iter().collect(),
        Expr::Case { operand, conditions, results, else_result } => operand
            .iter()
            .map(AsRef::as_ref)
            .chain(else_result.iter().map(AsRef::as_ref))
            .chain(conditions.iter())
            .chain(results.iter())
            .collect(),
        Expr::Function(function) => match &function.args {
            sqlparser::ast::FunctionArguments::List(list) => list
                .args
                .iter()
                .filter_map(|argument| {
                    let (FunctionArg::Named { arg, .. }
                    | FunctionArg::ExprNamed { arg, .. }
                    | FunctionArg::Unnamed(arg)) = argument;
                    match arg {
                        FunctionArgExpr::Expr(inner) => Some(inner),
                        _ => None,
                    }
                })
                .collect(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// Whether an expression *is* a reference to a read-protected column.
fn read_column_ref(scope: &TableScope<'_>, expr: &Expr) -> bool {
    match expr {
        Expr::Identifier(ident) => scope.resolves_read(std::slice::from_ref(ident)),
        Expr::CompoundIdentifier(idents) => scope.resolves_read(idents),
        _ => false,
    }
}

/// The first read-protected column an expression references, however deeply.
fn read_protected_reference(expr: &Expr, scope: &TableScope<'_>) -> Option<String> {
    if read_column_ref(scope, expr) {
        return column_name(expr);
    }
    expr_operands(expr).into_iter().find_map(|child| read_protected_reference(child, scope))
}

/// A projection item that computes over a protected column rather than
/// selecting it directly.
///
/// PostgreSQL fills `table_oid` and `attnum` in a `RowDescription` only for a
/// *direct* base-table column reference. Wrap the column in anything at all —
/// `email::text`, `ccnum || ''`, `coalesce(email, '')` — and the field arrives
/// as `(0, 0)`, which the read path matches against nothing and relays
/// untouched. For a mask-only column that hands back the very value the mask
/// exists to hide; for an encrypted one it hands back the raw stored form.
///
/// The read path cannot recover from this on its own: an expression output is
/// named `?column?` unless the client aliases it, so there is nothing left to
/// match on. `SELECT lower(email) FROM users` is worse than that — PostgreSQL
/// names the field `lower`, so `rows::check_for_stale_mapping`'s name-based
/// backstop matches nothing either. The statement, however, still says plainly
/// which column is being computed over, so the decision is made here while
/// that is still knowable.
///
/// Resolution runs against the *read* direction of the scope, not the write
/// one. The write direction has no entry for a mask-only column — a plaintext
/// write to one is correct — so resolving against it raised no site for
/// exactly the case this doc opens with, where the stored value *is* the
/// plaintext and the mask is the only thing that ever hid it.
pub(super) fn computed_protected_column<'a>(
    item: &'a SelectItem,
    scope: &TableScope<'_>,
) -> Option<(String, &'a Expr)> {
    let expr = match item {
        SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => expr,
        SelectItem::QualifiedWildcard(..) | SelectItem::Wildcard(_) => return None,
    };
    // A bare column reference is the case the read path handles correctly:
    // it arrives with a real `(table_oid, attnum)` to match on.
    if read_column_ref(scope, expr) {
        return None;
    }
    Some((read_protected_reference(expr, scope)?, expr))
}

/// The identifier path of a bare column reference, qualifiers included, or
/// `None` for anything computed.
pub(super) fn column_idents(expr: &Expr) -> Option<Vec<Ident>> {
    match expr {
        Expr::Identifier(ident) => Some(vec![ident.clone()]),
        Expr::CompoundIdentifier(idents) => Some(idents.clone()),
        _ => None,
    }
}

pub(super) fn column_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Identifier(ident) => Some(normalize(ident)),
        Expr::CompoundIdentifier(idents) => idents.last().map(normalize),
        _ => None,
    }
}

/// The protected column an unhandled predicate is about and whether it is
/// searchable, if any. Only the operands of the predicate are inspected — a
/// protected column buried in a subquery belongs to that subquery's own
/// traversal.
///
/// Every protected column qualifies, not only the searchable ones. What makes
/// an unrewritten predicate wrong is that the *stored form is not the
/// plaintext*, which is true of `encrypt` without `searchable`, of `fpe` and
/// of `token` just as much as of a searchable column — the searchable ones
/// are merely the subset the rewriter can also *fix*. Mask-only columns are
/// not protected here at all: they carry no transform, so they are absent from
/// [`ScopedTable::columns`] and every path through [`column_ref`] misses them
/// — deliberately, because their stored form *is* the plaintext and their
/// predicates are correct as written. They are in the scope's
/// [`ScopedTable::read_columns`], which only the projection check consults.
///
/// `IS NULL` and `IS NOT NULL` are deliberately absent: nullness survives
/// sealing exactly.
/// [`QueryRewriter::seal_expr`](super::QueryRewriter::seal_expr) returns early
/// on a NULL literal and Bind leaves a NULL parameter untouched, so a NULL in
/// a protected column is stored as SQL NULL and a non-NULL as a non-NULL
/// envelope. `col IS NULL` therefore returns exactly the rows the client meant
/// — no blind index is needed and none would help, so reporting it as an
/// [`Unprotected`](super::unprotected::Unprotected) site would refuse working
/// SQL under `reject` and dilute the warning stream under `warn`. `IS DISTINCT
/// FROM` is *not* exempt: it compares against the stored form like any other
/// operator.
pub(super) fn protected_operand(expr: &Expr, scope: &TableScope<'_>) -> Option<(String, bool)> {
    predicate_operands(expr)?.into_iter().find_map(|operand| protected_column(operand, scope))
}

/// The operands of an unhandled predicate — the positions a column reference
/// can occupy such that the comparison is *about* that column. `None` for an
/// expression that is not a comparison at all.
fn predicate_operands(expr: &Expr) -> Option<[&Expr; 2]> {
    match expr {
        Expr::BinaryOp { left, right, .. }
        | Expr::AnyOp { left, right, .. }
        | Expr::AllOp { left, right, .. } => Some([left, right]),
        Expr::InList { expr, .. }
        | Expr::InSubquery { expr, .. }
        | Expr::Between { expr, .. }
        | Expr::Like { expr, .. }
        | Expr::ILike { expr, .. }
        | Expr::SimilarTo { expr, .. }
        | Expr::IsDistinctFrom(expr, _)
        | Expr::IsNotDistinctFrom(expr, _) => Some([expr, expr]),
        _ => None,
    }
}

/// The name of a predicate operand that matches a protected column in more
/// than one relation in scope.
pub(super) fn ambiguous_operand(expr: &Expr, scope: &TableScope<'_>) -> Option<String> {
    predicate_operands(expr)?.into_iter().find_map(|operand| ambiguous_column(operand, scope))
}

/// The same for one operand, seeing through a row constructor exactly as
/// [`protected_column`] does.
pub(super) fn ambiguous_column(operand: &Expr, scope: &TableScope<'_>) -> Option<String> {
    if let Expr::Tuple(items) = operand {
        return items.iter().find_map(|item| ambiguous_column(item, scope));
    }
    match resolve_column(scope, operand) {
        ColumnResolution::Ambiguous => column_name(operand),
        ColumnResolution::One(_) | ColumnResolution::Unknown => None,
    }
}

/// The first protected column an operand names, seeing through a row
/// constructor.
///
/// Row-wise `(a, b) IN (...)` puts an [`Expr::Tuple`] where a column
/// reference would normally be. Without this the tuple resolves to no
/// transform at all, so the predicate was neither rewritten nor reported —
/// the same silent no-match this module exists to prevent, just reached by a
/// different syntax.
pub(super) fn protected_column(operand: &Expr, scope: &TableScope<'_>) -> Option<(String, bool)> {
    if let Expr::Tuple(items) = operand {
        return items.iter().find_map(|item| protected_column(item, scope));
    }
    let transform = column_ref(scope, operand)?;
    Some((column_name(operand)?, transform.supports_search()))
}

/// The AST discriminant of an expression — its *shape*, never its value.
/// Logging the expression itself would put the plaintext bound to a protected
/// column straight into the log.
pub(super) fn expr_shape(expr: &Expr) -> &'static str {
    match expr {
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => "column reference",
        Expr::Value(_) => "literal",
        Expr::Function(_) => "function call",
        Expr::Cast { .. } => "cast",
        Expr::BinaryOp { .. } => "binary operator",
        Expr::UnaryOp { .. } => "unary operator",
        Expr::Case { .. } => "CASE",
        Expr::Subquery(_) => "subquery",
        Expr::InSubquery { .. } => "IN subquery",
        Expr::InList { .. } => "IN list",
        Expr::AnyOp { .. } => "= ANY",
        Expr::AllOp { .. } => "= ALL",
        Expr::Like { .. } | Expr::ILike { .. } | Expr::SimilarTo { .. } => "pattern match",
        Expr::Between { .. } => "BETWEEN",
        Expr::IsNull(_) | Expr::IsNotNull(_) => "IS NULL",
        Expr::IsDistinctFrom(_, _) | Expr::IsNotDistinctFrom(_, _) => "IS DISTINCT FROM",
        Expr::Array(_) => "array",
        Expr::TypedString { .. } => "typed literal",
        Expr::Nested(_) => "parenthesized expression",
        _ => "unsupported expression",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dbsec_core::blind_index;
    use dbsec_core::transform::FieldTransform;
    use sqlparser::ast::{SelectItem, SetExpr, Statement};
    use sqlparser::dialect::PostgreSqlDialect;
    use sqlparser::parser::Parser;

    use crate::columns::ProtectedColumn;

    use crate::config::OnUnprotected;
    use crate::encrypt::tests::*;
    use crate::encrypt::unprotected::Unprotected;
    use crate::encrypt::WriteCatalog;
    use crate::rows::tests::transform;
    use crate::session::FrameAction;

    use super::expr_shape;

    /// A parenthesised join is one `TableFactor::NestedJoin` holding the whole
    /// join, not the two `Table` factors the same query has without the
    /// parentheses. The scope walk stopped at the top level, so every
    /// protected table inside them was invisible: the equality was relayed
    /// comparing the client's plaintext against the stored
    /// `blind_index || envelope`, which matches no row and reads as "no such
    /// user" — reached by adding one pair of parentheses.
    #[test]
    fn a_parenthesized_join_puts_its_protected_tables_in_scope() {
        use crate::rows::tests::INDEX_KEY;

        let mut rewriter = rewriter(catalog(true));
        let expected = blind_index::compute(&INDEX_KEY, b"alice@example.com");

        for sql in [
            // The enclosing predicate.
            "SELECT 1 FROM (users JOIN orders ON orders.id = users.id) \
             WHERE users.email = 'alice@example.com'",
            // A join constraint *inside* the parentheses.
            "SELECT 1 FROM (orders JOIN users ON users.email = 'alice@example.com')",
            // A derived table nested inside them, with its own predicate.
            "SELECT 1 FROM (orders JOIN (SELECT id FROM users WHERE \
             email = 'alice@example.com') s ON s.id = orders.id)",
            // Nested twice over, and reached through an UPDATE's FROM rather
            // than a SELECT's.
            "UPDATE orders SET total = 1 FROM ((users JOIN accounts ON accounts.id = users.id)) \
             WHERE users.email = 'alice@example.com'",
        ] {
            let rewritten = rewritten_query(&mut rewriter, sql).unwrap_or_else(|| {
                panic!("relayed verbatim instead of rewritten: {sql}");
            });
            assert!(!rewritten.contains("alice@example.com"), "{sql}: {rewritten}");
            assert!(rewritten.contains(&sealed_literal(&expected)), "{sql}: {rewritten}");
        }
    }

    /// The other half of the same gap: a shape no blind index can answer, over
    /// a table only the parenthesised join brings into scope, has to reach
    /// [`QueryRewriter::unprotected`] — otherwise `reject` does not fail closed
    /// for this syntax and the comparison is relayed to match nothing.
    #[test]
    fn an_unrewritable_predicate_inside_a_parenthesized_join_is_refused() {
        let mut strict = rewriter(strict_catalog(true));
        for sql in [
            "SELECT 1 FROM (users JOIN orders ON orders.id = users.id) \
             WHERE users.email LIKE 'a%'",
            "SELECT 1 FROM (orders JOIN users ON users.email > 'a')",
            "SELECT 1 FROM (orders JOIN (SELECT id FROM users WHERE email LIKE 'a%') s \
             ON s.id = orders.id)",
        ] {
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            assert!(
                refusal(&action).contains("searchable column email"),
                "{sql}: {}",
                refusal(&action)
            );
        }
    }

    #[test]
    fn join_cte_and_set_operations_are_traversed() {
        let mut rewriter = rewriter(catalog(true));
        for sql in [
            "SELECT u.id FROM users u JOIN orders o ON o.id = u.id AND u.email = 'a@b.io'",
            "WITH hits AS (SELECT id FROM users WHERE email = 'a@b.io') SELECT * FROM hits",
            "SELECT id FROM users WHERE email = 'a@b.io' UNION SELECT id FROM orders",
            "SELECT id FROM (SELECT id, email FROM users WHERE email = 'a@b.io') AS s",
            "SELECT count(*) FROM users GROUP BY email HAVING email = 'a@b.io'",
        ] {
            let rewritten = rewritten_query(&mut rewriter, sql).unwrap_or_else(|| panic!("{sql}"));
            assert!(!rewritten.contains("a@b.io"), "{rewritten}");
            assert!(rewritten.contains("FROM 1 FOR 32"), "{rewritten}");
        }
    }

    /// `UPDATE ... FROM` and `DELETE ... USING` join a second relation into
    /// the predicate's scope, and sqlparser keeps it in a field of its own. It
    /// used to be dropped, so a searchable column of the joined relation
    /// resolved to nothing: the comparison went upstream verbatim, matched no
    /// row, and never reached the gate. `DELETE FROM sessions USING users
    /// WHERE users.email = $1` silently revoked nothing — and its `<>`
    /// inversion deleted every session there was.
    #[test]
    fn the_joined_relation_of_update_from_and_delete_using_is_in_scope() {
        for sql in [
            "DELETE FROM sessions USING users \
             WHERE users.email = 'a@b.io' AND sessions.user_id = users.id",
            "UPDATE sessions SET valid = false FROM users \
             WHERE users.email = 'a@b.io' AND sessions.user_id = users.id",
        ] {
            let mut permissive = rewriter(catalog(true));
            let rewritten =
                rewritten_query(&mut permissive, sql).unwrap_or_else(|| panic!("{sql}"));
            assert!(!rewritten.contains("a@b.io"), "{rewritten}");
            assert!(rewritten.contains("FROM 1 FOR 32"), "{rewritten}");
        }

        // A derived table beside the target is a query of its own, and it was
        // walked for `SELECT` but not for these two: the equality inside it
        // went upstream as plaintext, matching nothing and signalling nothing.
        for sql in [
            "DELETE FROM sessions USING (SELECT id FROM users WHERE email = 'a@b.io') s \
             WHERE s.id = sessions.user_id",
            "UPDATE sessions SET valid = false \
             FROM (SELECT id FROM users WHERE email = 'a@b.io') s WHERE s.id = sessions.user_id",
        ] {
            let mut permissive = rewriter(catalog(true));
            let rewritten =
                rewritten_query(&mut permissive, sql).unwrap_or_else(|| panic!("{sql}"));
            assert!(!rewritten.contains("a@b.io"), "{rewritten}");
            assert!(rewritten.contains("FROM 1 FOR 32"), "{rewritten}");
        }

        // A join constraint inside that FROM/USING resolves against the same
        // scope the WHERE does, so it is the same rewrite site — and only
        // `rewrite_select` used to walk one, so these two left it comparing
        // plaintext against the stored form.
        for sql in [
            "DELETE FROM sessions USING accounts JOIN users ON users.email = 'a@b.io'",
            "UPDATE sessions SET valid = false FROM accounts JOIN users \
             ON users.email = 'a@b.io'",
        ] {
            let mut permissive = rewriter(catalog(true));
            let rewritten =
                rewritten_query(&mut permissive, sql).unwrap_or_else(|| panic!("{sql}"));
            assert!(!rewritten.contains("a@b.io"), "{rewritten}");
            assert!(rewritten.contains("FROM 1 FOR 32"), "{rewritten}");
        }

        // The inversion is the dangerous half and no index can answer it, so
        // it has to reach the gate rather than delete the table.
        for sql in [
            "DELETE FROM sessions USING users WHERE users.email <> 'a@b.io'",
            "UPDATE sessions SET valid = false FROM users WHERE users.email LIKE 'a%'",
            "DELETE FROM sessions USING accounts JOIN users ON users.email LIKE 'a%'",
        ] {
            let mut strict = rewriter(strict_catalog(true));
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            assert!(refusal(&action).contains("searchable column email"), "{sql}");
        }
    }

    /// An unqualified name that two protected relations in scope both carry
    /// cannot be rewritten — picking one would compare against the wrong
    /// table's blind index. It used to resolve to nothing at all, which put it
    /// on the same path as SQL that mentions no protected column: relayed
    /// verbatim, matching no row, and never refused under `reject`. It is a
    /// site of its own now.
    #[test]
    fn an_ambiguous_unqualified_searchable_column_is_a_signalled_site() {
        for sql in [
            "SELECT * FROM users u JOIN accounts a ON u.id = a.uid WHERE email = 'a@b.io'",
            "SELECT * FROM users u JOIN accounts a ON u.id = a.uid WHERE email IN ('a@b.io')",
            "SELECT * FROM users u JOIN accounts a ON u.id = a.uid WHERE email LIKE 'a%'",
        ] {
            let mut permissive = rewriter(ambiguous_catalog(OnUnprotected::Warn));
            assert!(rewritten_query(&mut permissive, sql).is_none(), "ambiguity must not guess");

            let mut strict = rewriter(ambiguous_catalog(OnUnprotected::Reject));
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            let message = refusal(&action);
            assert!(message.contains("email") && message.contains("qualify it"), "{message}");
        }

        // Qualifying the name resolves it, and the rewrite goes ahead.
        let mut permissive = rewriter(ambiguous_catalog(OnUnprotected::Warn));
        let sql = rewritten_query(
            &mut permissive,
            "SELECT * FROM users u JOIN accounts a ON u.id = a.uid WHERE u.email = 'a@b.io'",
        )
        .expect("rewritten");
        assert!(!sql.contains("a@b.io") && sql.contains("FROM 1 FOR 32"), "{sql}");
    }

    /// A shape the rewriter cannot express is a refusal site, not a silent
    /// "no rows".
    #[test]
    fn unsupported_predicates_over_searchable_columns_are_signalled() {
        for sql in [
            "SELECT id FROM users WHERE email LIKE 'a%'",
            "SELECT id FROM users WHERE email > 'a@b.io'",
            "SELECT id FROM users WHERE email IN (SELECT email FROM other)",
            "SELECT id FROM users WHERE email = ANY(SELECT email FROM other)",
            "SELECT id FROM users WHERE email IN ('a@b.io', lower('c@d.io'))",
            "DELETE FROM users WHERE email = lower('a@b.io')",
        ] {
            let mut permissive = rewriter(catalog(true));
            assert!(rewritten_query(&mut permissive, sql).is_none(), "{sql}");

            let mut strict = rewriter(strict_catalog(true));
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            assert!(refusal(&action).contains("searchable column email"), "{sql}");
        }
    }

    /// A predicate over a protected column with no equality index compares the
    /// client's plaintext against a stored form that is not the plaintext, so
    /// it matches nothing. That is the failure `Unprotected` exists to report,
    /// and it must fire for every non-searchable transform kind — an operator
    /// who sets `reject` to be told about queries that cannot work gets
    /// nothing otherwise, and "no rows" reads as "no such user".
    #[test]
    fn predicates_over_protected_columns_without_an_index_are_signalled() {
        let kinds: [(&str, Arc<dyn FieldTransform>); 3] = [
            ("encrypt (searchable = false)", transform(false)),
            ("fpe", fpe_transform()),
            ("token", token_transform()),
        ];
        for (kind, column_transform) in kinds {
            for sql in [
                "SELECT id FROM users WHERE email = 'a@b.io'",
                "SELECT id FROM users WHERE 'a@b.io' = email",
                "SELECT id FROM users WHERE email IN ('a@b.io', 'c@d.io')",
                "SELECT id FROM users WHERE email LIKE 'a%'",
                "DELETE FROM users WHERE email = 'a@b.io'",
            ] {
                let mut permissive =
                    rewriter(catalog_of(column_transform.clone(), false, OnUnprotected::Warn));
                assert!(
                    rewritten_query(&mut permissive, sql).is_none(),
                    "{kind} under warn relays: {sql}"
                );

                let mut strict =
                    rewriter(catalog_of(column_transform.clone(), false, OnUnprotected::Reject));
                let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
                let message = refusal(&action);
                assert!(
                    message.contains("protected column email") && message.contains("no equality"),
                    "{kind} under reject refuses: {sql}\ngot: {message}"
                );
            }
        }
    }

    /// The remedy differs by column, so the two predicate signals stay
    /// distinct: a searchable column names its blind index, an unindexed one
    /// names the setting that would fix it.
    #[test]
    fn the_two_predicate_signals_name_different_remedies() {
        let sql = "SELECT id FROM users WHERE email LIKE 'a%'";

        let mut searchable = rewriter(strict_catalog(true));
        let message = refusal(&searchable.on_frame(b'Q', &query_frame(sql)).unwrap());
        assert!(message.contains("searchable column email"), "{message}");
        assert!(message.contains("blind index"), "{message}");

        let mut unindexed = rewriter(strict_catalog(false));
        let message = refusal(&unindexed.on_frame(b'Q', &query_frame(sql)).unwrap());
        assert!(message.contains("protected column email"), "{message}");
        assert!(message.contains("searchable = true"), "{message}");
    }

    /// A mask-only column stores the plaintext, so its predicates are correct
    /// exactly as written and must stay silent. `WriteCatalog::new` skips
    /// columns with no transform, which is what makes this hold.
    #[test]
    fn predicates_over_mask_only_columns_stay_quiet() {
        let mask_only = ProtectedColumn {
            schema: "public".into(),
            table: "users".into(),
            column: "email".into(),
            transform: None,
            searchable: false,
            readable: false,
            mask: Some(dbsec_core::mask::MaskSpec { keep_first: 1, keep_last: 0, mask_with: '*' }),
        };
        let catalog = Arc::new(WriteCatalog::new(&[mask_only], OnUnprotected::Reject));
        let mut strict = rewriter(catalog);
        for sql in [
            "SELECT id FROM users WHERE email = 'a@b.io'",
            "SELECT id FROM users WHERE email LIKE 'a%'",
            "SELECT id FROM users WHERE email IN ('a@b.io')",
        ] {
            assert!(
                matches!(strict.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
                "a mask-only column stores the plaintext: {sql}"
            );
        }
    }

    /// Nullness survives sealing, so the two null tests are answered correctly
    /// by the stored form and must not be reported as unprotected. Both modes
    /// are checked through the same `unprotected` call site: silence under
    /// `reject` is what proves there is no warning under `warn`.
    #[test]
    fn null_tests_over_searchable_columns_are_not_unprotected_sites() {
        for sql in [
            "SELECT id FROM users WHERE email IS NULL",
            "SELECT id FROM users WHERE email IS NOT NULL",
            "SELECT id FROM users WHERE id > 4 AND email IS NOT NULL",
            "SELECT u.id FROM users u JOIN other o ON o.id = u.id AND u.email IS NULL",
        ] {
            let mut permissive = rewriter(catalog(true));
            assert!(rewritten_query(&mut permissive, sql).is_none(), "{sql}");

            let mut strict = rewriter(strict_catalog(true));
            assert!(
                matches!(strict.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
                "a null test matches correctly against the stored form: {sql}"
            );
        }
    }

    /// `IS DISTINCT FROM` is not in the same position as `IS NULL`: it
    /// compares against the stored form like any other operator, so it stays a
    /// signalled site.
    #[test]
    fn is_distinct_from_over_a_searchable_column_is_still_signalled() {
        for sql in [
            "SELECT id FROM users WHERE email IS DISTINCT FROM 'a@b.io'",
            "SELECT id FROM users WHERE email IS NOT DISTINCT FROM 'a@b.io'",
        ] {
            let mut strict = rewriter(strict_catalog(true));
            let action = strict.on_frame(b'Q', &query_frame(sql)).unwrap();
            assert!(refusal(&action).contains("searchable column email"), "{sql}");
        }
    }

    /// Predicates over columns the proxy does not protect stay silent.
    #[test]
    fn unsupported_predicates_over_other_columns_stay_quiet() {
        let mut strict = rewriter(strict_catalog(true));
        for sql in [
            "SELECT id FROM users WHERE id > 4",
            "SELECT id FROM users WHERE name LIKE 'a%'",
            "SELECT id FROM other WHERE email LIKE 'a%'",
        ] {
            assert!(
                matches!(strict.on_frame(b'Q', &query_frame(sql)).unwrap(), FrameAction::Relay),
                "{sql}"
            );
        }
    }

    /// The plaintext bound to a protected column must not reach the log, so
    /// the warning carries the column and the expression's shape instead.
    #[test]
    fn unsupported_value_warning_names_the_shape_not_the_value() {
        let site = Unprotected::UnsupportedValue { column: "email", shape: "function call" };
        let message = site.message();
        assert!(message.contains("email") && message.contains("function call"), "{message}");

        let parsed = Parser::parse_sql(&PostgreSqlDialect {}, "SELECT lower('a@b.io')").unwrap();
        let Statement::Query(query) = &parsed[0] else { panic!("a query") };
        let SetExpr::Select(select) = query.body.as_ref() else { panic!("a select") };
        let SelectItem::UnnamedExpr(expr) = &select.projection[0] else { panic!("an expression") };
        assert_eq!(expr_shape(expr), "function call");
        assert!(!expr_shape(expr).contains("a@b.io"));
    }
}
