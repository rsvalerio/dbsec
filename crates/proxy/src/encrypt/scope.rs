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

use std::sync::Arc;

use dbsec_core::transform::FieldTransform;
use sqlparser::ast::{Expr, FunctionArg, FunctionArgExpr, Ident, SelectItem};

use super::catalog::{normalize, Columns};

pub(super) struct ScopedTable<'a> {
    pub(super) alias: Option<String>,
    /// The table's name parts, normalized — owned so the scope does not
    /// borrow the statement it was built from, which the rewrite mutates.
    pub(super) name: Vec<String>,
    pub(super) columns: &'a Columns,
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
/// [`QueryRewriter::unprotected`]. Collapsing it into "no protected column
/// here" left the comparison relayed with nothing but a log line, refused by
/// nothing, matching no row.
pub(super) enum ColumnResolution<'a> {
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
}

impl ScopedTable<'_> {
    fn matches(&self, qualifiers: &[Ident]) -> bool {
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
pub(super) fn resolve_column<'a>(scope: &'a TableScope<'_>, expr: &Expr) -> ColumnResolution<'a> {
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
/// [`QueryRewriter::rewrite_nested_queries`]; it stops at query boundaries
/// because it hands them to `rewrite_query`, whereas this one descends into
/// them, since a protected column referenced inside a subquery is still
/// projected out of it.
pub(super) fn expr_operands(expr: &Expr) -> Vec<&Expr> {
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

/// The first protected column an expression references, however deeply.
pub(super) fn protected_reference(expr: &Expr, scope: &TableScope<'_>) -> Option<String> {
    if column_ref(scope, expr).is_some() {
        return column_name(expr);
    }
    expr_operands(expr).into_iter().find_map(|child| protected_reference(child, scope))
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
/// match on. The statement, however, still says plainly which column is being
/// computed over, so the decision is made here while that is still knowable.
pub(super) fn computed_protected_column<'a>(
    item: &'a SelectItem,
    scope: &TableScope<'_>,
) -> Option<(String, &'a Expr)> {
    let expr = match item {
        SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => expr,
        SelectItem::QualifiedWildcard(..) | SelectItem::Wildcard(_) => return None,
    };
    // A bare column reference is the case the read path handles correctly.
    if column_ref(scope, expr).is_some() {
        return None;
    }
    Some((protected_reference(expr, scope)?, expr))
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
/// not protected here at all: [`WriteCatalog::new`] skips columns with no
/// transform, so they never enter the scope and their predicates are correct
/// as written.
///
/// `IS NULL` and `IS NOT NULL` are deliberately absent: nullness survives
/// sealing exactly. [`QueryRewriter::seal_expr`] returns early on a NULL
/// literal and Bind leaves a NULL parameter untouched, so a NULL in a
/// protected column is stored as SQL NULL and a non-NULL as a non-NULL
/// envelope. `col IS NULL` therefore returns exactly the rows the client
/// meant — no blind index is needed and none would help, so reporting it as
/// an [`Unprotected`] site would refuse working SQL under `reject` and dilute
/// the warning stream under `warn`. `IS DISTINCT FROM` is *not* exempt: it
/// compares against the stored form like any other operator.
pub(super) fn protected_operand(expr: &Expr, scope: &TableScope<'_>) -> Option<(String, bool)> {
    predicate_operands(expr)?.into_iter().find_map(|operand| protected_column(operand, scope))
}

/// The operands of an unhandled predicate — the positions a column reference
/// can occupy such that the comparison is *about* that column. `None` for an
/// expression that is not a comparison at all.
pub(super) fn predicate_operands(expr: &Expr) -> Option<[&Expr; 2]> {
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
