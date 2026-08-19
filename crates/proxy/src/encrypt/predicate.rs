//! Predicate traversal: finding the comparisons a protected column takes part
//! in, and rewriting the ones that have a searchable form.
//!
//! A predicate is where the read side of the protection lives. The stored form
//! of a protected column is not its plaintext, so a comparison left as the
//! client wrote it does not error — it matches no row, or, inverted, every
//! row. That is the failure this module exists to prevent: every shape it
//! cannot rewrite is reported as an [`Unprotected`] site rather than relayed
//! in silence.
//!
//! The traversal is separate from the statement layer above it because the
//! same walk runs from a `WHERE`, a `HAVING`, a join constraint and a
//! subquery, and the rewrite it applies is the same in all four.

use std::sync::Arc;

use dbsec_core::transform::FieldTransform;

use crate::portal::{ParamAction, ParamTransforms};
use crate::Error;

use sqlparser::ast::{Expr, FunctionArg, FunctionArgExpr, UnaryOperator, Value};

use super::array::array_parameter;
use super::frame::record_param;
use super::scope::{
    ambiguous_column, ambiguous_operand, column_name, column_ref, expr_shape, protected_column,
    protected_operand, TableScope,
};
use super::seal::{bytea_literal, literal_plaintext};
use super::unprotected::Unprotected;
use super::{placeholder_index, unwrap_casts, QueryRewriter, Rejection};

impl QueryRewriter {
    /// A predicate owned by a statement or select: rewritten against its own
    /// scope, then swept for nested queries.
    ///
    /// Both halves are needed at every site that owns a `WHERE`, and keeping
    /// them behind one call is what stops a site being given only one of them
    /// — which is exactly how `DELETE` and `UPDATE` came to walk their
    /// predicates without ever crossing into a subquery.
    pub(super) fn rewrite_predicate(
        &self,
        expr: &mut Expr,
        scope: &TableScope<'_>,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let mut changed = self.rewrite_selection(expr, scope, params)?;
        changed |= self.rewrite_nested_queries(expr, params)?;
        Ok(changed)
    }

    /// Rewrites every query nested inside an expression, and nothing else.
    ///
    /// The counterpart to [`Self::rewrite_selection`], which rewrites
    /// predicates inside one scope and never crosses a subquery boundary.
    /// Splitting the two jobs this way is what makes the traversal safe:
    /// each [`Query`](sqlparser::ast::Query) is reached from exactly one place, so no predicate can
    /// be rewritten twice. Recursion into a nested query stops here because
    /// [`Self::rewrite_query`] walks its insides itself.
    ///
    /// Before this existed, `rewrite_select` descended only into FROM-clause
    /// derived tables, CTE bodies and set-operation branches. A searchable
    /// equality inside a scalar subquery, an `EXISTS`, or a projection item
    /// was left comparing the client's plaintext against the stored
    /// `blind_index || envelope` — matching nothing, and never reaching
    /// [`Self::unprotected`], so `reject` did not flag it either.
    ///
    /// "Matches nothing" is not a safe failure mode. `DELETE FROM t WHERE id
    /// NOT IN (SELECT id FROM users WHERE email = '...')` turns an empty
    /// subquery result into `NOT IN (empty)`, which is true for every row, so
    /// the statement deletes the whole table.
    pub(super) fn rewrite_nested_queries(
        &self,
        expr: &mut Expr,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let mut changed = false;
        // The children to walk, gathered first: a closure capturing `changed`
        // would borrow it for the whole match.
        let mut children: Vec<&mut Expr> = Vec::new();
        match expr {
            // A query boundary: `rewrite_query` takes it from here, so the
            // walk deliberately does not descend past this point.
            Expr::Subquery(query) | Expr::Exists { subquery: query, .. } => {
                return self.rewrite_query(query, params);
            }
            Expr::InSubquery { expr: operand, subquery, .. } => {
                changed |= self.rewrite_query(subquery, params)?;
                children.push(operand.as_mut());
            }
            Expr::BinaryOp { left, right, .. }
            | Expr::AnyOp { left, right, .. }
            | Expr::AllOp { left, right, .. }
            | Expr::IsDistinctFrom(left, right)
            | Expr::IsNotDistinctFrom(left, right) => {
                children.push(left.as_mut());
                children.push(right.as_mut());
            }
            Expr::UnaryOp { expr: inner, .. }
            | Expr::Nested(inner)
            | Expr::Cast { expr: inner, .. }
            | Expr::IsNull(inner)
            | Expr::IsNotNull(inner)
            | Expr::IsTrue(inner)
            | Expr::IsNotTrue(inner)
            | Expr::IsFalse(inner)
            | Expr::IsNotFalse(inner)
            | Expr::Collate { expr: inner, .. } => children.push(inner.as_mut()),
            Expr::InList { expr: operand, list, .. } => {
                children.push(operand.as_mut());
                children.extend(list.iter_mut());
            }
            Expr::Between { expr: operand, low, high, .. } => {
                children.push(operand.as_mut());
                children.push(low.as_mut());
                children.push(high.as_mut());
            }
            Expr::Like { expr: operand, pattern, .. }
            | Expr::ILike { expr: operand, pattern, .. }
            | Expr::SimilarTo { expr: operand, pattern, .. } => {
                children.push(operand.as_mut());
                children.push(pattern.as_mut());
            }
            Expr::Tuple(items) => children.extend(items.iter_mut()),
            Expr::Case { operand, conditions, results, else_result } => {
                children.extend(operand.iter_mut().map(AsMut::as_mut));
                children.extend(else_result.iter_mut().map(AsMut::as_mut));
                children.extend(conditions.iter_mut());
                children.extend(results.iter_mut());
            }
            Expr::Function(function) => {
                if let sqlparser::ast::FunctionArguments::List(list) = &mut function.args {
                    for argument in &mut list.args {
                        let (FunctionArg::Named { arg, .. }
                        | FunctionArg::ExprNamed { arg, .. }
                        | FunctionArg::Unnamed(arg)) = argument;
                        if let FunctionArgExpr::Expr(inner) = arg {
                            children.push(inner);
                        }
                    }
                }
            }
            // Everything else is a leaf, or a shape that cannot hold a query.
            // A miss here leaves the pre-existing behaviour rather than
            // opening a new hole, and an *outer* predicate over a protected
            // column is still signalled by `rewrite_selection`.
            _ => {}
        }
        for child in children {
            changed |= self.rewrite_nested_queries(child, params)?;
        }
        Ok(changed)
    }

    /// Rewrites the equality shapes that a blind index can answer, and turns
    /// everything else that mentions a searchable column into an
    /// [`Unprotected`] site — an unrewritten predicate matches no row, and
    /// "no rows" is indistinguishable from "no such user".
    pub(super) fn rewrite_selection(
        &self,
        expr: &mut Expr,
        scope: &TableScope<'_>,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        use sqlparser::ast::BinaryOperator;
        match expr {
            Expr::BinaryOp { left, op: BinaryOperator::Eq, right } => {
                if let Some(transform) = column_ref(scope, left).cloned() {
                    self.rewrite_equality(left, right, &transform, params)
                } else if let Some(transform) = column_ref(scope, right).cloned() {
                    self.rewrite_equality(right, left, &transform, params)
                } else {
                    self.unsupported_predicate(expr, scope)
                }
            }
            Expr::BinaryOp { left, op: BinaryOperator::And | BinaryOperator::Or, right } => {
                let left = self.rewrite_selection(left, scope, params)?;
                let right = self.rewrite_selection(right, scope, params)?;
                Ok(left | right)
            }
            Expr::Nested(inner) => self.rewrite_selection(inner, scope, params),
            Expr::UnaryOp { op: UnaryOperator::Not, expr: inner } => {
                self.rewrite_selection(inner, scope, params)
            }
            Expr::InList { expr: column, list, .. } => {
                self.rewrite_in_list(column, list, scope, params)
            }
            Expr::AnyOp { left, compare_op: BinaryOperator::Eq, right, .. } => {
                if let Expr::Array(array) = right.as_mut() {
                    return self.rewrite_in_list(left, &mut array.elem, scope, params);
                }
                // `= ANY($1)` is one bound array parameter: the elements only
                // exist at Bind time, so the index is applied there.
                if let Some((index, transform)) = array_parameter(left, right, scope) {
                    let column: Arc<str> = column_name(left).unwrap_or_default().into();
                    record_param(
                        params,
                        index,
                        ParamAction::SearchIndexArray { transform, column },
                    )?;
                    let operand = std::mem::replace(left.as_mut(), Expr::Value(Value::Null));
                    *left.as_mut() = index_prefix(operand);
                    return Ok(true);
                }
                self.unsupported_predicate(expr, scope)
            }
            _ => self.unsupported_predicate(expr, scope),
        }
    }

    /// `col IN (a, b)` and `col = ANY(ARRAY[a, b])` become an index-prefix
    /// match against the indexed values. Either every element is indexable or
    /// none is rewritten: a mixed predicate compares some values against the
    /// index and others against the stored form.
    fn rewrite_in_list(
        &self,
        column: &mut Expr,
        list: &mut [Expr],
        scope: &TableScope<'_>,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        let Some(transform) = column_ref(scope, column).cloned() else {
            if let Some(column) = ambiguous_column(column, scope) {
                self.unprotected(&Unprotected::AmbiguousColumn { column, shape: "IN list" })?;
                return Ok(false);
            }
            // Row-wise `(a, b) IN ((..), (..))`: no single transform covers a
            // row constructor, so it cannot be rewritten — but it still has to
            // be reported rather than relayed to match nothing.
            if let Some((column, searchable)) = protected_column(column, scope) {
                self.unprotected(&if searchable {
                    Unprotected::Predicate { column, shape: "row-wise IN list" }
                } else {
                    Unprotected::UnindexedPredicate { column, shape: "row-wise IN list" }
                })?;
            }
            return Ok(false);
        };
        if !transform.supports_search() {
            // Same as `rewrite_equality`: no index to compare against, so
            // every element would be tested against the stored form.
            let column = column_name(column).unwrap_or_default();
            self.unprotected(&Unprotected::UnindexedPredicate { column, shape: "IN list" })?;
            return Ok(false);
        }
        if !list.iter().all(|value| self.literal_agrees_with_server(value)) {
            let column = column_name(column).unwrap_or_default();
            self.unprotected(&Unprotected::AmbiguousLiteral { column: &column })?;
            return Ok(false);
        }
        let indexable = !list.is_empty()
            && list.iter().all(|value| match unwrap_casts(value) {
                Expr::Value(Value::Placeholder(placeholder)) => {
                    placeholder_index(placeholder).is_some()
                }
                other => literal_plaintext(other, transform.wire()).is_some(),
            });
        if !indexable {
            let column = column_name(column).unwrap_or_default();
            self.unprotected(&Unprotected::Predicate { column, shape: "IN list" })?;
            return Ok(false);
        }
        for value in list.iter_mut() {
            index_value(value, &transform, params)?;
        }
        *column = index_prefix(std::mem::replace(column, Expr::Value(Value::Null)));
        Ok(true)
    }

    /// Turns `col = <value>` into `substring(col from 1 for 32) = <index>`.
    /// Literals get the index inline; placeholders are indexed at Bind time.
    fn rewrite_equality(
        &self,
        column: &mut Expr,
        value: &mut Expr,
        transform: &Arc<dyn FieldTransform>,
        params: &mut ParamTransforms,
    ) -> Result<bool, Rejection> {
        if !transform.supports_search() {
            // The column is protected but carries no equality index, so this
            // comparison would run against the stored form and match nothing.
            // Relaying it silently is the failure `Unprotected` exists to
            // prevent: "no rows" reads as "no such user".
            let column = column_name(column).unwrap_or_default();
            self.unprotected(&Unprotected::UnindexedPredicate {
                column,
                shape: expr_shape(value),
            })?;
            return Ok(false);
        }
        if !self.literal_agrees_with_server(value) {
            let column = column_name(column).unwrap_or_default();
            self.unprotected(&Unprotected::AmbiguousLiteral { column: &column })?;
            return Ok(false);
        }
        let indexable = match unwrap_casts(value) {
            Expr::Value(Value::Placeholder(placeholder)) => {
                placeholder_index(placeholder).is_some()
            }
            other => literal_plaintext(other, transform.wire()).is_some(),
        };
        if !indexable {
            let column = column_name(column).unwrap_or_default();
            self.unprotected(&Unprotected::Predicate { column, shape: expr_shape(value) })?;
            return Ok(false);
        }
        index_value(value, transform, params)?;
        *column = index_prefix(std::mem::replace(column, Expr::Value(Value::Null)));
        Ok(true)
    }

    /// A predicate the rewriter cannot turn into an index match. Only worth a
    /// signal when it actually mentions a protected column — otherwise it is
    /// ordinary SQL the proxy has no business commenting on.
    fn unsupported_predicate(
        &self,
        expr: &Expr,
        scope: &TableScope<'_>,
    ) -> Result<bool, Rejection> {
        let shape = expr_shape(expr);
        // Checked first: an ambiguous name resolves to no transform, so the
        // protected-operand test below cannot see it, and it is precisely the
        // case that must not be left as a plaintext comparison.
        if let Some(column) = ambiguous_operand(expr, scope) {
            self.unprotected(&Unprotected::AmbiguousColumn { column, shape })?;
            return Ok(false);
        }
        let Some((column, searchable)) = protected_operand(expr, scope) else { return Ok(false) };
        self.unprotected(&if searchable {
            Unprotected::Predicate { column, shape }
        } else {
            Unprotected::UnindexedPredicate { column, shape }
        })?;
        Ok(false)
    }
}

/// `substring(col from 1 for 32)` — the stored blind-index prefix.
fn index_prefix(column: Expr) -> Expr {
    let number = |n: &str| Box::new(Expr::Value(Value::Number(n.into(), false)));
    Expr::Substring {
        expr: Box::new(column),
        substring_from: Some(number("1")),
        substring_for: Some(number(&dbsec_core::blind_index::BLIND_INDEX_LEN.to_string())),
        special: false,
    }
}

/// Replaces one compared value with its blind index: inline for a literal,
/// recorded for Bind time for a placeholder. Callers check first that the
/// value is one of those two.
fn index_value(
    value: &mut Expr,
    transform: &Arc<dyn FieldTransform>,
    params: &mut ParamTransforms,
) -> Result<(), Rejection> {
    if let Expr::Value(Value::Placeholder(placeholder)) = unwrap_casts(value) {
        let Some(index) = placeholder_index(placeholder) else {
            return Err(Error::Wire(dbsec_core::Error::Malformed).into());
        };
        record_param(params, index, ParamAction::SearchIndex(transform.clone()))?;
        return Ok(());
    }
    let Some(plaintext) = literal_plaintext(value, transform.wire()) else {
        return Err(Error::Wire(dbsec_core::Error::Malformed).into());
    };
    let Some(token) = transform.search_index(&plaintext).map_err(Error::Wire)? else {
        return Err(Error::Wire(dbsec_core::Error::Malformed).into());
    };
    *value = bytea_literal(&token);
    Ok(())
}
