//! The encrypt path (milestone 5): client→upstream interception.
//!
//! Simple protocol: `Query` SQL is parsed with sqlparser and literals bound
//! to protected columns in INSERT/UPDATE are sealed in place (as `\x` hex
//! bytea literals). Extended protocol: `Parse` remembers which parameter
//! placeholders feed protected columns (and seals any inline literals);
//! `Bind` seals those parameters. Unparseable SQL passes through — logged
//! loudly. Seal errors fail the session.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use dbsec_core::pgwire;
use dbsec_core::transform::{EncryptTransform, FieldTransform};
use sqlparser::ast::{
    Assignment, AssignmentTarget, Expr, Ident, ObjectName, SetExpr, Statement, Value,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

use crate::columns::ProtectedColumn;
use crate::Error;

/// Protected columns keyed by name for SQL matching:
/// `(schema, table) → column → transform`.
pub struct WriteCatalog {
    tables: HashMap<(String, String), HashMap<String, Arc<EncryptTransform>>>,
}

impl WriteCatalog {
    pub fn new(columns: &[ProtectedColumn]) -> Self {
        let mut tables: HashMap<_, HashMap<_, _>> = HashMap::new();
        for column in columns {
            tables
                .entry((column.schema.clone(), column.table.clone()))
                .or_default()
                .insert(column.column.clone(), column.transform.clone());
        }
        Self { tables }
    }

    /// Looks a table up the way Postgres would resolve the SQL name: the last
    /// identifier is the table, the one before it the schema, and bare names
    /// fall back to `public` (search_path is not consulted — a caveat).
    fn table(&self, name: &ObjectName) -> Option<&HashMap<String, Arc<EncryptTransform>>> {
        let mut parts = name.0.iter().rev();
        let table = normalize(parts.next()?);
        let schema = parts.next().map_or_else(|| "public".to_owned(), normalize);
        self.tables.get(&(schema, table))
    }
}

/// PG folds unquoted identifiers to lowercase; quoted ones stay verbatim.
fn normalize(ident: &Ident) -> String {
    if ident.quote_style.is_some() {
        ident.value.clone()
    } else {
        ident.value.to_lowercase()
    }
}

/// Which parameter placeholders of a prepared statement feed protected
/// columns.
type ParamTransforms = Vec<(usize, Arc<EncryptTransform>)>;

/// Per-session write-path state: rewrites Query/Parse SQL and Bind
/// parameters using the shared catalog, remembering prepared statements.
pub struct QueryRewriter {
    catalog: Arc<WriteCatalog>,
    statements: HashMap<Vec<u8>, ParamTransforms>,
}

impl QueryRewriter {
    pub fn new(catalog: Arc<WriteCatalog>) -> Self {
        Self { catalog, statements: HashMap::new() }
    }

    /// Inspects one client→upstream frame. Returns a replacement body when
    /// the message must be rewritten, `None` to relay it untouched.
    pub fn on_frame(&mut self, msg_type: u8, body: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match msg_type {
            b'Q' => {
                let mut sql = body;
                let query = pgwire::take_cstr(&mut sql).map_err(Error::Wire)?;
                let Some(rewritten) = self.rewrite_sql(query)?.rewritten else {
                    return Ok(None);
                };
                let mut new_body = rewritten.into_bytes();
                new_body.push(0);
                Ok(Some(new_body))
            }
            b'P' => {
                let parse = pgwire::parse_parse(body)?;
                let outcome = self.rewrite_sql(parse.query)?;
                self.statements.insert(parse.statement.to_vec(), outcome.params);
                Ok(outcome.rewritten.map(|sql| {
                    pgwire::encode_parse(parse.statement, sql.as_bytes(), parse.param_types)
                }))
            }
            b'B' => {
                let bind = pgwire::parse_bind(body)?;
                let Some(params) = self.statements.get(bind.statement) else {
                    return Ok(None);
                };
                if params.is_empty() {
                    return Ok(None);
                }
                let mut values: Vec<Option<Cow<'_, [u8]>>> =
                    bind.params.iter().map(|p| p.map(Cow::Borrowed)).collect();
                for (index, transform) in params {
                    let Some(Some(value)) = values.get_mut(*index) else { continue };
                    let sealed = transform.seal(value)?;
                    *value = if bind.param_format(*index) == 1 {
                        Cow::Owned(sealed)
                    } else {
                        // Text-format parameter for a BYTEA column: hex form.
                        Cow::Owned(format!("\\x{}", hex::encode(sealed)).into_bytes())
                    };
                }
                Ok(Some(pgwire::encode_bind(
                    bind.portal,
                    bind.statement,
                    &bind.param_formats,
                    &values,
                    bind.result_formats,
                )))
            }
            b'C' => {
                // Close: 'S' = statement, 'P' = portal.
                if let [b'S', name @ ..] = body {
                    let mut name = name;
                    if let Ok(statement) = pgwire::take_cstr(&mut name) {
                        self.statements.remove(statement);
                    }
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn rewrite_sql(&mut self, query: &[u8]) -> Result<RewriteOutcome, Error> {
        let Ok(query) = std::str::from_utf8(query) else {
            tracing::warn!("query is not valid UTF-8; passing through unencrypted");
            return Ok(RewriteOutcome::passthrough());
        };
        let mut statements = match Parser::parse_sql(&PostgreSqlDialect {}, query) {
            Ok(statements) => statements,
            Err(e) => {
                tracing::warn!(error = %e, "unparseable SQL; passing through unencrypted");
                return Ok(RewriteOutcome::passthrough());
            }
        };

        let mut outcome = RewriteOutcome::passthrough();
        let mut changed = false;
        for statement in &mut statements {
            changed |= self.rewrite_statement(statement, &mut outcome.params)?;
        }
        if changed {
            outcome.rewritten =
                Some(statements.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "));
        }
        Ok(outcome)
    }

    fn rewrite_statement(
        &self,
        statement: &mut Statement,
        params: &mut ParamTransforms,
    ) -> Result<bool, Error> {
        match statement {
            Statement::Insert(insert) => {
                let Some(columns) = self.catalog.table(&insert.table_name) else {
                    return Ok(false);
                };
                if insert.columns.is_empty() {
                    tracing::warn!(
                        table = %insert.table_name,
                        "INSERT without a column list on a protected table; passing through unencrypted"
                    );
                    return Ok(false);
                }
                let protected: Vec<(usize, Arc<EncryptTransform>)> = insert
                    .columns
                    .iter()
                    .enumerate()
                    .filter_map(|(i, ident)| columns.get(&normalize(ident)).map(|t| (i, t.clone())))
                    .collect();
                if protected.is_empty() {
                    return Ok(false);
                }
                let Some(source) = insert.source.as_mut() else { return Ok(false) };
                let SetExpr::Values(values) = source.body.as_mut() else {
                    tracing::warn!(
                        table = %insert.table_name,
                        "INSERT ... SELECT into a protected table; passing through unencrypted"
                    );
                    return Ok(false);
                };
                let mut changed = false;
                for row in &mut values.rows {
                    for (position, transform) in &protected {
                        if let Some(expr) = row.get_mut(*position) {
                            changed |= seal_expr(expr, transform, params)?;
                        }
                    }
                }
                Ok(changed)
            }
            Statement::Update { table, assignments, .. } => {
                let sqlparser::ast::TableFactor::Table { name, .. } = &table.relation else {
                    return Ok(false);
                };
                let Some(columns) = self.catalog.table(name) else { return Ok(false) };
                let mut changed = false;
                for Assignment { target, value } in assignments {
                    let AssignmentTarget::ColumnName(column) = target else { continue };
                    let Some(ident) = column.0.last() else { continue };
                    let Some(transform) = columns.get(&normalize(ident)) else { continue };
                    changed |= seal_expr(value, transform, params)?;
                }
                Ok(changed)
            }
            Statement::Copy { source, .. } => {
                if let sqlparser::ast::CopySource::Table { table_name, .. } = source {
                    if self.catalog.table(table_name).is_some() {
                        tracing::warn!(
                            table = %table_name,
                            "COPY on a protected table is not encrypted by the proxy"
                        );
                    }
                }
                Ok(false)
            }
            _ => Ok(false),
        }
    }
}

/// Seals one literal in place, or records the placeholder for Bind time.
/// Returns whether the statement text changed.
fn seal_expr(
    expr: &mut Expr,
    transform: &Arc<EncryptTransform>,
    params: &mut ParamTransforms,
) -> Result<bool, Error> {
    let sealed = match expr {
        Expr::Value(Value::SingleQuotedString(s)) => transform.seal(s.as_bytes())?,
        Expr::Value(Value::Number(n, _)) => transform.seal(n.as_bytes())?,
        Expr::Value(Value::Placeholder(p)) => {
            if let Some(index) = p.strip_prefix('$').and_then(|n| n.parse::<usize>().ok()) {
                params.push((index - 1, transform.clone()));
            }
            return Ok(false);
        }
        Expr::Value(Value::Null) => return Ok(false),
        other => {
            tracing::warn!(
                expr = %other,
                "unsupported expression for a protected column; passing through unencrypted"
            );
            return Ok(false);
        }
    };
    *expr = Expr::Value(Value::SingleQuotedString(format!("\\x{}", hex::encode(sealed))));
    Ok(true)
}

/// What one SQL text produced: a rewritten statement (when literals were
/// sealed) and the placeholder positions to seal at Bind time.
struct RewriteOutcome {
    rewritten: Option<String>,
    params: ParamTransforms,
}

impl RewriteOutcome {
    fn passthrough() -> Self {
        Self { rewritten: None, params: Vec::new() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rows::tests::transform;
    use dbsec_core::blind_index;

    fn catalog(searchable: bool) -> Arc<WriteCatalog> {
        Arc::new(WriteCatalog::new(&[ProtectedColumn {
            schema: "public".into(),
            table: "users".into(),
            column: "email".into(),
            transform: transform(searchable),
        }]))
    }

    fn query_frame(sql: &str) -> Vec<u8> {
        let mut body = sql.as_bytes().to_vec();
        body.push(0);
        body
    }

    /// Extracts the sealed hex literal out of a rewritten statement and
    /// opens it.
    fn open_hex_literal(sql: &str, searchable: bool) -> Vec<u8> {
        let start = sql.find("'\\x").expect("hex literal") + 3;
        let end = sql[start..].find('\'').unwrap() + start;
        let stored = hex::decode(&sql[start..end]).unwrap();
        transform(searchable).open(&stored).unwrap().expect("opens")
    }

    #[test]
    fn insert_literal_is_sealed() {
        let mut rewriter = QueryRewriter::new(catalog(false));
        let body = query_frame("INSERT INTO users (id, email) VALUES (1, 'alice@example.com')");
        let rewritten = rewriter.on_frame(b'Q', &body).unwrap().unwrap();
        let sql = std::str::from_utf8(&rewritten[..rewritten.len() - 1]).unwrap();
        assert!(!sql.contains("alice@example.com"));
        assert_eq!(open_hex_literal(sql, false), b"alice@example.com");
    }

    #[test]
    fn update_literal_is_sealed_and_searchable_gets_index() {
        let mut rewriter = QueryRewriter::new(catalog(true));
        let body = query_frame("UPDATE users SET email = 'bob@example.com' WHERE id = 7");
        let rewritten = rewriter.on_frame(b'Q', &body).unwrap().unwrap();
        let sql = std::str::from_utf8(&rewritten[..rewritten.len() - 1]).unwrap();
        assert!(!sql.contains("bob@example.com"));
        assert_eq!(open_hex_literal(sql, true), b"bob@example.com");

        // The stored form carries the blind index.
        let start = sql.find("'\\x").unwrap() + 3;
        let end = sql[start..].find('\'').unwrap() + start;
        let stored = hex::decode(&sql[start..end]).unwrap();
        let (index, _) = blind_index::split(&stored).unwrap();
        assert_eq!(index, blind_index::compute(&crate::rows::tests::INDEX_KEY, b"bob@example.com"));
    }

    #[test]
    fn unrelated_sql_passes_through() {
        let mut rewriter = QueryRewriter::new(catalog(false));
        for sql in [
            "SELECT * FROM users",
            "INSERT INTO other (email) VALUES ('x')",
            "UPDATE other SET email = 'x'",
            "this is not SQL at all",
        ] {
            assert!(rewriter.on_frame(b'Q', &query_frame(sql)).unwrap().is_none(), "{sql}");
        }
    }

    #[test]
    fn extended_protocol_seals_bound_params() {
        let mut rewriter = QueryRewriter::new(catalog(false));

        let parse = pgwire::encode_parse(
            b"stmt1",
            b"INSERT INTO users (id, email) VALUES ($1, $2)",
            &0i16.to_be_bytes(),
        );
        assert!(rewriter.on_frame(b'P', &parse).unwrap().is_none());

        // Text-format params: the protected one becomes \x hex.
        let bind = pgwire::encode_bind(
            b"",
            b"stmt1",
            &[],
            &[
                Some(Cow::Borrowed(b"1".as_slice())),
                Some(Cow::Borrowed(b"carol@example.com".as_slice())),
            ],
            &0i16.to_be_bytes(),
        );
        let rewritten = rewriter.on_frame(b'B', &bind).unwrap().unwrap();
        let bound = pgwire::parse_bind(&rewritten).unwrap();
        assert_eq!(bound.params[0], Some(b"1".as_slice()));
        let sealed_hex = bound.params[1].unwrap();
        let stored = hex::decode(sealed_hex.strip_prefix(b"\\x").unwrap()).unwrap();
        assert_eq!(transform(false).open(&stored).unwrap().unwrap(), b"carol@example.com");

        // Binary-format params stay raw bytes.
        let bind = pgwire::encode_bind(
            b"",
            b"stmt1",
            &[1],
            &[
                Some(Cow::Borrowed(b"1".as_slice())),
                Some(Cow::Borrowed(b"dave@example.com".as_slice())),
            ],
            &0i16.to_be_bytes(),
        );
        let rewritten = rewriter.on_frame(b'B', &bind).unwrap().unwrap();
        let bound = pgwire::parse_bind(&rewritten).unwrap();
        assert_eq!(
            transform(false).open(bound.params[1].unwrap()).unwrap().unwrap(),
            b"dave@example.com"
        );

        // Closing the statement forgets it.
        let mut close = vec![b'S'];
        close.extend_from_slice(b"stmt1\0");
        rewriter.on_frame(b'C', &close).unwrap();
        assert!(rewriter.on_frame(b'B', &bind).unwrap().is_none());
    }

    #[test]
    fn parse_with_inline_literal_is_rewritten() {
        let mut rewriter = QueryRewriter::new(catalog(false));
        let parse = pgwire::encode_parse(
            b"",
            b"INSERT INTO users (email) VALUES ('eve@example.com')",
            &0i16.to_be_bytes(),
        );
        let rewritten = rewriter.on_frame(b'P', &parse).unwrap().unwrap();
        let reparsed = pgwire::parse_parse(&rewritten).unwrap();
        let sql = std::str::from_utf8(reparsed.query).unwrap();
        assert!(!sql.contains("eve@example.com"));
        assert_eq!(open_hex_literal(sql, false), b"eve@example.com");
    }

    #[test]
    fn null_and_unsupported_expressions_pass_through() {
        let mut rewriter = QueryRewriter::new(catalog(false));
        assert!(rewriter
            .on_frame(b'Q', &query_frame("INSERT INTO users (email) VALUES (NULL)"))
            .unwrap()
            .is_none());
        assert!(rewriter
            .on_frame(b'Q', &query_frame("INSERT INTO users (email) VALUES (lower('X'))"))
            .unwrap()
            .is_none());
    }
}
