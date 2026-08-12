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
use dbsec_core::transform::{FieldTransform, WireForm};
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
    tables: HashMap<(String, String), HashMap<String, Arc<dyn FieldTransform>>>,
}

impl WriteCatalog {
    pub fn new(columns: &[ProtectedColumn]) -> Self {
        let mut tables: HashMap<_, HashMap<_, _>> = HashMap::new();
        // Mask-only columns have no transform; their writes pass through.
        for column in columns {
            let Some(transform) = &column.transform else { continue };
            tables
                .entry((column.schema.clone(), column.table.clone()))
                .or_default()
                .insert(column.column.clone(), transform.clone());
        }
        Self { tables }
    }

    /// Looks a table up the way Postgres would resolve the SQL name: the last
    /// identifier is the table, the one before it the schema, and bare names
    /// fall back to `public` (search_path is not consulted — a caveat).
    fn table(&self, name: &ObjectName) -> Option<&HashMap<String, Arc<dyn FieldTransform>>> {
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

/// What Bind must do to one parameter of a prepared statement.
#[derive(Clone)]
enum ParamAction {
    /// The parameter feeds a protected column: seal it.
    Seal(Arc<dyn FieldTransform>),
    /// The parameter is compared for equality against a searchable column:
    /// replace it with the blind index (the SQL was rewritten to match the
    /// index prefix).
    SearchIndex(Arc<dyn FieldTransform>),
}

/// Which parameter placeholders of a prepared statement need transforming.
type ParamTransforms = Vec<(usize, ParamAction)>;

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
                for (index, action) in params {
                    let Some(Some(value)) = values.get_mut(*index) else { continue };
                    let (replacement, wire) = match action {
                        ParamAction::Seal(transform) => (transform.seal(value)?, transform.wire()),
                        ParamAction::SearchIndex(transform) => {
                            let Some(token) = transform.search_index(value)? else {
                                return Err(Error::Wire(dbsec_core::Error::Malformed));
                            };
                            // The index prefix is BYTEA regardless of the
                            // transform's own stored form.
                            (token, WireForm::Bytea)
                        }
                    };
                    *value = match wire {
                        // Text-shaped stored forms (FPE digits, hex tokens)
                        // are the same bytes in either parameter format.
                        WireForm::Text => Cow::Owned(replacement),
                        WireForm::Bytea if bind.param_format(*index) == 1 => {
                            Cow::Owned(replacement)
                        }
                        // Text-format parameter for a BYTEA column: hex form.
                        WireForm::Bytea => {
                            Cow::Owned(format!("\\x{}", hex::encode(replacement)).into_bytes())
                        }
                    };
                }
                Ok(Some(pgwire::encode_bind(
                    bind.portal,
                    bind.statement,
                    &bind.param_formats,
                    &values,
                    bind.result_formats,
                )?))
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
                let protected: Vec<(usize, Arc<dyn FieldTransform>)> = insert
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
            Statement::Update { table, assignments, selection, .. } => {
                let mut changed = false;
                if let sqlparser::ast::TableFactor::Table { name, .. } = &table.relation {
                    if let Some(columns) = self.catalog.table(name) {
                        for Assignment { target, value } in assignments {
                            let AssignmentTarget::ColumnName(column) = target else { continue };
                            let Some(ident) = column.0.last() else { continue };
                            let Some(transform) = columns.get(&normalize(ident)) else { continue };
                            changed |= seal_expr(value, transform, params)?;
                        }
                    }
                }
                let scope = self.scope(std::slice::from_ref(table));
                if let Some(selection) = selection {
                    changed |= rewrite_selection(selection, &scope, params)?;
                }
                Ok(changed)
            }
            Statement::Query(query) => {
                let SetExpr::Select(select) = query.body.as_mut() else { return Ok(false) };
                let scope = self.scope(&select.from);
                let mut changed = false;
                if let Some(selection) = select.selection.as_mut() {
                    changed |= rewrite_selection(selection, &scope, params)?;
                }
                Ok(changed)
            }
            Statement::Delete(delete) => {
                let tables = match &delete.from {
                    sqlparser::ast::FromTable::WithFromKeyword(tables)
                    | sqlparser::ast::FromTable::WithoutKeyword(tables) => tables,
                };
                let scope = self.scope(tables);
                let mut changed = false;
                if let Some(selection) = delete.selection.as_mut() {
                    changed |= rewrite_selection(selection, &scope, params)?;
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

    /// Collects the protected tables visible to a WHERE clause, with their
    /// aliases, so column references can be resolved.
    fn scope<'a>(&'a self, from: &'a [sqlparser::ast::TableWithJoins]) -> TableScope<'a> {
        let mut tables = Vec::new();
        for table_with_joins in from {
            let factors = std::iter::once(&table_with_joins.relation)
                .chain(table_with_joins.joins.iter().map(|join| &join.relation));
            for factor in factors {
                let sqlparser::ast::TableFactor::Table { name, alias, .. } = factor else {
                    continue;
                };
                let Some(columns) = self.catalog.table(name) else { continue };
                tables.push(ScopedTable {
                    alias: alias.as_ref().map(|a| normalize(&a.name)),
                    name,
                    columns,
                });
            }
        }
        TableScope { tables }
    }
}

struct ScopedTable<'a> {
    alias: Option<String>,
    name: &'a ObjectName,
    columns: &'a HashMap<String, Arc<dyn FieldTransform>>,
}

/// Protected tables a WHERE clause can reference.
struct TableScope<'a> {
    tables: Vec<ScopedTable<'a>>,
}

impl TableScope<'_> {
    /// Resolves a (possibly qualified) column reference to its transform.
    /// Unqualified names matching more than one protected table are skipped —
    /// ambiguity must not guess.
    fn resolve(&self, idents: &[Ident]) -> Option<&Arc<dyn FieldTransform>> {
        let (column, qualifiers) = idents.split_last()?;
        let column = normalize(column);
        let matches: Vec<_> = self
            .tables
            .iter()
            .filter(|table| table.matches(qualifiers))
            .filter_map(|table| table.columns.get(&column))
            .collect();
        match matches.as_slice() {
            [transform] => Some(transform),
            [] => None,
            _ => {
                tracing::warn!(column, "ambiguous column reference; equality not rewritten");
                None
            }
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
                    || self.name.0.last().is_some_and(|last| normalize(last) == qualifier)
            }
            _ => {
                // schema.table (or longer): compare the trailing parts.
                let want: Vec<String> = qualifiers.iter().map(normalize).collect();
                let have: Vec<String> = self.name.0.iter().map(normalize).collect();
                have.len() >= want.len() && have[have.len() - want.len()..] == want[..]
            }
        }
    }
}

/// Recursively rewrites `col = value` equality against searchable columns
/// into a blind-index prefix match. Traverses AND/OR/NOT and parentheses;
/// anything else is left untouched.
fn rewrite_selection(
    expr: &mut Expr,
    scope: &TableScope<'_>,
    params: &mut ParamTransforms,
) -> Result<bool, Error> {
    use sqlparser::ast::BinaryOperator;
    match expr {
        Expr::BinaryOp { left, op: BinaryOperator::Eq, right } => {
            if let Some(transform) = column_ref(scope, left) {
                let transform = transform.clone();
                rewrite_equality(left, right, &transform, params)
            } else if let Some(transform) = column_ref(scope, right) {
                let transform = transform.clone();
                rewrite_equality(right, left, &transform, params)
            } else {
                Ok(false)
            }
        }
        Expr::BinaryOp { left, op: BinaryOperator::And | BinaryOperator::Or, right } => {
            let l = rewrite_selection(left, scope, params)?;
            let r = rewrite_selection(right, scope, params)?;
            Ok(l | r)
        }
        Expr::Nested(inner) => rewrite_selection(inner, scope, params),
        Expr::UnaryOp { op: sqlparser::ast::UnaryOperator::Not, expr: inner } => {
            rewrite_selection(inner, scope, params)
        }
        _ => Ok(false),
    }
}

fn column_ref<'a>(scope: &'a TableScope<'_>, expr: &Expr) -> Option<&'a Arc<dyn FieldTransform>> {
    match expr {
        Expr::Identifier(ident) => scope.resolve(std::slice::from_ref(ident)),
        Expr::CompoundIdentifier(idents) => scope.resolve(idents),
        _ => None,
    }
}

/// Turns `col = <value>` into `substring(col from 1 for 32) = <index>`.
/// Literals get the index inline; placeholders are indexed at Bind time.
fn rewrite_equality(
    column: &mut Expr,
    value: &mut Expr,
    transform: &Arc<dyn FieldTransform>,
    params: &mut ParamTransforms,
) -> Result<bool, Error> {
    if !transform.supports_search() {
        return Ok(false);
    }
    match unwrap_casts(value) {
        Expr::Value(Value::Placeholder(p)) => {
            let Some(index) = placeholder_index(p) else { return Ok(false) };
            params.push((index, ParamAction::SearchIndex(transform.clone())));
        }
        _ => {
            let Some(plaintext) = literal_plaintext(value, transform.wire()) else {
                return Ok(false);
            };
            let Some(token) = transform.search_index(&plaintext)? else { return Ok(false) };
            *value = Expr::Value(Value::SingleQuotedString(format!("\\x{}", hex::encode(token))));
        }
    }
    *column = index_prefix(std::mem::replace(column, Expr::Value(Value::Null)));
    Ok(true)
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

fn placeholder_index(placeholder: &str) -> Option<usize> {
    placeholder.strip_prefix('$').and_then(|n| n.parse::<usize>().ok()).map(|n| n - 1)
}

/// Peels the casts and parentheses drivers wrap literals in — psycopg's
/// client-side binding renders every bytes parameter as `'\x…'::bytea` — so
/// the value underneath can be recognised.
fn unwrap_casts(expr: &Expr) -> &Expr {
    match expr {
        Expr::Cast { expr, .. } | Expr::Nested(expr) => unwrap_casts(expr),
        other => other,
    }
}

/// The plaintext a literal expression stands for, or `None` when it is not a
/// literal at all. For BYTEA-form columns a `\x`-prefixed string is
/// Postgres' hex input syntax, so it denotes the bytes it encodes rather than
/// its own characters — sealing it verbatim would round-trip the hex text.
fn literal_plaintext(expr: &Expr, wire: WireForm) -> Option<Vec<u8>> {
    match unwrap_casts(expr) {
        Expr::Value(Value::SingleQuotedString(s)) => Some(match wire {
            WireForm::Bytea => s
                .strip_prefix("\\x")
                .and_then(|hex| hex::decode(hex).ok())
                .unwrap_or_else(|| s.as_bytes().to_vec()),
            WireForm::Text => s.as_bytes().to_vec(),
        }),
        Expr::Value(Value::Number(n, _)) => Some(n.as_bytes().to_vec()),
        _ => None,
    }
}

/// Seals one literal in place, or records the placeholder for Bind time.
/// Returns whether the statement text changed.
fn seal_expr(
    expr: &mut Expr,
    transform: &Arc<dyn FieldTransform>,
    params: &mut ParamTransforms,
) -> Result<bool, Error> {
    match unwrap_casts(expr) {
        Expr::Value(Value::Placeholder(p)) => {
            if let Some(index) = placeholder_index(p) {
                params.push((index, ParamAction::Seal(transform.clone())));
            }
            return Ok(false);
        }
        Expr::Value(Value::Null) => return Ok(false),
        _ => {}
    }
    let Some(plaintext) = literal_plaintext(expr, transform.wire()) else {
        tracing::warn!(
            expr = %expr,
            "unsupported expression for a protected column; passing through unencrypted"
        );
        return Ok(false);
    };
    let sealed = transform.seal(&plaintext)?;
    let literal = match transform.wire() {
        WireForm::Bytea => format!("\\x{}", hex::encode(sealed)),
        WireForm::Text => String::from_utf8_lossy(&sealed).into_owned(),
    };
    *expr = Expr::Value(Value::SingleQuotedString(literal));
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

    fn column(name: &str, transform: Arc<dyn FieldTransform>, searchable: bool) -> ProtectedColumn {
        ProtectedColumn {
            schema: "public".into(),
            table: "users".into(),
            column: name.into(),
            transform: Some(transform),
            searchable,
            readable: true,
            mask: None,
        }
    }

    fn catalog(searchable: bool) -> Arc<WriteCatalog> {
        Arc::new(WriteCatalog::new(&[column("email", transform(searchable), searchable)]))
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

    /// psycopg (client-side binding, and psycopg2 always) renders a bytes
    /// parameter as `'\x…'::bytea`: the cast has to be seen through, and the
    /// hex decoded, or the column would store the hex text — or plaintext.
    #[test]
    fn cast_wrapped_bytea_literals_are_sealed_as_the_bytes_they_denote() {
        let mut rewriter = QueryRewriter::new(catalog(false));
        let hex = hex::encode("alice@example.com");
        let body = query_frame(&format!("INSERT INTO users (email) VALUES ('\\x{hex}'::bytea)"));
        let rewritten = rewriter.on_frame(b'Q', &body).unwrap().unwrap();
        let sql = std::str::from_utf8(&rewritten[..rewritten.len() - 1]).unwrap();
        assert!(!sql.contains(&hex), "the plaintext bytes are still on the wire: {sql}");
        assert_eq!(open_hex_literal(sql, false), b"alice@example.com");
    }

    #[test]
    fn cast_wrapped_searchable_equality_is_rewritten() {
        use crate::rows::tests::INDEX_KEY;
        use dbsec_core::blind_index;

        let mut rewriter = QueryRewriter::new(catalog(true));
        let hex = hex::encode("alice@example.com");
        let body = query_frame(&format!("SELECT id FROM users WHERE email = '\\x{hex}'::bytea"));
        let rewritten = rewriter.on_frame(b'Q', &body).unwrap().unwrap();
        let sql = std::str::from_utf8(&rewritten[..rewritten.len() - 1]).unwrap();

        let expected = blind_index::compute(&INDEX_KEY, b"alice@example.com");
        assert!(sql.contains("SUBSTRING(email FROM 1 FOR 32)"), "{sql}");
        assert!(sql.contains(&format!("'\\x{}'", hex::encode(expected))), "{sql}");
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
        )
        .unwrap();
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
        )
        .unwrap();
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
    fn text_shaped_transforms_seal_as_plain_literals_and_params() {
        use crate::rows::tests::OneKey;
        use dbsec_core::transform::{FpeTransform, TokenTransform};

        let fpe: Arc<dyn FieldTransform> =
            Arc::new(FpeTransform::new(Arc::new(OneKey), "public.users.phone".into(), true));
        let token: Arc<dyn FieldTransform> =
            Arc::new(TokenTransform::new(Arc::new(OneKey), "public.users.ssn".into()));
        let catalog = Arc::new(WriteCatalog::new(&[
            column("phone", fpe.clone(), false),
            column("ssn", token.clone(), false),
        ]));
        let mut rewriter = QueryRewriter::new(catalog);

        // FPE literal keeps its digit shape — no \x hex, no plaintext.
        let body = query_frame("INSERT INTO users (phone, ssn) VALUES ('555-867-5309', 'abc')");
        let rewritten = rewriter.on_frame(b'Q', &body).unwrap().unwrap();
        let sql = std::str::from_utf8(&rewritten[..rewritten.len() - 1]).unwrap();
        assert!(!sql.contains("555-867-5309") && !sql.contains("\\x"), "{sql}");
        let pseudonym = sql.split('\'').nth(1).expect("first literal");
        assert_eq!(pseudonym.len(), 12);
        assert_eq!(&pseudonym[3..4], "-");
        assert_eq!(fpe.open(pseudonym.as_bytes()).unwrap().unwrap(), b"555-867-5309");
        // Token literal is the 64-char hex HMAC.
        let token_literal = sql.split('\'').nth(3).expect("second literal");
        assert_eq!(token_literal.len(), 64);
        assert_eq!(token_literal.as_bytes(), token.seal(b"abc").unwrap().as_slice());

        // Bound text-format param for an FPE column stays digit-shaped.
        let parse = pgwire::encode_parse(
            b"s1",
            b"UPDATE users SET phone = $1 WHERE id = $2",
            &0i16.to_be_bytes(),
        );
        assert!(rewriter.on_frame(b'P', &parse).unwrap().is_none());
        let bind = pgwire::encode_bind(
            b"",
            b"s1",
            &[],
            &[
                Some(Cow::Borrowed(b"555-867-5309".as_slice())),
                Some(Cow::Borrowed(b"7".as_slice())),
            ],
            &0i16.to_be_bytes(),
        )
        .unwrap();
        let rewritten = rewriter.on_frame(b'B', &bind).unwrap().unwrap();
        let bound = pgwire::parse_bind(&rewritten).unwrap();
        let sealed = bound.params[0].unwrap();
        assert!(!sealed.starts_with(b"\\x"));
        assert_eq!(fpe.open(sealed).unwrap().unwrap(), b"555-867-5309");
        assert_eq!(bound.params[1], Some(b"7".as_slice()));
    }

    #[test]
    fn fpe_seal_of_tiny_domain_fails_closed() {
        use crate::rows::tests::OneKey;
        use dbsec_core::transform::FpeTransform;

        let fpe: Arc<dyn FieldTransform> =
            Arc::new(FpeTransform::new(Arc::new(OneKey), "public.users.pin".into(), true));
        let catalog = Arc::new(WriteCatalog::new(&[column("pin", fpe, false)]));
        let mut rewriter = QueryRewriter::new(catalog);
        let body = query_frame("INSERT INTO users (pin) VALUES ('1234')");
        assert!(rewriter.on_frame(b'Q', &body).is_err());
    }

    #[test]
    fn searchable_equality_rewrites_to_index_prefix_match() {
        use crate::rows::tests::INDEX_KEY;
        use dbsec_core::blind_index;

        let mut rewriter = QueryRewriter::new(catalog(true));
        let body = query_frame("SELECT id FROM users WHERE email = 'alice@example.com'");
        let rewritten = rewriter.on_frame(b'Q', &body).unwrap().unwrap();
        let sql = std::str::from_utf8(&rewritten[..rewritten.len() - 1]).unwrap();

        let expected = blind_index::compute(&INDEX_KEY, b"alice@example.com");
        assert!(!sql.contains("alice@example.com"), "{sql}");
        assert!(sql.contains("SUBSTRING(email FROM 1 FOR 32)"), "prefix match missing: {sql}");
        assert!(sql.contains(&format!("'\\x{}'", hex::encode(expected))), "{sql}");

        // Aliased and AND-nested references rewrite too; DELETE works.
        let body = query_frame(
            "DELETE FROM users u WHERE u.id > 4 AND (u.email = 'bob@x.io' OR u.email = 'c@y.io')",
        );
        let rewritten = rewriter.on_frame(b'Q', &body).unwrap().unwrap();
        let sql = std::str::from_utf8(&rewritten[..rewritten.len() - 1]).unwrap();
        assert!(!sql.contains("bob@x.io") && !sql.contains("c@y.io"), "{sql}");
        assert_eq!(sql.matches("SUBSTRING(u.email FROM 1 FOR 32)").count(), 2, "{sql}");
    }

    #[test]
    fn searchable_equality_placeholder_binds_the_index() {
        use crate::rows::tests::INDEX_KEY;
        use dbsec_core::blind_index;

        let mut rewriter = QueryRewriter::new(catalog(true));
        let parse = pgwire::encode_parse(
            b"find",
            b"SELECT id FROM users WHERE email = $1",
            &0i16.to_be_bytes(),
        );
        let rewritten = rewriter.on_frame(b'P', &parse).unwrap().unwrap();
        let reparsed = pgwire::parse_parse(&rewritten).unwrap();
        let sql = std::str::from_utf8(reparsed.query).unwrap();
        assert!(sql.contains("SUBSTRING(email FROM 1 FOR 32) = $1"), "{sql}");

        let bind = pgwire::encode_bind(
            b"",
            b"find",
            &[],
            &[Some(Cow::Borrowed(b"alice@example.com".as_slice()))],
            &0i16.to_be_bytes(),
        )
        .unwrap();
        let rewritten = rewriter.on_frame(b'B', &bind).unwrap().unwrap();
        let bound = pgwire::parse_bind(&rewritten).unwrap();
        let expected = blind_index::compute(&INDEX_KEY, b"alice@example.com");
        assert_eq!(bound.params[0].unwrap(), format!("\\x{}", hex::encode(expected)).as_bytes());
    }

    #[test]
    fn non_searchable_equality_is_left_alone() {
        let mut rewriter = QueryRewriter::new(catalog(false));
        for sql in [
            "SELECT id FROM users WHERE email = 'alice@example.com'",
            "SELECT id FROM other WHERE email = 'x'",
            "SELECT id FROM users WHERE id = 4",
        ] {
            assert!(rewriter.on_frame(b'Q', &query_frame(sql)).unwrap().is_none(), "{sql}");
        }
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
