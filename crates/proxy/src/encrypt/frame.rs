//! The pgwire frame layer of the rewriter: the extended-protocol messages the
//! write path acts on, and nothing about SQL itself.
//!
//! [`QueryRewriter::on_frame`] is the only entry point the session calls. What
//! lives here is the part that speaks *frames* — which message types carry SQL
//! or values, how a Parse/Bind/Describe/Close is unpacked, what a refusal
//! looks like on the wire, and how a batch is discarded until the next Sync.
//! The SQL it uncovers is handed to the statement layer; the values it
//! uncovers are handed to the parameter transforms recorded there.
//!
//! Splitting it out is what lets the two be reviewed apart: a frame bug loses
//! protocol sync, a rewrite bug relays a plaintext, and the two failure modes
//! have almost nothing in common beyond meeting here.

use std::borrow::Cow;
use std::sync::atomic::Ordering;

use dbsec_core::envelope::RowKey;
use dbsec_core::transform::WireForm;
use dbsec_pgwire as pgwire;

use crate::portal::{ParamAction, ParamTransforms, ResultFormats, RowKeySource, Target};
use crate::session::FrameAction;
use crate::Error;
use dbsec_core::rowkey;

use super::array::index_array;
use super::unprotected::{error_response, frame, Unprotected};
use super::{QueryRewriter, Rejection, SqlOutcome};

/// Records what Bind must do to one placeholder, turning the single refusal
/// [`ParamTransforms::record`] can raise into a *statement-level* one.
///
/// `INSERT INTO users (email, backup_email) VALUES ($1, $1)` with the two
/// columns under different transforms — or `UPDATE users SET email = $1 WHERE
/// email = $1`, which needs the sealed value in the SET and the blind index in
/// the WHERE — is valid client SQL, not a protocol violation. The Bind carries
/// one value per placeholder, so only one of the two answers fits on the wire
/// and the statement cannot be honoured. Refusing it is the whole remedy:
/// nothing has gone upstream at this point, so the same
/// [`SqlOutcome::Refuse`] path every other unrewritable statement takes
/// applies unchanged.
///
/// It used to travel as [`Rejection::Fatal`], which tore the session down over
/// well-formed SQL and told the client nothing but a closed socket — and under
/// a connection pool the retry killed the next connection too.
///
/// Unlike an [`Unprotected`] site this does not consult `on_unprotected`:
/// there is no "warn and relay" answer available. Letting it through would
/// seal a value and then blind-index the ciphertext, or seal an already-sealed
/// value — silently, and irreversibly in the second case (CL-3), which is the
/// outcome [`ParamTransforms`] exists to prevent.
pub(super) fn record_param(
    params: &mut ParamTransforms,
    index: usize,
    action: ParamAction,
) -> Result<(), Rejection> {
    match params.record(index, action) {
        Ok(()) => Ok(()),
        Err(Error::ConflictingParameter { placeholder }) => Err(Rejection::Refused(format!(
            "dbsec refused this statement: placeholder ${placeholder} feeds two protected \
             positions that need different values, and a Bind carries one value per \
             placeholder; give each position its own placeholder"
        ))),
        Err(other) => Err(Rejection::Fatal(Box::new(other))),
    }
}

/// The row key one sealed parameter binds to, resolved from the Bind that
/// carries it.
///
/// [`RowKeySource::Param`] is the only arm with work to do: the key is another
/// parameter of this same Bind, so its bytes exist only now. Canonicalising
/// them reads *client input* — a NULL, a text body that is not UTF-8, a binary
/// integer of the wrong width, an undefined format code — and every one of
/// those is ordinary, well-formed traffic that a client can send by accident.
///
/// Propagating them as [`Error`] closed the connection with no ErrorResponse,
/// which is the regression [`record_param`] was written to remove two lines
/// away in the same function: a session torn down over well-formed SQL, and
/// under a connection pool the retry killing the next connection too. They are
/// statement-level refusals for the same reason every other Bind-time refusal
/// is — nothing has gone upstream, so the statement can be refused and the
/// session kept.
fn bind_row_key(
    row: &RowKeySource,
    bind: &pgwire::BindMessage<'_>,
) -> Result<Option<RowKey>, Rejection> {
    let (index, type_oid, column) = match row {
        RowKeySource::None => return Ok(None),
        RowKeySource::Literal(key) => return Ok(Some(key.clone())),
        RowKeySource::Param { index, type_oid, column } => (*index, *type_oid, column),
    };
    let resolved = rowkey::Format::from_code(bind.param_format(index)).and_then(|format| {
        rowkey::canonical(type_oid, format, bind.params.get(index).copied().flatten())
    });
    match resolved {
        Ok(key) => Ok(Some(key)),
        Err(dbsec_core::Error::RowKeyType(why)) => Err(Rejection::Refused(format!(
            "dbsec refused this statement: placeholder ${} supplies the row key {column} that \
             this statement's protected values are sealed against, but {why}; bind a usable \
             {column} for the row being written",
            index.saturating_add(1)
        ))),
        Err(other) => Err(Rejection::Fatal(Box::new(Error::from(other)))),
    }
}

impl QueryRewriter {
    /// Inspects one client→upstream frame, returning what the relay should do
    /// with it.
    pub fn on_frame(&mut self, msg_type: u8, body: &[u8]) -> Result<FrameAction, Error> {
        if self.awaiting_sync {
            return Ok(self.discard_until_sync(msg_type));
        }
        match msg_type {
            b'Q' => {
                let mut sql = body;
                let query = pgwire::take_cstr(&mut sql)?;
                match self.rewrite_sql(query)? {
                    // Refused here, so the backend never sees it and owes no
                    // ReadyForQuery: the proxy answers with its own, and no
                    // batch is recorded.
                    SqlOutcome::Refuse(message) => {
                        let mut reply = error_response(&message);
                        reply.extend_from_slice(&self.ready_for_query());
                        Ok(FrameAction::Reply(reply))
                    }
                    SqlOutcome::Rewrite(outcome) => {
                        // A simple Query is its own batch: the backend answers
                        // it with a ReadyForQuery, which is where the read
                        // path resynchronises.
                        self.portals.expect_batch()?;
                        Ok(match outcome.rewritten {
                            None => FrameAction::Relay,
                            Some(rewritten) => {
                                let mut new_body = rewritten.into_bytes();
                                new_body.push(0);
                                FrameAction::Replace(new_body)
                            }
                        })
                    }
                }
            }
            b'P' => {
                let parse = pgwire::parse_parse(body)?;
                let outcome = match self.rewrite_sql(parse.query)? {
                    SqlOutcome::Refuse(message) => {
                        // The backend is not going to answer this batch, so
                        // the proxy owns the error state until Sync. Nothing
                        // is recorded for this statement: the frame is not
                        // forwarded, so no response is owed for it.
                        self.awaiting_sync = true;
                        return Ok(FrameAction::Reply(error_response(&message)));
                    }
                    SqlOutcome::Rewrite(outcome) => outcome,
                };
                self.portals.parse(parse.statement, outcome.params)?;
                Ok(match outcome.rewritten {
                    None => FrameAction::Relay,
                    Some(sql) => FrameAction::Replace(pgwire::encode_parse(
                        parse.statement,
                        sql.as_bytes(),
                        parse.param_types,
                    )),
                })
            }
            b'B' => self.bind(body),
            b'D' => {
                // Describe: the RowDescription it provokes is what tells the
                // read path which columns of this statement are protected.
                let (target, name) = describe_target(body)?;
                self.portals.expect_describe(target, name)?;
                Ok(FrameAction::Relay)
            }
            b'E' => {
                let mut rest = body;
                let portal = pgwire::take_cstr(&mut rest)?;
                self.portals.expect_execute(portal)?;
                Ok(FrameAction::Relay)
            }
            b'S' => {
                self.portals.expect_batch()?;
                Ok(FrameAction::Relay)
            }
            // FunctionCall: the legacy fast path, answered by
            // FunctionCallResponse **and a ReadyForQuery** — it is the one
            // client message outside Sync and the simple Query that closes a
            // batch on its own. Left unrecorded it queued nothing, and its
            // ReadyForQuery then settled the *next* batch's marker: from there
            // every response was matched to the expectation in front of the one
            // it answered, and a RowDescription was attributed to a following
            // statement. The dangerous direction is a protected position the
            // mis-attributed description does not cover, relayed in its stored
            // form — for a mask-only column the very plaintext the mask exists
            // to hide (SEC-31).
            //
            // The frame itself carries no SQL, so there is nothing to rewrite;
            // whether its *result* may be relayed is decided on the read path,
            // where `rows::RowDecryptor::function_call_result` answers the
            // ordinary `on_unprotected` question about `'V'`.
            b'F' => {
                self.portals.expect_batch()?;
                Ok(FrameAction::Relay)
            }
            // CopyData, CopyDone, CopyFail. In copy-in mode these are the
            // payload, and the backend is ignoring the Sync the client already
            // pipelined. Outside it they are strays PostgreSQL discards
            // without answering — and `copy_data` refuses to move the queue
            // for them, because a client that could pop this batch's marker
            // could desync every response behind it. Relayed either way: the
            // backend's own handling of a stray frame is the authority, and
            // withholding it would only differ from PostgreSQL.
            b'd' | b'c' | b'f' => {
                self.portals.copy_data(msg_type);
                Ok(FrameAction::Relay)
            }
            b'C' => {
                // Close: 'S' = statement, 'P' = portal.
                let (target, name) = describe_target(body)?;
                match target {
                    Target::Statement => self.portals.close_statement(name),
                    Target::Portal => self.portals.close_portal(name),
                }
                Ok(FrameAction::Relay)
            }
            _ => Ok(FrameAction::Relay),
        }
    }

    fn bind(&mut self, body: &[u8]) -> Result<FrameAction, Error> {
        let bind = pgwire::parse_bind(body)?;
        // Recorded even when the statement is unknown to the rewriter: the
        // read path still needs to know which statement this portal names —
        // and, since a Describe of a statement cannot say it, which formats
        // this Bind asked its results back in (SEC-31).
        let result_formats = ResultFormats::new(bind.result_format_codes()?);
        let Some(params) = self.portals.bind(bind.portal, bind.statement, result_formats)? else {
            return Ok(FrameAction::Relay);
        };
        if params.is_empty() {
            return Ok(FrameAction::Relay);
        }
        let mut values: Vec<Option<Cow<'_, [u8]>>> =
            bind.params.iter().map(|p| p.map(Cow::Borrowed)).collect();
        // Every column whose array could not be indexed, not just the last one:
        // an operator handed one name out of two fixes that site and hits the
        // other on the next run.
        let mut unindexed: Vec<String> = Vec::new();
        for (index, action) in params.iter() {
            let binary = bind.param_format(*index) == 1;
            let Some(Some(value)) = values.get_mut(*index) else { continue };
            let replacement = match action {
                ParamAction::Seal { transform, row } => {
                    let key = match bind_row_key(row, &bind) {
                        Ok(key) => key,
                        // Same shape as a refused Parse: nothing has gone
                        // upstream, so the proxy owns the batch until Sync and
                        // the session carries on.
                        Err(Rejection::Refused(message)) => {
                            self.awaiting_sync = true;
                            return Ok(FrameAction::Reply(error_response(&message)));
                        }
                        Err(Rejection::Fatal(error)) => return Err(*error),
                    };
                    encode_param(transform.seal(value, key.as_ref())?, transform.wire(), binary)
                }
                ParamAction::SearchIndex(transform) => {
                    let Some(token) = transform.search_index(value)? else {
                        return Err(Error::Wire(dbsec_core::Error::Malformed));
                    };
                    // The index prefix is BYTEA regardless of the transform's
                    // own stored form.
                    encode_param(token, WireForm::Bytea, binary)
                }
                // The array is already in the parameter's own format: the
                // codec re-encodes it in the shape it decoded.
                ParamAction::SearchIndexArray { transform, column } => {
                    match index_array(value, binary, transform)? {
                        Some(indexed) => indexed,
                        // Nothing about this array can be indexed faithfully.
                        // The SQL already matches the blind index, so leaving
                        // the plaintext array is the "matches no rows" outcome
                        // the warn path describes; strict mode refuses it.
                        None => {
                            unindexed.push(column.to_string());
                            continue;
                        }
                    }
                }
            };
            *value = Cow::Owned(replacement);
        }
        // Every other parameter of this Bind is still transformed on the warn
        // path: a sealed parameter relayed as plaintext because some *other*
        // parameter could not be indexed would write the very thing this proxy
        // exists to prevent.
        if !unindexed.is_empty() {
            let site =
                Unprotected::Predicate { column: unindexed.join(", "), shape: "= ANY bound array" };
            match self.unprotected(&site) {
                Ok(()) => {}
                Err(Rejection::Refused(message)) => {
                    // Same shape as a refused Parse: the backend never sees
                    // the Bind, so the proxy owns the batch until Sync.
                    self.awaiting_sync = true;
                    return Ok(FrameAction::Reply(error_response(&message)));
                }
                Err(Rejection::Fatal(error)) => return Err(*error),
            }
        }
        Ok(FrameAction::Replace(pgwire::encode_bind(
            bind.portal,
            bind.statement,
            &bind.param_formats,
            &values,
            bind.result_formats,
        )?))
    }

    /// After a refusal the backend has no work queued for this batch, so the
    /// proxy mirrors what the backend does in its own error state: drop
    /// everything up to `Sync`, then answer with ReadyForQuery.
    fn discard_until_sync(&mut self, msg_type: u8) -> FrameAction {
        match msg_type {
            b'S' => {
                self.awaiting_sync = false;
                FrameAction::Reply(self.ready_for_query())
            }
            // Terminate ends the session; the backend should see it.
            b'X' => {
                self.awaiting_sync = false;
                FrameAction::Relay
            }
            _ => FrameAction::Reply(Vec::new()),
        }
    }

    /// The ReadyForQuery a refusal answers with. The backend never saw the
    /// statement, so its transaction is still open: reporting the aborted
    /// state is what makes the client roll back instead of committing the
    /// rest of a transaction whose protected write did not happen.
    fn ready_for_query(&self) -> Vec<u8> {
        let status = match self.tx_status.load(Ordering::Relaxed) {
            b'T' | b'E' => b'E',
            _ => b'I',
        };
        frame(b'Z', &[status])
    }
}

/// One transformed Bind parameter, in the format the parameter arrived in.
/// Text-shaped stored forms (FPE digits, hex tokens) are the same bytes in
/// either format; a BYTEA form in a text-format parameter is `\x` hex.
fn encode_param(value: Vec<u8>, wire: WireForm, binary: bool) -> Vec<u8> {
    match wire {
        WireForm::Text => value,
        WireForm::Bytea if binary => value,
        WireForm::Bytea => format!("\\x{}", hex::encode(value)).into_bytes(),
    }
}

/// Splits a Describe or Close body into its target and name — both messages
/// share the shape `u8 kind | cstr name`. A kind byte that is neither `'S'`
/// (statement) nor `'P'` (portal) is a protocol violation the relay must not
/// guess at: carrying on would leave the read path's expectations misaligned
/// with what the server is about to answer.
fn describe_target(body: &[u8]) -> Result<(Target, &[u8]), Error> {
    let [kind, rest @ ..] = body else {
        return Err(Error::Wire(dbsec_core::Error::Malformed));
    };
    let target = match kind {
        b'S' => Target::Statement,
        b'P' => Target::Portal,
        _ => return Err(Error::Wire(dbsec_core::Error::Malformed)),
    };
    let mut rest = rest;
    let name = pgwire::take_cstr(&mut rest)?;
    Ok((target, name))
}
