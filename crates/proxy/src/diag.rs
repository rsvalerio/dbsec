//! Rendering an error for the log.
//!
//! `tracing::error!(error = %e, …)` formats `Display` and stops there, and
//! `tracing_subscriber::fmt` does not walk [`std::error::Error::source`]. Every
//! cause the error types in this workspace go out of their way to keep — the
//! `io::Error` under a `tokio_postgres` connect failure, the `vaultrs` error
//! under [`dbsec_core::Error::KeyBackend`] — is therefore invisible to the
//! operator, which is precisely the part that distinguishes "connection
//! refused" from "certificate verify failed" and a Vault 403 from an
//! unreachable Vault. [`chain`] is what the handling sites format instead.
//!
//! It renders only what the error types chose to expose. A variant that
//! deliberately drops its cause keeps it dropped: [`crate::Error::ConfigParse`]
//! holds a rendered `reason` and no `#[source]`, because the `toml` error's own
//! `Display` echoes the offending config line — which, on a lost quote in an
//! inline `[vault] token` or a `control_dsn`, is the credential itself. Nothing
//! here can reach around that, and a test in `main` pins it.

use std::fmt;

/// Causes rendered below the top-level error before the chain is cut off.
///
/// A `source()` chain is a linked list this code does not own, so it is walked
/// with a bound rather than on trust: a cycle would otherwise hang the thread
/// that is trying to report a failure. Eight is far past any chain this
/// workspace builds (three is the deepest: proxy error → backend error →
/// `io::Error`).
const MAX_CAUSES: usize = 8;

/// An error and the causes under it, rendered as `top: cause: cause`.
///
/// Wraps rather than returning a `String` so nothing is formatted when the
/// subscriber is not going to record the event.
pub(crate) struct Chain<'a>(&'a (dyn std::error::Error + 'static));

/// Formats `error` together with its `source()` chain — the value to pass to
/// `tracing`'s `error = %…` field.
pub(crate) fn chain<'a>(error: &'a (dyn std::error::Error + 'static)) -> Chain<'a> {
    Chain(error)
}

impl fmt::Display for Chain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Several variants in this crate interpolate `{source}` into their own
        // message (`Error::Control`, `Error::Listen`, `Error::Hardening`), so
        // appending every link unconditionally would print the same sentence
        // twice before reaching the one link that is new. A cause whose text
        // the message above it already contains is therefore skipped — the
        // walk still descends past it, which is where the `io::Error` those
        // variants do not carry in their own `Display` lives.
        let mut above = self.0.to_string();
        f.write_str(&above)?;
        let mut cause = self.0.source();
        for _ in 0..MAX_CAUSES {
            let Some(error) = cause else { return Ok(()) };
            let rendered = error.to_string();
            if !above.contains(&rendered) {
                write!(f, ": {rendered}")?;
            }
            above = rendered;
            cause = error.source();
        }
        if cause.is_some() {
            f.write_str(": …")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("{message}")]
    struct Layer {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    }

    fn layer(message: &str, source: Option<Layer>) -> Layer {
        Layer {
            message: message.to_owned(),
            source: source.map(|source| Box::new(source) as Box<_>),
        }
    }

    #[test]
    fn a_chain_is_rendered_top_down_and_joined_with_colons() {
        let deep = layer("connection refused", None);
        let middle = layer("error connecting to server", Some(deep));
        let top = layer("resolving protected columns", Some(middle));
        assert_eq!(
            chain(&top).to_string(),
            "resolving protected columns: error connecting to server: connection refused"
        );
    }

    /// An error with nothing under it renders exactly as `Display` did before.
    #[test]
    fn an_error_with_no_cause_renders_as_itself() {
        let alone = layer("no config file", None);
        assert_eq!(chain(&alone).to_string(), "no config file");
    }

    /// The variants that interpolate `{source}` into their own message must
    /// not say it twice — but the link *below* the repeat is the whole point
    /// and still has to arrive.
    #[test]
    fn a_cause_the_message_above_already_quotes_is_not_repeated() {
        let io = layer("connection refused", None);
        let quoted = layer("error connecting to server", Some(io));
        let top = layer("control connection to db:5432: error connecting to server", Some(quoted));
        assert_eq!(
            chain(&top).to_string(),
            "control connection to db:5432: error connecting to server: connection refused"
        );
    }

    /// The chain is someone else's linked list: reporting a failure must not
    /// be a way to hang the thread reporting it.
    #[test]
    fn a_chain_longer_than_the_bound_is_cut_off_rather_than_walked_forever() {
        let mut error = layer("bottom", None);
        for i in 0..MAX_CAUSES + 4 {
            error = layer(&format!("level {i}"), Some(error));
        }
        let rendered = chain(&error).to_string();
        assert!(rendered.ends_with(": …"), "{rendered}");
        assert!(!rendered.contains("bottom"), "{rendered}");
        assert_eq!(rendered.matches(": ").count(), MAX_CAUSES + 1, "{rendered}");
    }
}
