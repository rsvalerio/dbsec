//! Process hardening applied before any key material is read.
//!
//! The proxy holds every DEK, every deterministic index key and the Vault
//! token in memory for the life of the process. A core dump writes all of it
//! to disk in one file, and the `Drop`-based zeroization the crate relies on
//! never runs on an abort — so the hardening has to be a property of the
//! process, not of the code paths that happen to unwind. `--allow-core-dumps`
//! is the escape hatch for debugging a crash, and it is a flag rather than the
//! default because the operator turning it on is then the one deciding to let
//! keys reach the disk.
//!
//! Swap is the other half of the same problem and cannot be handled from here:
//! `mlockall` would have to cover every allocation the process ever makes, at
//! which point the proxy needs a `RLIMIT_MEMLOCK` the deployment must grant it
//! anyway. That one is documented in the README as a deployment setting
//! (`LimitMEMLOCK` / `MemoryDenyWriteExecute`, or simply no swap on the host)
//! rather than attempted here, where a partial `mlock` would read as a
//! guarantee it is not.

#[cfg(unix)]
use crate::Error;

/// Makes this process undumpable: no core file on a crash, and no `ptrace`
/// attach from another process running as the same user.
///
/// `RLIMIT_CORE = 0` alone is not enough — a `kernel.core_pattern` that pipes
/// to a helper (`systemd-coredump`, `apport`) ignores the soft limit — so the
/// `dumpable` attribute is cleared too, which is what actually stops the
/// kernel handing the image to that helper. Both are set: the rlimit covers
/// the plain-file path and every non-Linux unix, the `prctl` covers the pipe.
///
/// A failure is fatal rather than a warning. The whole point is that key
/// material cannot reach the disk, and a proxy that starts anyway after the
/// guarantee failed is exactly the fail-open startup this wave removes
/// elsewhere; the message names the flag that says "start anyway".
#[cfg(unix)]
pub(crate) fn disable_core_dumps() -> Result<(), Error> {
    use rustix::process::{setrlimit, Resource, Rlimit};

    setrlimit(Resource::Core, Rlimit { current: Some(0), maximum: Some(0) }).map_err(|e| {
        Error::Hardening { what: "setting the core dump limit to 0", source: e.into() }
    })?;
    set_undumpable()
}

/// The Linux half: `prctl(PR_SET_DUMPABLE, 0)`, which has no portable
/// equivalent. On other unices the `RLIMIT_CORE` above is the whole story.
#[cfg(target_os = "linux")]
fn set_undumpable() -> Result<(), Error> {
    use rustix::process::{set_dumpable_behavior, DumpableBehavior};

    set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(|e| Error::Hardening {
        what: "clearing the process' dumpable attribute",
        source: e.into(),
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn set_undumpable() -> Result<(), Error> {
    Ok(())
}

/// Non-unix targets have neither `RLIMIT_CORE` nor `prctl`, and this crate has
/// no portable way to suppress a crash dump there. Documented as a no-op
/// rather than a build failure, on the same reasoning as the secret-file mode
/// check in [`crate::config`].
#[cfg(not(unix))]
pub(crate) fn disable_core_dumps() -> Result<(), crate::Error> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Both halves of the hardening, observed through the kernel rather than
    /// through the call returning `Ok`. Deliberately the only test in this
    /// module: the limits are process-wide, so a second case could only
    /// re-assert the state this one leaves behind.
    #[test]
    fn disabling_core_dumps_zeroes_the_limit_and_clears_dumpable() {
        disable_core_dumps().unwrap();

        let limit = rustix::process::getrlimit(rustix::process::Resource::Core);
        assert_eq!(limit.current, Some(0), "a core file must not be writable");
        assert_eq!(limit.maximum, Some(0), "and the process must not be able to raise it back");

        #[cfg(target_os = "linux")]
        assert_eq!(
            rustix::process::dumpable_behavior().unwrap(),
            rustix::process::DumpableBehavior::NotDumpable,
            "a core_pattern piping to a helper ignores the rlimit; this is what stops it"
        );
    }
}
