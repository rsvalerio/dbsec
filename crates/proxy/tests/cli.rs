//! The `dbsec` binary as a command: argument handling, config discovery, exit
//! codes, and which stream diagnostics go to (TEST-31).
//!
//! These decisions are invisible to unit tests over internal functions, and
//! they are exactly where CLI regressions land: a changed exit code breaks a
//! supervisor's restart policy, and a change to config discovery breaks every
//! deployment relying on the implicit `./dbsec.toml`. Driven with
//! `std::process::Command` rather than a CLI assertion crate — the e2e harness
//! already spawns `CARGO_BIN_EXE_dbsec` this way, and every assertion here is
//! an exact string rather than a fluent chain.

use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// The listen address a run with no config must fall back to.
const DEFAULT_LISTEN: &str = "127.0.0.1:6432";

/// The opt-in that turns a missing config file from a refusal back into
/// built-in defaults. Spelled out here rather than imported: this suite drives
/// the binary as an operator does, so the flag is part of what it pins.
const PLAIN_RELAY_FLAG: &str = "--plain-relay";

/// The opt-in that leaves core dumps enabled, spelled out for the same reason
/// as [`PLAIN_RELAY_FLAG`].
const ALLOW_CORE_DUMPS_FLAG: &str = "--allow-core-dumps";

/// The warning a startup that protects nothing has to carry, whichever way it
/// got there: a config file with no `[[column]]` entries and `--plain-relay`
/// leave the proxy in the same state, so an operator grepping for one finds
/// the other (TASK-0131).
const NO_PROTECTION_WARNING: &str = "no protected columns are configured";

/// `max_sessions` for a config with no argument-passing ambiguity: the
/// default is 256, so any of these values proves *which* file was read.
const EXPLICIT_SESSIONS: usize = 7;
const DISCOVERED_SESSIONS: usize = 9;

/// How long a case waits for the line it expects before declaring the binary
/// hung. Generous: a cold process start on a loaded test runner.
const LINE_TIMEOUT: Duration = Duration::from_secs(30);

/// A config that binds an ephemeral port, so these cases never contend for
/// one with each other or with the e2e suites.
fn config_toml(max_sessions: usize) -> String {
    format!(
        "listen = \"127.0.0.1:0\"\nupstream = \"127.0.0.1:5432\"\nmax_sessions = {max_sessions}\n"
    )
}

fn dbsec(dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dbsec"));
    command
        .current_dir(dir)
        // Pinned so an inherited RUST_LOG cannot filter away the lines
        // asserted below.
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// A spawned proxy plus a thread draining its stderr, so a case can wait for
/// one line without blocking on a process that is designed never to exit.
struct Running {
    child: Child,
    lines: mpsc::Receiver<String>,
}

impl Running {
    fn start(command: &mut Command) -> Self {
        let mut child = command.spawn().expect("the dbsec binary must be runnable");
        let stderr = child.stderr.take().expect("stderr is piped");
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self { child, lines }
    }

    /// The first stderr line containing `needle`.
    fn wait_for(&mut self, needle: &str) -> String {
        let mut seen = Vec::new();
        loop {
            match self.lines.recv_timeout(LINE_TIMEOUT) {
                Ok(line) if line.contains(needle) => return line,
                Ok(line) => seen.push(line),
                Err(e) => panic!("no stderr line containing {needle:?} ({e}); saw {seen:#?}"),
            }
        }
    }

    fn assert_still_serving(&mut self) {
        assert!(
            matches!(self.child.try_wait(), Ok(None)),
            "the proxy exited instead of staying up to serve"
        );
    }

    /// Stops the proxy and returns everything it wrote to stdout. Read only
    /// after the kill: a healthy proxy never closes the stream on its own.
    fn stop(mut self) -> String {
        self.terminate();
        let mut stdout = String::new();
        self.child
            .stdout
            .take()
            .expect("stdout is piped")
            .read_to_string(&mut stdout)
            .expect("the proxy's stdout must be readable");
        stdout
    }

    /// Idempotent: `stop` calls it, and so does `Drop` for the case where an
    /// assertion panicked first. Errors are ignored because the only ones
    /// reachable mean the child is already gone.
    fn terminate(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A panicking assertion must not leave a proxy running: it would hold a
/// listener for the rest of the run and make every later case fail for the
/// wrong reason.
impl Drop for Running {
    fn drop(&mut self) {
        self.terminate();
    }
}

/// An explicit path wins over a `dbsec.toml` sitting in the working
/// directory — otherwise a run that ignored its argument would look correct
/// by accident.
#[test]
fn an_explicit_config_path_is_the_one_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let explicit = dir.path().join("custom.toml");
    std::fs::write(&explicit, config_toml(EXPLICIT_SESSIONS)).unwrap();
    std::fs::write(dir.path().join("dbsec.toml"), config_toml(DISCOVERED_SESSIONS)).unwrap();

    let mut proxy = Running::start(dbsec(dir.path()).arg(&explicit));
    let line = proxy.wait_for("dbsec listening");
    assert!(line.contains(&format!("max_sessions={EXPLICIT_SESSIONS}")), "{line}");
    proxy.assert_still_serving();
    assert_eq!(proxy.stop(), "", "diagnostics must not reach stdout");
}

/// No argument in a directory that has a `dbsec.toml`: the implicit
/// discovery every deployment relies on.
#[test]
fn no_argument_picks_up_the_config_in_the_working_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("dbsec.toml"), config_toml(DISCOVERED_SESSIONS)).unwrap();

    let mut proxy = Running::start(&mut dbsec(dir.path()));
    let line = proxy.wait_for("dbsec listening");
    assert!(line.contains(&format!("max_sessions={DISCOVERED_SESSIONS}")), "{line}");
    proxy.assert_still_serving();
    assert_eq!(proxy.stop(), "", "diagnostics must not reach stdout");
}

/// No argument and no `dbsec.toml`: the proxy refuses to start rather than
/// falling back to built-in defaults, which configure no columns and no TLS
/// and would make it a transparent plaintext relay (TASK-0088). The refusal
/// has to name both the file it looked for and the opt-in, because the way
/// this case is reached — a moved `WorkingDirectory`, a config volume mounted
/// elsewhere — leaves no other clue.
#[test]
fn no_argument_and_no_config_file_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let output = dbsec(dir.path()).output().expect("the dbsec binary must be runnable");
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("dbsec.toml"), "the file it looked for: {stderr}");
    assert!(stderr.contains(PLAIN_RELAY_FLAG), "the opt-in: {stderr}");
    assert!(stderr.contains("startup failed"), "{stderr}");
    assert!(output.stdout.is_empty(), "stdout: {:?}", String::from_utf8_lossy(&output.stdout));
}

/// The opt-in itself: with it, a missing default file means built-in defaults
/// again, so startup gets all the way to binding the default listen address.
///
/// Observed by spawning and reading stderr rather than by racing for the port
/// first (TASK-0162). A fixed global port cannot be claimed by a suite that
/// runs concurrently with the e2e suites, with a second checkout, or with
/// another CI job — and an earlier version of this case took the address away
/// first so that the bind would fail, which made the *outcome* depend on who
/// else held the port: if the port was free again by the time the proxy
/// reached it, the proxy bound it and stayed up, and the `Command::output()`
/// waiting on it never returned.
///
/// Whichever way that race falls, the address the run reached is named on
/// stderr — by the `dbsec listening` line when the bind succeeds and by the
/// bind failure when it does not — and that address is the fact under test:
/// the run fell back to the default rather than erroring out on the missing
/// file. So the case waits for the address and then stops the process, which
/// terminates either way.
#[test]
fn the_plain_relay_opt_in_falls_back_to_the_default_listen_address() {
    let dir = tempfile::tempdir().unwrap();
    let mut proxy = Running::start(dbsec(dir.path()).arg(PLAIN_RELAY_FLAG));

    // The opt-in is not a quiet mode: running with no protection at all is
    // still announced, in the same words the no-columns config uses, and the
    // warning names how it got there.
    let warning = proxy.wait_for(NO_PROTECTION_WARNING);
    assert!(warning.contains(PLAIN_RELAY_FLAG), "the warning names how it got there: {warning}");
    proxy.wait_for(DEFAULT_LISTEN);
    assert_eq!(proxy.stop(), "", "diagnostics must not reach stdout");
}

/// The other opt-in, driven as a command line rather than as a parsed `Args`:
/// `--allow-core-dumps` is read before the hardening step it skips, so a run
/// that carries it has to get all the way to serving — and a flag no spawned
/// case ever passes is one a startup-order change can break silently
/// (TASK-0162).
#[test]
fn the_core_dump_opt_in_is_accepted_on_the_command_line_and_still_serves() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("dbsec.toml"), config_toml(DISCOVERED_SESSIONS)).unwrap();

    let mut proxy = Running::start(dbsec(dir.path()).arg(ALLOW_CORE_DUMPS_FLAG));
    let line = proxy.wait_for("dbsec listening");
    assert!(line.contains(&format!("max_sessions={DISCOVERED_SESSIONS}")), "{line}");
    proxy.assert_still_serving();
    assert_eq!(proxy.stop(), "", "diagnostics must not reach stdout");
}

/// A config file that exists and declares no `[[column]]` reaches exactly the
/// zero-protection state `--plain-relay` is an opt-in for, and by a likelier
/// route: a `[[column]]` block lost to a bad merge or an environment overlay.
/// It gets the same WARN rather than a `protected_columns=0` field buried in
/// the INFO listening line (TASK-0131).
#[test]
fn a_config_with_no_columns_warns_that_nothing_is_protected() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("dbsec.toml"), config_toml(DISCOVERED_SESSIONS)).unwrap();

    let mut proxy = Running::start(&mut dbsec(dir.path()));
    let warning = proxy.wait_for(NO_PROTECTION_WARNING);
    assert!(warning.contains("WARN"), "not a field on an INFO line: {warning}");
    assert!(warning.contains("dbsec.toml"), "the warning names the config it read: {warning}");
    // And it is a warning, not a refusal: a plain relay that was asked for is
    // still allowed to serve.
    proxy.wait_for("dbsec listening");
    proxy.assert_still_serving();
    assert_eq!(proxy.stop(), "", "diagnostics must not reach stdout");
}

/// `--help` is the first thing an operator tries, and it used to be reported
/// as a startup failure: an ERROR record and exit 1 (TASK-0130). It is now the
/// one thing this binary writes to stdout — the run never becomes a proxy, so
/// there is no pipe to keep clean, and `dbsec --help | grep` works.
#[test]
fn help_prints_usage_to_stdout_and_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    for flag in ["--help", "-h"] {
        let output =
            dbsec(dir.path()).arg(flag).output().expect("the dbsec binary must be runnable");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();

        assert_eq!(output.status.code(), Some(0), "{flag}: stderr: {stderr}");
        assert!(stdout.contains("usage: dbsec"), "{flag}: stdout: {stdout}");
        assert!(stdout.contains(PLAIN_RELAY_FLAG), "{flag}: stdout: {stdout}");
        // Nothing is logged: help is an answer, not a diagnostic, and the
        // empty working directory it ran in must not turn into a complaint
        // about the missing config it never looked for.
        assert!(stderr.is_empty(), "{flag}: stderr: {stderr}");
    }
}

/// The piped shape the help text's own comment advertises. A consumer that
/// closes the pipe early is ordinary — `| head`, a `less` the reader quits —
/// and it must not turn help into a panic on stderr and a non-zero exit.
///
/// Driven through a shell so the pipe is a real one with a real early-closing
/// reader. `head -1` is the reader, and a POSIX shell reports the *last*
/// stage's status for a pipeline — `head`'s, which is 0 whatever dbsec did. So
/// dbsec's own status is echoed to stderr instead of being read off the
/// pipeline (TASK-0172); `$?` is portable where `pipefail` is not, `sh` being
/// dash on some of the platforms this runs on.
#[test]
fn help_survives_a_reader_that_closes_the_pipe() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new("sh")
        .current_dir(dir.path())
        .arg("-c")
        .arg(format!(
            "{{ {} --help; echo \"dbsec exit $?\" >&2; }} | head -1",
            env!("CARGO_BIN_EXE_dbsec")
        ))
        .output()
        .expect("sh must be runnable");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("dbsec exit 0"),
        "help must succeed for the reader that hung up: {stderr}"
    );
    assert!(stdout.contains("usage: dbsec"), "the reader still got its line: {stdout}");
    assert!(
        !stderr.contains("panicked") && !stderr.contains("failed printing"),
        "a closed pipe must not panic: {stderr}"
    );
}

/// A mistyped option is refused with the usage line rather than treated as a
/// config path — on this command line the difference between `--plain-relay`
/// and a typo is the difference between an intended plaintext relay and an
/// unintended one.
#[test]
fn an_unknown_option_exits_non_zero_with_the_usage_line() {
    let dir = tempfile::tempdir().unwrap();
    let output =
        dbsec(dir.path()).arg("--plan-relay").output().expect("the dbsec binary must be runnable");
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("--plan-relay"), "{stderr}");
    assert!(stderr.contains("usage: dbsec"), "{stderr}");
    assert!(output.stdout.is_empty(), "stdout: {:?}", String::from_utf8_lossy(&output.stdout));
}

/// A config path the operator got wrong: non-zero exit, and a message that
/// names the file so the typo is findable.
#[test]
fn a_missing_config_path_exits_non_zero_and_names_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join("absent.toml");

    let output =
        dbsec(dir.path()).arg(&absent).output().expect("the dbsec binary must be runnable");
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains(&absent.display().to_string()), "{stderr}");
    assert!(stderr.contains("startup failed"), "{stderr}");
    // The stream choice, pinned: diagnostics are stderr's, so `dbsec
    // 2>/dev/null` silences them and a pipe on stdout stays clean.
    assert!(output.stdout.is_empty(), "stdout: {:?}", String::from_utf8_lossy(&output.stdout));
}

/// Malformed TOML has to reach the operator legibly rather than as a bare
/// parse error with no file in it.
#[test]
fn a_malformed_config_exits_non_zero_and_names_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let broken = dir.path().join("broken.toml");
    std::fs::write(&broken, "listen = \nupstream =\n").unwrap();

    let output =
        dbsec(dir.path()).arg(&broken).output().expect("the dbsec binary must be runnable");
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains(&broken.display().to_string()), "{stderr}");
    assert!(output.stdout.is_empty(), "stdout: {:?}", String::from_utf8_lossy(&output.stdout));
}

/// A config that parses but violates an invariant fails the same way: the
/// operator sees why, and the exit code is the one a supervisor reads.
#[test]
fn an_invalid_config_exits_non_zero_with_the_reason() {
    let dir = tempfile::tempdir().unwrap();
    let invalid = dir.path().join("invalid.toml");
    std::fs::write(&invalid, "max_sessions = 0\n").unwrap();

    let output =
        dbsec(dir.path()).arg(&invalid).output().expect("the dbsec binary must be runnable");
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("max_sessions must be greater than 0"), "{stderr}");
    assert!(output.stdout.is_empty(), "stdout: {:?}", String::from_utf8_lossy(&output.stdout));
}
