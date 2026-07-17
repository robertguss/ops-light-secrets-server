use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use ops_light_secrets_server::config::{SecretSource, SystemSecretInput};
use test_support::{ActualOutcome, ArtifactKind, ExpectedOutcome, Harness, SafeSummary};

const SECRET: &[u8] = b"pty-canary-OLSS-7c6d91";

#[test]
fn pty_child_helper() {
    let Ok(mode) = std::env::var("OLSS_PTY_CHILD_MODE") else {
        return;
    };
    let source: SecretSource = "tty".parse().unwrap();
    let mut input = SystemSecretInput::from_credentials_directory(None);
    match mode.as_str() {
        "success" => {
            let value = source.read("secrets.age_identity", &mut input).unwrap();
            let expected = std::env::var("OLSS_PTY_EXPECTED_DIGEST").unwrap();
            assert_eq!(blake3::hash(value.expose()).to_hex().as_str(), expected);
            println!("PTY_RESULT_OK");
        }
        "refuse" => {
            assert!(source.read("secrets.age_identity", &mut input).is_err());
            println!("PTY_RESULT_REFUSED");
        }
        _ => panic!("unknown child mode"),
    }
}

enum InputAction {
    Secret,
    Empty,
    Eof,
    Break,
}

struct PtyRun {
    status: ExitStatus,
    output: Vec<u8>,
    echo_during_prompt: bool,
    echo_after_exit: bool,
}

fn run_pty(mode: &str, action: InputAction) -> PtyRun {
    let mut master_fd = -1;
    let mut slave_fd = -1;
    // SAFETY: openpty initializes both descriptors on success; both are immediately
    // wrapped in File values that own and close them exactly once.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    // SAFETY: descriptors were freshly returned by openpty and are uniquely owned.
    let mut master = Some(unsafe { File::from_raw_fd(master_fd) });
    // SAFETY: descriptor was freshly returned by openpty and is uniquely owned.
    let mut slave = Some(unsafe { File::from_raw_fd(slave_fd) });
    let stdin = slave.as_ref().unwrap().try_clone().unwrap();
    let stdout = slave.as_ref().unwrap().try_clone().unwrap();
    let stderr = slave.as_ref().unwrap().try_clone().unwrap();

    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "pty_child_helper", "--nocapture"])
        .env("OLSS_PTY_CHILD_MODE", mode)
        .env(
            "OLSS_PTY_EXPECTED_DIGEST",
            blake3::hash(SECRET).to_hex().as_str(),
        )
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    // SAFETY: this hook calls only async-signal-safe libc functions before exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1
                || libc::ioctl(0, libc::TIOCSCTTY, 0) == -1
                || libc::tcsetpgrp(0, libc::getpgrp()) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();

    let flags = unsafe { libc::fcntl(master.as_ref().unwrap().as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe {
            libc::fcntl(
                master.as_ref().unwrap().as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK,
            )
        },
        0
    );

    let mut output = Vec::new();
    let prompt_deadline = Instant::now() + Duration::from_secs(5);
    while !output
        .windows(b"Secret: ".len())
        .any(|part| part == b"Secret: ")
    {
        read_available(master.as_mut().unwrap(), &mut output);
        assert!(Instant::now() < prompt_deadline, "PTY prompt timeout");
        std::thread::sleep(Duration::from_millis(5));
    }
    let echo_during_prompt = echo_enabled(slave.as_ref().unwrap());

    match action {
        InputAction::Secret => master
            .as_mut()
            .unwrap()
            .write_all(&[SECRET, b"\n"].concat())
            .unwrap(),
        InputAction::Empty => master.as_mut().unwrap().write_all(b"\n").unwrap(),
        InputAction::Eof => master.as_mut().unwrap().write_all(&[4]).unwrap(),
        InputAction::Break => {
            drop(slave.take());
            drop(master.take());
            let pid = i32::try_from(child.id()).unwrap();
            // A real PTY hangup delivers SIGHUP to the foreground process group.
            // Inject it explicitly so this kernel-independent fault case is bounded.
            assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
        }
    }

    let exit_deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(file) = master.as_mut() {
            read_available(file, &mut output);
        }
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= exit_deadline {
            child.kill().unwrap();
            panic!("PTY child timeout");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    if let Some(file) = master.as_mut() {
        read_available(file, &mut output);
    }
    PtyRun {
        status,
        output,
        echo_during_prompt,
        echo_after_exit: slave.as_ref().is_some_and(echo_enabled),
    }
}

fn read_available(master: &mut File, output: &mut Vec<u8>) {
    let mut buffer = [0_u8; 4096];
    loop {
        match master.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => output.extend_from_slice(&buffer[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                break;
            }
            Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
            Err(error) => panic!("PTY read failed: {error}"),
        }
    }
}

fn echo_enabled(slave: &File) -> bool {
    // SAFETY: tcgetattr writes a termios value for the valid PTY slave descriptor.
    let mut terminal: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut terminal) },
        0
    );
    terminal.c_lflag & libc::ECHO != 0
}

#[test]
fn tty_is_hidden_refuses_empty_and_eof_restores_terminal_and_handles_breakage() {
    let harness = Harness::builder("startup-tty")
        .register_canary(SECRET)
        .build()
        .unwrap();
    let mut scenario = harness.scenario("tty-secret-source", 1).unwrap();

    let success = run_pty("success", InputAction::Secret);
    assert!(success.status.success());
    assert!(!success.echo_during_prompt);
    assert!(success.echo_after_exit);
    assert!(
        success
            .output
            .windows(13)
            .any(|part| part == b"PTY_RESULT_OK")
    );
    assert!(
        !success
            .output
            .windows(SECRET.len())
            .any(|part| part == SECRET)
    );
    scenario
        .capture(ArtifactKind::ClientStdout, &success.output)
        .unwrap();
    scenario
        .step(
            "hidden-success",
            SafeSummary::new(),
            ExpectedOutcome::Success,
            ActualOutcome::Success,
        )
        .unwrap();

    for action in [InputAction::Empty, InputAction::Eof] {
        let refused = run_pty("refuse", action);
        assert!(refused.status.success());
        assert!(!refused.echo_during_prompt);
        assert!(refused.echo_after_exit);
        assert!(
            refused
                .output
                .windows(18)
                .any(|part| part == b"PTY_RESULT_REFUSED")
        );
        scenario
            .capture(ArtifactKind::ClientStderr, &refused.output)
            .unwrap();
    }
    scenario
        .step(
            "cancel-and-eof",
            SafeSummary::new(),
            ExpectedOutcome::Success,
            ActualOutcome::Success,
        )
        .unwrap();

    let broken = run_pty("refuse", InputAction::Break);
    assert!(broken.status.success() || broken.status.signal().is_some());
    assert!(
        !broken
            .output
            .windows(SECRET.len())
            .any(|part| part == SECRET)
    );
    scenario
        .capture(ArtifactKind::ClientStderr, &broken.output)
        .unwrap();
    scenario
        .step(
            "broken-tty",
            SafeSummary::new(),
            ExpectedOutcome::Success,
            ActualOutcome::Success,
        )
        .unwrap();

    scenario.finish_success().unwrap();
}

#[test]
fn tty_source_refuses_when_process_has_no_controlling_terminal() {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "pty_child_helper", "--nocapture"])
        .env("OLSS_PTY_CHILD_MODE", "refuse")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: setsid is async-signal-safe and detaches the child from any TTY.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output().unwrap();
    assert!(output.status.success());
    assert!(
        output
            .stdout
            .windows(18)
            .any(|part| part == b"PTY_RESULT_REFUSED")
    );
    assert!(
        !output
            .stdout
            .windows(SECRET.len())
            .any(|part| part == SECRET)
    );
    assert!(
        !output
            .stderr
            .windows(SECRET.len())
            .any(|part| part == SECRET)
    );
}
