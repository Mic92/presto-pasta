//! The stop fd must end `run()` and double as a liveness signal.

use std::fs::File;
use std::io::{PipeWriter, Read};
use std::os::fd::OwnedFd;
use std::time::Duration;

/// Fake a tap fd with a pipe
fn fake_tap() -> (presto_pasta::Presto, PipeWriter) {
    let (tap, peer) = std::io::pipe().expect("pipe");
    let presto = presto_pasta::Presto::new(presto_pasta::Config::default(), OwnedFd::from(tap));
    (presto, peer)
}

#[test]
fn run_exits_when_the_stop_peer_closes() {
    let (mut presto, _tap_peer) = fake_tap();
    let (stop_r, stop_w) = std::io::pipe().expect("pipe");
    presto.stop_on(OwnedFd::from(stop_r));
    let datapath = std::thread::spawn(move || presto.run());

    std::thread::sleep(Duration::from_millis(50));
    assert!(
        !datapath.is_finished(),
        "run() exited before the stop fd fired"
    );
    drop(stop_w);

    datapath
        .join()
        .expect("join")
        .expect("run() should return Ok");
}

#[test]
fn stop_peer_hangs_up_when_presto_drops() {
    let (mut presto, _tap_peer) = fake_tap();
    let (stop_r, stop_w) = std::io::pipe().expect("pipe");
    presto.stop_on(OwnedFd::from(stop_w));
    drop(presto);

    let mut buf = [0u8; 1];
    let n = File::from(OwnedFd::from(stop_r))
        .read(&mut buf)
        .expect("read stop peer");
    assert_eq!(n, 0, "expected EOF after presto-pasta dropped");
}
