//! `run()` must return once the shutdown handle is dropped.

use std::os::fd::OwnedFd;
use std::time::Duration;

#[test]
fn run_exits_when_shutdown_handle_drops() {
    // Any fd works as a stand-in tap. The peer stays open so the tap
    // read never reports EOF and only the shutdown poll can end run().
    let (fake_tap, peer) = std::io::pipe().expect("pipe");
    let mut presto =
        presto_pasta::Presto::new(presto_pasta::Config::default(), OwnedFd::from(fake_tap));
    let handle = presto.shutdown_handle().expect("shutdown handle");
    let datapath = std::thread::spawn(move || presto.run());

    std::thread::sleep(Duration::from_millis(50));
    assert!(!datapath.is_finished(), "run() exited before shutdown");
    handle.shutdown();

    datapath
        .join()
        .expect("join")
        .expect("run() should return Ok");
    drop(peer);
}
