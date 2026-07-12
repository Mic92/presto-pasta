//! The liveness fd must report EOF once the datapath is gone.

use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;

#[test]
fn liveness_fd_hangs_up_when_presto_drops() {
    // Any fd works as a stand-in tap; offload probing just fails.
    let (fake_tap, _peer) = std::io::pipe().expect("pipe");
    let mut presto =
        presto_pasta::Presto::new(presto_pasta::Config::default(), OwnedFd::from(fake_tap));
    let liveness = presto.liveness_fd().expect("liveness fd");
    drop(presto);

    let mut buf = [0u8; 1];
    let n = File::from(liveness).read(&mut buf).expect("read liveness");
    assert_eq!(n, 0, "expected EOF after presto-pasta dropped");
}
