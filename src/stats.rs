//! Datapath counters for benchmarking. Compiled in with the `stats`
//! feature; otherwise every method is an empty inline stub.

#[cfg(feature = "stats")]
mod imp {
    /// Event-loop counters, printed to stderr when the loop is dropped.
    #[derive(Default)]
    pub struct Stats {
        wakeups: u64,
        cqes: u64,
        tap_frames_in: u64,
        tap_bytes_in: u64,
        tap_frames_out: u64,
        tap_bytes_out: u64,
        tcp_ctrl_frames: u64,
        acks_deferred: u64,
        sock_sends: u64,
        sock_send_bytes: u64,
        sock_send_shortfall: u64,
        peeks: u64,
        peeks_empty: u64,
    }

    impl Stats {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn wakeup(&mut self, cqes: usize) {
            self.wakeups += 1;
            self.cqes += cqes as u64;
        }

        pub fn tap_in(&mut self, len: usize) {
            self.tap_frames_in += 1;
            self.tap_bytes_in += len as u64;
        }

        pub fn tap_out(&mut self, len: usize) {
            self.tap_frames_out += 1;
            self.tap_bytes_out += len as u64;
        }

        pub fn tcp_ctrl(&mut self) {
            self.tcp_ctrl_frames += 1;
        }

        pub fn ack_deferred(&mut self) {
            self.acks_deferred += 1;
        }

        pub fn sock_send(&mut self, accepted: usize, wanted: usize) {
            self.sock_sends += 1;
            self.sock_send_bytes += accepted as u64;
            self.sock_send_shortfall += (wanted - accepted) as u64;
        }

        pub fn peek(&mut self, empty: bool) {
            self.peeks += 1;
            self.peeks_empty += u64::from(empty);
        }
    }

    impl Stats {
        /// Print the counters accumulated so far to stderr.
        #[expect(clippy::cast_precision_loss, reason = "approximate averages")]
        pub fn dump(&self) {
            let per = |n: u64| n as f64 / self.wakeups.max(1) as f64;
            eprintln!(
                "presto stats: wakeups {} cqes/wakeup {:.2}",
                self.wakeups,
                per(self.cqes)
            );
            eprintln!(
                "presto stats: tap in {} frames {} bytes ({:.2} frames/wakeup), out {} frames {} bytes",
                self.tap_frames_in,
                self.tap_bytes_in,
                per(self.tap_frames_in),
                self.tap_frames_out,
                self.tap_bytes_out
            );
            eprintln!(
                "presto stats: tcp ctrl frames {} acks deferred {}",
                self.tcp_ctrl_frames, self.acks_deferred
            );
            eprintln!(
                "presto stats: sock sends {} bytes {} shortfall {}",
                self.sock_sends, self.sock_send_bytes, self.sock_send_shortfall
            );
            eprintln!(
                "presto stats: peeks {} empty {}",
                self.peeks, self.peeks_empty
            );
        }
    }
}

#[cfg(not(feature = "stats"))]
mod imp {
    /// Stub whose methods compile to nothing without the `stats` feature.
    pub struct Stats;

    #[expect(clippy::unused_self, reason = "mirrors the stats build")]
    impl Stats {
        pub fn new() -> Self {
            Self
        }

        #[inline]
        pub fn dump(&self) {}

        #[inline]
        pub fn wakeup(&mut self, _cqes: usize) {}
        #[inline]
        pub fn tap_in(&mut self, _len: usize) {}
        #[inline]
        pub fn tap_out(&mut self, _len: usize) {}
        #[inline]
        pub fn tcp_ctrl(&mut self) {}
        #[inline]
        pub fn ack_deferred(&mut self) {}
        #[inline]
        pub fn sock_send(&mut self, _accepted: usize, _wanted: usize) {}
        #[inline]
        pub fn peek(&mut self, _empty: bool) {}
    }
}

pub use imp::Stats;
