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
        sock_recvs: u64,
        sock_recvs_empty: u64,
        guest_window_last: u64,
        guest_window_max: u64,
        window_full: u64,
        budget_short: u64,
        dup_ack_retransmits: u64,
        rto_retransmits: u64,
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

        pub fn sock_recv(&mut self, empty: bool) {
            self.sock_recvs += 1;
            self.sock_recvs_empty += u64::from(empty);
        }

        pub fn guest_window(&mut self, window: u32) {
            self.guest_window_last = u64::from(window);
            self.guest_window_max = self.guest_window_max.max(u64::from(window));
        }

        pub fn window_full(&mut self) {
            self.window_full += 1;
        }

        pub fn budget_short(&mut self) {
            self.budget_short += 1;
        }

        pub fn dup_ack_retransmit(&mut self) {
            self.dup_ack_retransmits += 1;
        }

        pub fn rto_retransmit(&mut self) {
            self.rto_retransmits += 1;
        }
    }

    impl Stats {
        /// Print the counters accumulated so far to stderr.
        #[expect(clippy::cast_precision_loss, reason = "approximate averages")]
        pub fn dump(&self) {
            let per = |n: u64| n as f64 / self.wakeups.max(1) as f64;
            eprintln!(
                "presto-pasta stats: wakeups {} cqes/wakeup {:.2}",
                self.wakeups,
                per(self.cqes)
            );
            eprintln!(
                "presto-pasta stats: tap in {} frames {} bytes ({:.2} frames/wakeup), out {} frames {} bytes",
                self.tap_frames_in,
                self.tap_bytes_in,
                per(self.tap_frames_in),
                self.tap_frames_out,
                self.tap_bytes_out
            );
            eprintln!(
                "presto-pasta stats: tcp ctrl frames {} acks deferred {}",
                self.tcp_ctrl_frames, self.acks_deferred
            );
            eprintln!(
                "presto-pasta stats: sock sends {} bytes {} shortfall {}",
                self.sock_sends, self.sock_send_bytes, self.sock_send_shortfall
            );
            eprintln!(
                "presto-pasta stats: sock recvs {} empty {}",
                self.sock_recvs, self.sock_recvs_empty
            );
            eprintln!(
                "presto-pasta stats: guest window last {} max {}, window full {} budget short {} dup-ack retransmits {} rto retransmits {}",
                self.guest_window_last,
                self.guest_window_max,
                self.window_full,
                self.budget_short,
                self.dup_ack_retransmits,
                self.rto_retransmits
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
        pub fn sock_recv(&mut self, _empty: bool) {}
        #[inline]
        pub fn guest_window(&mut self, _window: u32) {}
        #[inline]
        pub fn window_full(&mut self) {}
        #[inline]
        pub fn budget_short(&mut self) {}
        #[inline]
        pub fn dup_ack_retransmit(&mut self) {}
        #[inline]
        pub fn rto_retransmit(&mut self) {}
    }
}

pub use imp::Stats;
