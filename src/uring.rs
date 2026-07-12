//! `io_uring` event loop.
//!
//! The ring starts disabled, registers an operation allowlist
//! (`io_uring` submissions bypass seccomp, so the kernel-side
//! restriction is the only enforcement point), the tap fd and the
//! buffer pool, and only then is enabled.
//!
//! Currently reads frames from the tap and discards anything it does
//! not handle; protocol handlers (UDP/DNS/ICMP/TCP) hook in here as
//! they land.

use std::io;
use std::os::fd::AsRawFd;

use io_uring::{IoUring, opcode, register::Restriction, types};

use crate::{Config, buf, tap};

/// Registered-file index of the tap fd.
const TAP: types::Fixed = types::Fixed(0);

/// Operations the datapath needs; everything else is rejected by the
/// kernel. Restrictions can only be registered while the ring is
/// disabled, so ops for handlers that are not implemented yet are
/// already listed.
const ALLOWED_OPS: &[u8] = &[
    opcode::ReadFixed::CODE,
    opcode::WriteFixed::CODE,
    opcode::Recv::CODE,
    opcode::RecvMulti::CODE,
    opcode::Send::CODE,
    opcode::SendZc::CODE,
    opcode::Connect::CODE,
    opcode::PollAdd::CODE,
    opcode::Timeout::CODE,
    opcode::AsyncCancel::CODE,
    opcode::Close::CODE,
];

pub struct EventLoop {
    ring: IoUring,
    pool: buf::Pool,
    /// Keeps the registered tap fd alive; offload info is consumed by
    /// the protocol handlers once they land.
    _tap: tap::Tap,
}

impl EventLoop {
    /// # Errors
    ///
    /// Fails when the ring cannot be created or registration fails
    /// (needs kernel >= 5.10 for ring restrictions).
    pub fn new(cfg: &Config, tap: tap::Tap) -> io::Result<Self> {
        let ring = IoUring::builder().setup_r_disabled().build(256)?;
        let mut pool = buf::Pool::new(cfg.buffers);

        ring.submitter().register_files(&[tap.fd().as_raw_fd()])?;
        let region = pool.region();
        let iov = libc::iovec {
            iov_base: region.as_mut_ptr().cast(),
            iov_len: region.len(),
        };
        // SAFETY: the pool outlives the ring; both live in EventLoop and
        // the ring is dropped first (field order).
        unsafe { ring.submitter().register_buffers(&[iov])? };

        let mut restrictions: Vec<Restriction> = ALLOWED_OPS
            .iter()
            .map(|&op| Restriction::sqe_op(op))
            .collect();
        ring.submitter().register_restrictions(&mut restrictions)?;
        ring.submitter().register_enable_rings()?;

        Ok(Self {
            ring,
            pool,
            _tap: tap,
        })
    }

    /// Run until the tap fd reports EOF or an unrecoverable error.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from the ring or the tap fd.
    pub fn run(mut self) -> io::Result<()> {
        let Some(buf_id) = self.pool.alloc() else {
            return Err(io::Error::other("buffer pool configured with zero buffers"));
        };
        loop {
            self.submit_tap_read(buf_id)?;
            self.ring.submit_and_wait(1)?;
            let Some(cqe) = self.ring.completion().next() else {
                continue;
            };
            match cqe.result() {
                0 => return Ok(()), // tap torn down
                n if n < 0 => return Err(io::Error::from_raw_os_error(-n)),
                // Frame handling lands with the protocol modules; for
                // now every frame is dropped.
                _ => {}
            }
        }
    }

    fn submit_tap_read(&mut self, buf_id: buf::BufId) -> io::Result<()> {
        let b = self.pool.get_mut(buf_id);
        #[expect(clippy::cast_possible_truncation, reason = "buffer size fits u32")]
        let read = opcode::ReadFixed::new(TAP, b.as_mut_ptr(), b.len() as u32, 0).build();
        // SAFETY: the buffer lives in self.pool for the duration of the
        // operation; we wait for the completion before reusing it.
        unsafe {
            self.ring
                .submission()
                .push(&read)
                .map_err(|e| io::Error::other(format!("submission queue full: {e}")))?;
        }
        Ok(())
    }
}
