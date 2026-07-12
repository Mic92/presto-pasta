//! `io_uring` event loop.
//!
//! Currently reads frames from the tap and discards anything it does
//! not handle; protocol handlers (UDP/DNS/ICMP/TCP) hook in here as
//! they land.

use std::io;
use std::os::fd::AsRawFd;

use io_uring::{IoUring, opcode, types};

use crate::{Config, buf, tap};

pub struct EventLoop {
    ring: IoUring,
    pool: buf::Pool,
    tap: tap::Tap,
}

impl EventLoop {
    /// # Errors
    ///
    /// Fails when the ring cannot be created.
    pub fn new(cfg: &Config, tap: tap::Tap) -> io::Result<Self> {
        Ok(Self {
            ring: IoUring::new(64)?,
            pool: buf::Pool::new(cfg.buffers),
            tap,
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
                _n => {
                    // Frame handling lands with the protocol modules;
                    // for now every frame is dropped.
                }
            }
        }
    }

    fn submit_tap_read(&mut self, buf_id: buf::BufId) -> io::Result<()> {
        let b = self.pool.get_mut(buf_id);
        #[expect(clippy::cast_possible_truncation, reason = "buffer size fits u32")]
        let read = opcode::Read::new(
            types::Fd(self.tap.fd().as_raw_fd()),
            b.as_mut_ptr(),
            b.len() as u32,
        )
        .build();
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
