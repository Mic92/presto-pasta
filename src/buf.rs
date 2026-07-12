//! Fixed pool of frame buffers.
//!
//! Each buffer holds payload plus headroom where L2/L3/L4 headers are
//! built in front of the payload, so payload never moves.

/// Headroom in front of the payload for vnet + ethernet + IP + TCP headers.
pub const HEADROOM: usize = 256;
/// Payload space per buffer. It bounds a tap frame (up to a 64 KiB
/// super-frame) and, per TCP flow, the data in flight towards the
/// guest: retransmits are resent from this buffer, so unacked data
/// must fit. Well above twice the largest possible MSS, otherwise the
/// guest's delayed ack (which waits for two full segments) would idle
/// the flow at large MTUs.
pub const FRAME: usize = 262_144;
/// Total size of one buffer.
pub const BUF_SIZE: usize = HEADROOM + FRAME;

/// Index of a buffer in the pool.
pub type BufId = u32;

/// Fixed-size pool of equally sized buffers.
pub struct Pool {
    mem: Box<[u8]>,
    free: Vec<BufId>,
}

impl Pool {
    /// # Panics
    ///
    /// Panics if `count` does not fit in a `u32`.
    #[must_use]
    pub fn new(count: usize) -> Self {
        Self {
            mem: vec![0u8; count * BUF_SIZE].into_boxed_slice(),
            free: (0..u32::try_from(count).expect("pool size fits u32")).collect(),
        }
    }

    pub fn alloc(&mut self) -> Option<BufId> {
        self.free.pop()
    }

    pub fn free(&mut self, id: BufId) {
        debug_assert!((id as usize) < self.mem.len() / BUF_SIZE);
        self.free.push(id);
    }

    #[must_use]
    pub fn get_mut(&mut self, id: BufId) -> &mut [u8] {
        let start = id as usize * BUF_SIZE;
        &mut self.mem[start..start + BUF_SIZE]
    }

    #[must_use]
    pub fn get(&self, id: BufId) -> &[u8] {
        let start = id as usize * BUF_SIZE;
        &self.mem[start..start + BUF_SIZE]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_free_roundtrip() {
        let mut p = Pool::new(2);
        let a = p.alloc().unwrap();
        let b = p.alloc().unwrap();
        assert_ne!(a, b);
        assert!(p.alloc().is_none());
        p.free(a);
        assert_eq!(p.alloc(), Some(a));
    }
}
