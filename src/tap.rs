//! Tap device fd handling: offload probing and vnet header framing.
//!
//! The caller opens the device inside the sandbox netns with
//! `IFF_TAP | IFF_NO_PI | IFF_VNET_HDR` and hands presto the fd.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

// TUN_F_* offload flags (linux/if_tun.h); not exposed by libc.
pub const TUN_F_CSUM: libc::c_int = 0x01;
pub const TUN_F_TSO4: libc::c_int = 0x02;
pub const TUN_F_TSO6: libc::c_int = 0x04;
pub const TUN_F_USO4: libc::c_int = 0x20;
pub const TUN_F_USO6: libc::c_int = 0x40;

/// Size of `struct virtio_net_hdr` prepended to every frame on a
/// `IFF_VNET_HDR` tap.
pub const VNET_HDR_LEN: usize = 10;

// virtio_net_hdr flag/gso constants (linux/virtio_net.h).
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
pub const VIRTIO_NET_HDR_GSO_UDP_L4: u8 = 5;

/// Parsed `struct virtio_net_hdr`.
#[derive(Debug, Clone, Copy, Default)]
pub struct VnetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

impl VnetHdr {
    #[must_use]
    pub fn parse(b: &[u8; VNET_HDR_LEN]) -> Self {
        Self {
            flags: b[0],
            gso_type: b[1],
            hdr_len: u16::from_le_bytes([b[2], b[3]]),
            gso_size: u16::from_le_bytes([b[4], b[5]]),
            csum_start: u16::from_le_bytes([b[6], b[7]]),
            csum_offset: u16::from_le_bytes([b[8], b[9]]),
        }
    }

    #[must_use]
    pub fn to_bytes(self) -> [u8; VNET_HDR_LEN] {
        let mut b = [0u8; VNET_HDR_LEN];
        b[0] = self.flags;
        b[1] = self.gso_type;
        b[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        b[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        b[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        b[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
        b
    }
}

/// Offloads negotiated with the tap device, as `TUN_F_*` flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct Offloads(libc::c_int);

impl Offloads {
    #[must_use]
    pub fn csum(self) -> bool {
        self.0 & TUN_F_CSUM != 0
    }

    #[must_use]
    pub fn tso(self) -> bool {
        self.0 & (TUN_F_TSO4 | TUN_F_TSO6) != 0
    }

    #[must_use]
    pub fn uso(self) -> bool {
        self.0 & (TUN_F_USO4 | TUN_F_USO6) != 0
    }
}

/// A tap fd with negotiated offloads.
pub struct Tap {
    fd: OwnedFd,
    offloads: Offloads,
}

nix::ioctl_write_int_bad!(
    tun_set_offload,
    nix::request_code_write!(b'T', 208, std::mem::size_of::<libc::c_uint>())
);

impl Tap {
    /// Take ownership of the fd and negotiate offloads. Falls back to
    /// software checksums when the kernel rejects an offload set (USO
    /// needs kernel >= 6.2, CSUM/TSO are ancient).
    #[must_use]
    pub fn new(fd: OwnedFd) -> Self {
        let attempts = [
            TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_USO4 | TUN_F_USO6,
            TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6,
            0,
        ];
        let mut offloads = Offloads::default();
        for flags in attempts {
            // SAFETY: fd is a valid tun fd; TUNSETOFFLOAD takes the flag
            // word as the ioctl argument.
            if unsafe { tun_set_offload(fd.as_raw_fd(), flags) }.is_ok() {
                offloads = Offloads(flags);
                break;
            }
        }
        Self { fd, offloads }
    }

    #[must_use]
    pub fn offloads(&self) -> Offloads {
        self.offloads
    }

    #[must_use]
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
