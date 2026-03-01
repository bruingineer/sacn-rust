// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Standard UDP backend for sACN using [`socket2`].
//!
//! [`StdNet`] is the default [`SacnNet`] implementation. It owns:
//! - One multicast send socket per non-loopback IPv4 network interface,
//!   each configured with `IP_MULTICAST_IF` pointing at that interface.
//! - One shared unicast send socket.
//!
//! This matches the ETCLabs sACN socket model: socket count scales with the
//! number of interfaces, not the number of universes.
//!
//! If no non-loopback interfaces are found (e.g. in a CI environment), a
//! single unbound fallback socket is used for multicast sends so the library
//! remains functional on minimal hosts.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use if_addrs::get_if_addrs;
use socket2::{Domain, Socket, Type};

use crate::error::errors::{Result, SacnError};
use crate::net::{NetIntId, SacnNet};

// ---------------------------------------------------------------------------
// StdNet
// ---------------------------------------------------------------------------

/// Standard UDP network backend for sACN.
///
/// Created by [`StdNet::new`] and passed to `SacnSource::with_net`. Users
/// relying on the default type parameter (`SacnSource<StdNet>`) do not need
/// to construct this directly — `SacnSource::with_ip` and friends call
/// [`StdNet::new`] internally.
///
/// # Socket layout
///
/// | Socket | Count | Purpose |
/// |---|---|---|
/// | `mcast_sockets[i]` | 1 per netint | Multicast sends with `IP_MULTICAST_IF = netint[i].addr` |
/// | `ucast_socket` | 1 shared | Unicast sends |
///
/// # Fallback behaviour
///
/// If [`get_if_addrs`] returns no non-loopback IPv4 interfaces, `StdNet`
/// creates a single unbound socket used for all multicast sends. This keeps
/// the library working on minimal hosts (CI, loopback-only containers) at the
/// cost of losing explicit interface selection.
#[derive(Debug)]
pub struct StdNet {
    /// Non-loopback IPv4 interfaces available at construction time.
    sys_netints: Vec<NetIntId>,

    /// One multicast send socket per entry in `sys_netints`.
    /// If `sys_netints` is empty this contains exactly one fallback socket.
    mcast_sockets: Vec<Socket>,

    /// Shared unicast send socket.
    ucast_socket: Socket,

    default_netint_idx: usize,
}

impl StdNet {
    /// Constructs a new `StdNet` bound to the given local address.
    ///
    /// `addr` is used to bind the unicast socket. The port is typically
    /// `ACN_SDT_MULTICAST_PORT + 1` to avoid conflicts with receiver sockets
    /// on the same host.
    ///
    /// # Errors
    /// `Io`: Returned if any socket cannot be created, configured, or bound.
    ///
    /// `UnsupportedIpVersion`: Returned if `addr` is not IPv4.
    pub fn new(addr: SocketAddr) -> Result<Self> {
        if !addr.is_ipv4() {
            return Err(SacnError::UnsupportedIpVersion(
                "StdNet currently only supports IPv4".to_string(),
            ));
        }

        // Enumerate non-loopback IPv4 interfaces.
        let sys_netints = enumerate_ipv4_netints()?;

        let default_netint_idx = match addr.ip() {
            IpAddr::V4(v4) if !v4.is_unspecified() => {
                sys_netints.iter().position(|n| n.addr == v4).unwrap_or(0)
            }
            _ => 0,
        };

        // Build one multicast send socket per interface.
        let mcast_sockets = if sys_netints.is_empty() {
            // Fallback: single unbound socket. Multicast egress interface will
            // be chosen by the OS routing table — correct for single-NIC hosts.
            vec![make_mcast_socket(None)?]
        } else {
            sys_netints
                .iter()
                .map(|n| make_mcast_socket(Some(n.addr)))
                .collect::<Result<Vec<_>>>()?
        };

        // Shared unicast socket bound to the caller-supplied address.
        let ucast_socket = make_ucast_socket(addr)?;

        Ok(StdNet {
            sys_netints,
            mcast_sockets,
            ucast_socket,
            default_netint_idx,
        })
    }
}

// ---------------------------------------------------------------------------
// SacnNet impl
// ---------------------------------------------------------------------------

impl SacnNet for StdNet {
    fn enumerate_netints(&self) -> &[NetIntId] {
        &self.sys_netints
    }

    fn default_netint_idx(&self) -> usize {
        self.default_netint_idx
    }

    fn send_mcast(&self, idx: usize, dst: SocketAddr, bytes: &[u8]) -> Result<()> {
        // When sys_netints is empty we have exactly one fallback socket at index 0.
        // Callers should pass idx = 0 in that case (SourceUniverseState default).
        let socket = if self.sys_netints.is_empty() {
            &self.mcast_sockets[0]
        } else {
            &self.mcast_sockets[idx]
        };

        socket
            .send_to(bytes, &dst.into())
            .map_err(|e| std::io::Error::new(e.kind(), "StdNet: multicast send_to failed"))?;

        Ok(())
    }

    fn send_ucast(&self, dst: SocketAddr, bytes: &[u8]) -> Result<()> {
        self.ucast_socket
            .send_to(bytes, &dst.into())
            .map_err(|e| std::io::Error::new(e.kind(), "StdNet: unicast send_to failed"))?;

        Ok(())
    }

    // execute_batch uses the default loop implementation from the trait.
    // fn execute_batch(&self, sends: &[super::PendingSend]) -> Result<()> {}

    fn set_multicast_ttl(&self, ttl: u32) -> Result<()> {
        for s in &self.mcast_sockets {
            s.set_multicast_ttl_v4(ttl)?;
        }
        Ok(())
    }

    fn multicast_ttl(&self) -> Result<u32> {
        // All sockets are configured identically — read from the first.
        Ok(self.mcast_sockets[0].multicast_ttl_v4()?)
    }

    fn set_multicast_loop_v4(&self, val: bool) -> Result<()> {
        for s in &self.mcast_sockets {
            s.set_multicast_loop_v4(val)?;
        }
        Ok(())
    }

    fn multicast_loop_v4(&self) -> Result<bool> {
        // All sockets are configured identically — read from the first.
        Ok(self.mcast_sockets[0].multicast_loop_v4()?)
    }

    fn ttl(&self) -> Result<u32> {
        Ok(self.ucast_socket.ttl_v4()?)
    }

    fn set_ttl(&self, ttl: u32) -> Result<()> {
        Ok(self.ucast_socket.set_ttl_v4(ttl)?)
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Enumerates non-loopback IPv4 network interfaces on the current host.
///
/// Returns an empty `Vec` if no such interfaces exist rather than an error,
/// so the fallback socket path in [`StdNet::new`] can handle minimal hosts.
fn enumerate_ipv4_netints() -> Result<Vec<NetIntId>> {
    let ifaces = get_if_addrs().map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("Failed to enumerate network interfaces: {e}"),
        )
    })?;

    let netints = ifaces
        .into_iter()
        .filter(|iface| {
            // Exclude loopback interfaces — matches ETCLabs behaviour.
            // Loopback can be added explicitly by the user if needed.
            !iface.is_loopback()
        })
        .filter_map(|iface| {
            // IPv4 only for now; IPv6 support added in a later phase.
            match iface.addr.ip() {
                IpAddr::V4(addr) => Some(NetIntId { addr }),
                IpAddr::V6(_) => None,
            }
        })
        .collect();

    Ok(netints)
}

/// Creates and configures a multicast send socket.
///
/// If `interface_addr` is `Some`, sets `IP_MULTICAST_IF` so multicast packets
/// egress on the specified interface. If `None`, the OS routing table picks
/// the interface (fallback behaviour for single-NIC or minimal hosts).
///
/// # Socket configuration
/// - `SO_REUSEADDR` (+ `SO_REUSEPORT` on Linux): allows multiple processes to
///   use the sACN port simultaneously.
/// - `IP_MULTICAST_IF`: pins multicast egress to the given interface.
/// - `IP_MULTICAST_TTL`: left at OS default (1); caller may override via
///   [`StdNet::set_multicast_ttl`].
fn make_mcast_socket(interface_addr: Option<Ipv4Addr>) -> Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;

    // Allow multiple processes / sockets to share the sACN port.
    #[cfg(target_os = "linux")]
    socket.set_reuse_port(true)?;
    socket.set_reuse_address(true)?;

    // Pin multicast egress to the specified interface if provided.
    if let Some(addr) = interface_addr {
        socket.set_multicast_if_v4(&addr)?;
    }

    Ok(socket)
}

/// Creates and configures a unicast send socket bound to `addr`.
///
/// # Socket configuration
/// - `SO_REUSEADDR` (+ `SO_REUSEPORT` on Linux): consistent with multicast sockets.
/// - Bound to `addr` so the OS assigns a fixed local port for unicast sends.
fn make_ucast_socket(addr: SocketAddr) -> Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;

    #[cfg(target_os = "linux")]
    socket.set_reuse_port(true)?;
    socket.set_reuse_address(true)?;

    socket.bind(&addr.into())?;

    Ok(socket)
}
