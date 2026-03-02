// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Network abstraction layer for sACN.
//!
//! This module defines the [`SacnNet`] trait and the associated types used to
//! decouple E1.31 protocol logic from OS networking primitives.
//!
//! The core protocol state machine (`SacnSourceCore`) produces [`PendingSend`]
//! values describing *what* to send and *where*. A [`SacnNet`] implementation
//! is responsible for *how* those sends are executed — using standard UDP
//! sockets, `sendmmsg`, an embedded stack, or a test double.
//!
//! # Provided implementations
//!
//! | Feature flag | Type | Notes |
//! |---|---|---|
//! | `std-net` (default) | [`std_net::StdNet`] | One `socket2` UDP socket per interface |
//! | `mmsg-net` (Linux only) | `mmsg_net::MmsgNet` | Batches sends with `sendmmsg` |
//!
//! # Implementing a custom backend
//!
//! Implement [`SacnNet`] on your own type and pass it to
//! `SacnSource::with_net(your_backend)`. The protocol core and runtime wrapper
//! will call [`SacnNet::execute_batch`] for every group of sends produced by a
//! single user-facing API call, so batching opportunities are preserved.

use std::net::{Ipv4Addr, SocketAddr};

use crate::error::errors::Result;

pub mod std_net;

#[cfg(all(target_os = "linux", feature = "mmsg-net"))]
pub mod mmsg_net;

// ---------------------------------------------------------------------------
// NetIntId
// ---------------------------------------------------------------------------

/// Identifies a single network interface available for sACN multicast sends.
///
/// Currently IPv4-only. IPv6 support will be added in a later phase.
///
/// The `addr` field is the local unicast address of the interface and is used
/// to set `IP_MULTICAST_IF` on the per-interface multicast send socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetIntId {
    /// The local IPv4 address of this network interface.
    pub addr: Ipv4Addr,
    pub os_idx: u32,
}

// ---------------------------------------------------------------------------
// SendDestination
// ---------------------------------------------------------------------------

/// Describes where a [`PendingSend`] should be delivered.
#[derive(Debug, Clone)]
pub enum SendDestination {
    /// Send to an IP multicast group via the socket bound to the interface at
    /// the given index within [`SacnNet::enumerate_netints`].
    Multicast {
        /// Index into the netint list returned by [`SacnNet::enumerate_netints`].
        netint_os_idx: u32,
        /// The multicast group address and port to send to.
        multicast_addr: SocketAddr,
    },
    /// Send directly to a unicast destination.
    Unicast {
        /// The destination address and port.
        addr: SocketAddr,
    },
}

// ---------------------------------------------------------------------------
// PendingSend
// ---------------------------------------------------------------------------

/// A fully-formed datagram ready to be handed to a [`SacnNet`] backend.
///
/// Produced by `SacnSourceCore` methods (`send`, `send_sync_packet`, `tick`,
/// etc.) and consumed by [`SacnNet::execute_batch`].
///
/// The bytes are already packed; the backend only needs to choose the right
/// socket and call the appropriate send syscall.
#[derive(Debug, Clone)]
pub struct PendingSend {
    /// Where this datagram should be delivered.
    pub destination: SendDestination,
    /// The fully packed E1.31 datagram bytes.
    pub bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// SacnNet trait
// ---------------------------------------------------------------------------

/// Pluggable network backend for sACN sending.
///
/// Implementations own the OS sockets (or equivalent resources) and are
/// responsible for interface enumeration, multicast configuration, and
/// datagram dispatch.
///
/// The protocol core (`SacnSourceCore`) has no knowledge of this trait — it
/// only produces [`PendingSend`] values. The runtime wrapper
/// (`SacnSourceInternal`) calls [`SacnNet::execute_batch`] to dispatch them.
///
/// # Required methods
///
/// Only [`enumerate_netints`], [`send_mcast`], [`send_ucast`], and the socket
/// option accessors are required. [`execute_batch`] has a correct default
/// implementation that calls the required methods in a loop; override it in
/// backends that can do better (e.g. `sendmmsg`).
///
/// # Thread safety
///
/// Implementations must be `Send` because the runtime wrapper moves the
/// backend into the update thread. `&self` send methods allow the backend to
/// be shared across method calls without requiring `&mut self` on the hot
/// path.
pub trait SacnSourceNet: Send {
    // -----------------------------------------------------------------------
    // Interface enumeration
    // -----------------------------------------------------------------------

    /// Returns the list of network interfaces available for multicast sending.
    ///
    /// The indices used in [`SendDestination::Multicast::netint_idx`] refer to
    /// positions within this slice. The slice must remain stable for the
    /// lifetime of the backend (i.e. do not re-enumerate dynamically between
    /// calls without also updating all universe netint index lists).
    fn enumerate_netints(&self) -> &[NetIntId];

    /// Returns the interface index that should be used as the default for
    /// newly registered universes.
    ///
    /// For [`StdNet`] this is derived from the local address passed at
    /// construction. For custom backends, return 0 if there is no preference.
    fn default_netint_idx(&self) -> u32;

    /// Resolves a local IPv4 address to the OS interface index used for multicast sends.
    ///
    /// Returns `None` if no interface with that address is known to this backend.
    fn resolve_netint_idx(&self, addr: Ipv4Addr) -> Option<u32> {
        self.enumerate_netints()
            .iter()
            .find_map(|n| if n.addr == addr { Some(n.os_idx) } else { None })
    }

    // -----------------------------------------------------------------------
    // Send primitives (required)
    // -----------------------------------------------------------------------

    /// Send `bytes` to the multicast group at `dst` using the socket
    /// associated with the interface at `idx` in [`enumerate_netints`].
    ///
    /// # Errors
    /// Returns `Io` if the send fails.
    fn send_mcast(&self, idx: u32, dst: SocketAddr, bytes: &[u8]) -> Result<()>;

    /// Send `bytes` to the unicast destination `dst`.
    ///
    /// # Errors
    /// Returns `Io` if the send fails.
    fn send_ucast(&self, dst: SocketAddr, bytes: &[u8]) -> Result<()>;

    // -----------------------------------------------------------------------
    // Batched dispatch (overridable)
    // -----------------------------------------------------------------------

    /// Execute a batch of [`PendingSend`] items produced by a single protocol
    /// operation.
    ///
    /// The default implementation calls [`send_mcast`] or [`send_ucast`] for
    /// each item in order. Backends that support vectored I/O (e.g.
    /// `sendmmsg`) should override this to group sends by socket and issue a
    /// single syscall per socket.
    ///
    /// # Errors
    /// Returns the first error encountered. Remaining sends in the batch are
    /// not attempted after an error.
    fn execute_batch(&self, sends: &[PendingSend]) -> Result<()> {
        for s in sends {
            match &s.destination {
                SendDestination::Multicast {
                    netint_os_idx,
                    multicast_addr,
                } => self.send_mcast(*netint_os_idx, *multicast_addr, &s.bytes)?,
                SendDestination::Unicast { addr } => self.send_ucast(*addr, &s.bytes)?,
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Socket options
    // -----------------------------------------------------------------------

    /// Sets the multicast TTL on all multicast send sockets.
    ///
    /// # Errors
    /// Returns `Io` if the option cannot be set.
    fn set_multicast_ttl(&self, ttl: u32) -> Result<()>;

    /// Returns the current multicast TTL.
    ///
    /// # Errors
    /// Returns `Io` if the option cannot be read.
    fn multicast_ttl(&self) -> Result<u32>;

    /// Enables or disables multicast loopback on all multicast send sockets.
    ///
    /// When enabled, multicast packets sent by this source are looped back to
    /// other sockets on the same host that have joined the multicast group.
    /// Required for local testing without a second machine.
    ///
    /// # Errors
    /// Returns `Io` if the option cannot be set.
    fn set_multicast_loop_v4(&self, val: bool) -> Result<()>;

    /// Returns whether multicast loopback is currently enabled.
    ///
    /// # Errors
    /// Returns `Io` if the option cannot be read.
    fn multicast_loop_v4(&self) -> Result<bool>;

    /// Returns the unicast TTL.
    ///
    /// # Errors
    /// Returns `Io` if the option cannot be read.
    fn ttl(&self) -> Result<u32>;

    /// Sets the unicast TTL.
    ///
    /// # Errors
    /// Returns `Io` if the option cannot be set.
    fn set_ttl(&self, ttl: u32) -> Result<()>;
}
