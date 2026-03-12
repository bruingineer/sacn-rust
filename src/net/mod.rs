// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Network abstraction layer for sACN.
//!
//! This module defines the [`SacnSourceNet`] trait and the associated types used to
//! decouple E1.31 protocol logic from OS networking primitives.
//!
//! The core protocol state machine (`SacnSourceCore`) produces [`PendingSend`]
//! values describing *what* to send and *where*. A [`SacnSourceNet`] implementation
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
//! Implement [`SacnSourceNet`] on your own type and pass it to
//! `SacnSource::with_net(your_backend)`. The protocol core and runtime wrapper
//! will call [`SacnSourceNet::execute_batch`] for every group of sends produced by a
//! single user-facing API call, so batching opportunities are preserved.

use core::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use crate::error::errors::Result;

pub mod std_net;

// ---------------------------------------------------------------------------
// NetIntId
// ---------------------------------------------------------------------------

/// Identifies a single network interface available for sACN multicast sends.
///
/// Currently IPv4-only. IPv6 support will be added in a later phase.
///
/// The `addr` field is the local unicast address of the interface and is used
/// to set `IP_MULTICAST_IF` on the per-interface multicast send socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetIntId {
    /// The local IPv4 address of this network interface.
    pub addr: IpAddr,
    /// The network interface OS index
    pub os_idx: u32,
}

/// Holds the IP version used for a specific instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

// ---------------------------------------------------------------------------
// SendDestination
// ---------------------------------------------------------------------------

/// Describes where a [`PendingSend`] should be delivered.
#[derive(Debug, Clone)]
pub enum SendDestination {
    /// Send to an IP multicast group via the socket bound to the interface with
    /// the given OS index.
    Multicast {
        /// The OS interface index identifying which socket to send from.
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

/// A fully-formed datagram ready to be handed to a [`SacnSourceNet`] backend.
///
/// Produced by `SacnSourceCore` methods (`send`, `send_sync_packet`, `tick`,
/// etc.) and consumed by [`SacnSourceNet::execute_batch`].
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
// SacnSourceNet trait
// ---------------------------------------------------------------------------

/// Pluggable network backend for sACN sending.
///
/// Implementations own the OS sockets (or equivalent resources) and are
/// responsible for interface enumeration, multicast configuration, and
/// datagram dispatch.
///
/// The protocol core (`SacnSourceCore`) has no knowledge of this trait — it
/// only produces [`PendingSend`] values. The runtime wrapper
/// (`SacnSourceInternal`) calls [`SacnSourceNet::execute_batch`] to dispatch them.
///
/// # Required methods
///
/// Only [`send_mcast`], [`send_ucast`], and the socket option accessors are
/// required. [`execute_batch`] has a correct default implementation that calls
/// the required methods in a loop; override it in backends that can do better
/// (e.g. `sendmmsg`).
///
/// # Thread safety
///
/// Implementations must be `Send` because the runtime wrapper moves the
/// backend into the update thread. `&self` send methods allow the backend to
/// be shared across method calls without requiring `&mut self` on the hot
/// path.
pub trait SacnSourceNet: Send {
    // -----------------------------------------------------------------------
    // Interface lookup
    // -----------------------------------------------------------------------

    /// Returns the OS interface index that should be used as the default for
    /// newly registered universes.
    ///
    /// For [`StdSourceNet`] this is derived from the local address passed at
    /// construction. For custom backends, return 0 if there is no preference.
    fn default_netint_idx(&self) -> u32;

    fn ip_version(&self) -> IpVersion;

    // -----------------------------------------------------------------------
    // Send primitives (required)
    // -----------------------------------------------------------------------

    /// Send `bytes` to the multicast group at `dst` using the socket
    /// associated with the interface identified by OS index `idx`.
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
    fn set_multicast_loop(&self, val: bool) -> Result<()>;

    /// Returns whether multicast loopback is currently enabled.
    ///
    /// # Errors
    /// Returns `Io` if the option cannot be read.
    fn multicast_loop(&self) -> Result<bool>;

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

// ---------------------------------------------------------------------------
// RCV_BUF_DEFAULT_SIZE
// ---------------------------------------------------------------------------

/// The default size of the buffer used to receive E1.31 packets.
///
/// 1143 bytes is the largest packet required as per Section 8 of ANSI E1.31-2018,
/// aligned to 64 bits that is 1144 bytes.
pub const RCV_BUF_DEFAULT_SIZE: usize = 1144;

// ---------------------------------------------------------------------------
// SacnReceiverNet trait
// ---------------------------------------------------------------------------

/// Pluggable network backend for sACN receiving.
///
/// Implementations own the OS sockets (or equivalent resources) and are
/// responsible for receiving raw datagrams and managing multicast group membership.
///
/// [`std_net::StdReceiverNet`] is the default implementation used by
/// [`SacnReceiver`](crate::receive::SacnReceiver). A test double can be provided
/// by implementing this trait on a custom type and constructing a receiver via
/// `SacnReceiver::with_net`.
///
/// # Required methods
///
/// All methods are required. There are no provided defaults — every backend
/// must implement the full interface.
pub trait SacnReceiverNet {
    // -----------------------------------------------------------------------
    // Receive primitive (required)
    // -----------------------------------------------------------------------

    /// Reads raw bytes from the underlying transport into `buf`.
    ///
    /// Returns the number of bytes read.
    ///
    /// # Errors
    ///
    /// Returns `Io(WouldBlock)` / `Io(TimedOut)` when no data is available
    /// within the configured socket timeout — callers treat this as a normal
    /// non-fatal condition and loop.
    ///
    /// Returns `TooManyBytesRead` if the datagram is larger than `buf`.
    fn recv_bytes(&mut self, buf: &mut [u8; RCV_BUF_DEFAULT_SIZE]) -> Result<usize>;

    // -----------------------------------------------------------------------
    // Multicast group management (required)
    // -----------------------------------------------------------------------

    /// Joins the IP multicast group corresponding to `universe`.
    ///
    /// # Errors
    ///
    /// Returns `Io` if the socket operation fails.
    fn listen_multicast_universe(&self, universe: u16) -> Result<()>;

    /// Leaves the IP multicast group corresponding to `universe`.
    ///
    /// # Errors
    ///
    /// Returns `Io` if the socket operation fails.
    fn mute_multicast_universe(&mut self, universe: u16) -> Result<()>;

    // -----------------------------------------------------------------------
    // Socket options (required)
    // -----------------------------------------------------------------------

    /// Sets the read timeout used by [`recv_bytes`](SacnReceiverNet::recv_bytes).
    ///
    /// A value of `None` makes the socket blocking (no timeout).
    ///
    /// # Errors
    ///
    /// Returns `Io` if the option cannot be applied to the underlying socket.
    fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<()>;

    /// Returns `true` if multicast is supported and enabled on this backend.
    ///
    /// When `false`, calls to
    /// [`listen_multicast_universe`](SacnReceiverNet::listen_multicast_universe)
    /// and [`mute_multicast_universe`](SacnReceiverNet::mute_multicast_universe)
    /// should be skipped by the caller.
    fn is_multicast_enabled(&self) -> bool;

    /// Enables or disables multicast on this backend.
    ///
    /// # Errors
    ///
    /// Returns `OsOperationUnsupported` if multicast cannot be enabled in the
    /// current environment (e.g. IPv6 on Windows).
    fn set_is_multicast_enabled(&mut self, val: bool) -> Result<()>;

    /// Restricts the socket to IPv6 traffic only, or allows dual-stack when `false`.
    ///
    /// # Errors
    ///
    /// Returns `IpVersionError` if the socket is not bound to an IPv6 address.
    fn set_only_v6(&mut self, val: bool) -> Result<()>;
}
