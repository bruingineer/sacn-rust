// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Standard UDP backend for sACN using [`socket2`].
//!
//! [`StdSourceNet`] is the default [`SacnSourceNet`] implementation. It owns:
//! - One multicast send socket per non-loopback IPv4 network interface,
//!   each configured with `IP_MULTICAST_IF` pointing at that interface.
//! - One shared unicast send socket.
//!
//! If no non-loopback interfaces are found (e.g. in a CI environment), a
//! single unbound fallback socket is used for multicast sends so the library
//! remains functional on minimal hosts.

use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use if_addrs::get_if_addrs;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::error::errors::{Result, SacnError};
use crate::net::{IpVersion, NetIntId, RCV_BUF_DEFAULT_SIZE, SacnReceiverNet, SacnSourceNet};
use crate::packet::{universe_to_ipv4_multicast_addr, universe_to_ipv6_multicast_addr};

// ---------------------------------------------------------------------------
// StdSourceNet
// ---------------------------------------------------------------------------

/// Standard UDP network backend for sACN.
///
/// Created by [`StdSourceNet::new`] and passed to `SacnSource::with_net`. Users
/// relying on the default type parameter (`SacnSource<StdSourceNet>`) do not need
/// to construct this directly — `SacnSource::with_ip` and friends call
/// [`StdSourceNet::new`] internally.
///
/// # Socket layout
///
/// | Socket | Count | Purpose |
/// |---|---|---|
/// | `mcast_sockets[os_idx]` | 1 per netint | Multicast sends with `IP_MULTICAST_IF = netint.addr` |
/// | `ucast_socket` | 1 shared | Unicast sends |
///
/// # Fallback behaviour
///
/// If [`get_if_addrs`] returns no non-loopback interfaces for the chosen family,
/// `StdSourceNet` creates a single unbound socket at index 0 used for all multicast
/// sends. This keeps the library working on minimal hosts (CI, loopback-only
/// containers) at the cost of losing explicit interface selection.
#[derive(Debug)]
pub struct StdSourceNet {
    /// Maps each known interface's IP address to its OS interface index.
    /// Used by [`resolve_netint_idx`] without exposing a public interface list.
    netint_index: HashMap<IpAddr, u32>,

    /// One multicast send socket per network interface, keyed by OS interface index.
    /// Always contains at least one entry: a fallback socket at index 0.
    mcast_sockets: HashMap<u32, Socket>,

    /// Shared unicast send socket.
    ucast_socket: Socket,

    default_netint_idx: u32,

    family: IpVersion,
}

impl StdSourceNet {
    /// Constructs a new `StdSourceNet` bound to the given local address.
    ///
    /// `addr` is used to bind the unicast socket. The port is typically
    /// `ACN_SDT_MULTICAST_PORT + 1` to avoid conflicts with receiver sockets
    /// on the same host.
    ///
    /// # Errors
    /// `Io`: Returned if any socket cannot be created, configured, or bound.
    ///
    /// `UnsupportedIpVersion`: Returned if `addr` is not IPv4.
    pub(crate) fn new(addr: SocketAddr) -> Result<Self> {
        let family = match addr.ip() {
            IpAddr::V4(_) => IpVersion::V4,
            IpAddr::V6(_) => IpVersion::V6,
        };
        // Enumerate non-loopback interfaces for the chosen IP family.
        let netints = enumerate_netints(family)?;

        let default_netint_idx = if addr.ip().is_unspecified() {
            0
        } else {
            netints
                .iter()
                .find_map(|n| {
                    if n.addr == addr.ip() {
                        Some(n.os_idx)
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    SacnError::UnsupportedIpVersion(format!(
                        "No matching interface for IP {}",
                        addr.ip()
                    ))
                })?
        };

        // Build one multicast send socket per interface.
        let mut mcast_sockets = HashMap::new();

        // Fallback: single unbound socket. Multicast egress interface will
        // be chosen by the OS routing table — correct for single-NIC hosts.
        match family {
            IpVersion::V4 => mcast_sockets.insert(0, make_mcast_socket(family, None)?),
            IpVersion::V6 => mcast_sockets.insert(
                0,
                make_mcast_socket(
                    family,
                    Some(&NetIntId {
                        addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                        os_idx: 0,
                    }),
                )?,
            ),
        };

        for netint in &netints {
            mcast_sockets.insert(netint.os_idx, make_mcast_socket(family, Some(netint))?);
        }

        // Build addr→index lookup map from the enumerated interfaces.
        let netint_index: HashMap<IpAddr, u32> =
            netints.iter().map(|n| (n.addr, n.os_idx)).collect();

        // Shared unicast socket bound to the caller-supplied address.
        let ucast_socket = make_ucast_socket(addr)?;

        let net = StdSourceNet {
            netint_index,
            mcast_sockets,
            ucast_socket,
            default_netint_idx,
            family,
        };
        if !cfg!(target_os = "windows")
            && let IpVersion::V6 = family
        {
            net.set_multicast_loop(false)?;
        }

        Ok(net)
    }

    pub(crate) fn resolve_netint_idx(&self, addr: IpAddr) -> Option<u32> {
        self.netint_index.get(&addr).copied()
    }
}

// ---------------------------------------------------------------------------
// SacnSourceNet impl
// ---------------------------------------------------------------------------

impl SacnSourceNet for StdSourceNet {
    fn default_netint_idx(&self) -> u32 {
        self.default_netint_idx
    }

    fn ip_version(&self) -> IpVersion {
        self.family
    }

    fn send_mcast(&self, idx: u32, dst: SocketAddr, bytes: &[u8]) -> Result<()> {
        // Look up the socket for the requested interface index.
        // Fall back to the unbound socket at index 0 if the index isn't found —
        // this handles both the minimal-host case (no real interfaces enumerated)
        // and callers that pass idx = 0 as the default.
        let socket = self
            .mcast_sockets
            .get(&idx)
            .or_else(|| self.mcast_sockets.get(&0))
            .expect("mcast_sockets always has at least one entry at index 0");

        socket.send_to(bytes, &dst.into()).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "StdSourceNet: socket({:?}) multicast send_to({:?}) failed",
                    socket, dst
                ),
            )
        })?;

        Ok(())
    }

    fn send_ucast(&self, dst: SocketAddr, bytes: &[u8]) -> Result<()> {
        self.ucast_socket
            .send_to(bytes, &dst.into())
            .map_err(|e| std::io::Error::new(e.kind(), "StdSourceNet: unicast send_to failed"))?;
        Ok(())
    }

    fn set_multicast_ttl(&self, ttl: u32) -> Result<()> {
        for s in self.mcast_sockets.values() {
            self.family.set_multicast_ttl(s, ttl)?;
        }
        Ok(())
    }

    fn multicast_ttl(&self) -> Result<u32> {
        // All sockets are configured identically — read from the first.
        self.family.multicast_ttl(
            self.mcast_sockets
                .values()
                .next()
                .expect("Always should have at least 1 socket"),
        )
    }

    fn ttl(&self) -> Result<u32> {
        self.family.unicast_ttl(&self.ucast_socket)
    }

    fn set_ttl(&self, ttl: u32) -> Result<()> {
        self.family.set_unicast_ttl(&self.ucast_socket, ttl)
    }

    fn set_multicast_loop(&self, val: bool) -> Result<()> {
        for s in self.mcast_sockets.values() {
            self.family.set_multicast_loop(s, val)?;
        }
        Ok(())
    }

    fn multicast_loop(&self) -> Result<bool> {
        // All sockets are configured identically — read from the first.
        self.family.multicast_loop(
            self.mcast_sockets
                .values()
                .next()
                .expect("Always should have at least 1 socket"),
        )
    }
}

/// Encapsulates the per-family socket operations that differ between IPv4 and IPv6.
/// Everything else (`send_to`, `bind`, `SO_REUSEADDR`, `SO_REUSEPORT`) is identical
/// and lives directly in the calling code.
impl IpVersion {
    fn domain(&self) -> Domain {
        match self {
            IpVersion::V4 => Domain::IPV4,
            IpVersion::V6 => Domain::IPV6,
        }
    }

    /// Pins the multicast egress interface on a send socket.
    /// V4 uses the interface address; V6 uses the OS interface index.
    fn set_multicast_if(&self, socket: &Socket, netint: &NetIntId) -> Result<()> {
        match self {
            IpVersion::V4 => match netint.addr {
                IpAddr::V4(ref v4) => Ok(socket.set_multicast_if_v4(v4)?),
                IpAddr::V6(_) => Err(SacnError::IpVersionError()),
            },
            IpVersion::V6 => Ok(socket.set_multicast_if_v6(netint.os_idx)?),
        }
    }

    fn set_multicast_loop(&self, socket: &Socket, val: bool) -> Result<()> {
        match self {
            IpVersion::V4 => Ok(socket.set_multicast_loop_v4(val)?),
            IpVersion::V6 => Ok(socket.set_multicast_loop_v6(val)?),
        }
    }

    fn multicast_loop(&self, socket: &Socket) -> Result<bool> {
        match self {
            IpVersion::V4 => Ok(socket.multicast_loop_v4()?),
            IpVersion::V6 => Ok(socket.multicast_loop_v6()?),
        }
    }

    fn set_multicast_ttl(&self, socket: &Socket, ttl: u32) -> Result<()> {
        match self {
            IpVersion::V4 => Ok(socket.set_multicast_ttl_v4(ttl)?),
            IpVersion::V6 => Ok(socket.set_multicast_hops_v6(ttl)?),
        }
    }

    fn multicast_ttl(&self, socket: &Socket) -> Result<u32> {
        match self {
            IpVersion::V4 => Ok(socket.multicast_ttl_v4()?),
            IpVersion::V6 => Ok(socket.multicast_hops_v6()?),
        }
    }

    fn set_unicast_ttl(&self, socket: &Socket, ttl: u32) -> Result<()> {
        match self {
            IpVersion::V4 => Ok(socket.set_ttl_v4(ttl)?),
            IpVersion::V6 => Ok(socket.set_unicast_hops_v6(ttl)?),
        }
    }

    fn unicast_ttl(&self, socket: &Socket) -> Result<u32> {
        match self {
            IpVersion::V4 => Ok(socket.ttl_v4()?),
            IpVersion::V6 => Ok(socket.unicast_hops_v6()?),
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Enumerates non-loopback IPv4 or IPv6 network interfaces on the current host
/// based on the family argument.
///
/// Returns an empty `Vec` if no such interfaces exist rather than an error,
/// so the fallback socket path in [`StdSourceNet::new`] can handle minimal hosts.
fn enumerate_netints(family: IpVersion) -> Result<Vec<NetIntId>> {
    let ifaces = get_if_addrs().map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("Failed to enumerate network interfaces: {e}"),
        )
    })?;

    let netints = ifaces
        .into_iter()
        .filter(|iface| iface.index.is_some())
        .filter_map(|iface| {
            let idx = iface
                .index
                .expect("Filtered interfaces with indices in previous filter.");
            match family {
                IpVersion::V4 => iface.addr.ip().is_ipv4().then_some(NetIntId {
                    addr: iface.addr.ip(),
                    os_idx: idx,
                }),
                IpVersion::V6 => iface.addr.ip().is_ipv6().then_some(NetIntId {
                    addr: iface.addr.ip(),
                    os_idx: idx,
                }),
            }
        })
        .collect();

    Ok(netints)
}

/// Finds the single [`NetIntId`] whose address matches `addr` in the given IP family.
///
/// Returns `Ok(None)` if no interface has that address (rather than an error),
/// so callers can choose how to handle the missing-interface case.
fn find_netint(family: IpVersion, addr: IpAddr) -> Result<Option<NetIntId>> {
    Ok(enumerate_netints(family)?
        .into_iter()
        .find(|n| n.addr == addr))
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
/// - for IPv4, `IP_MULTICAST_TTL`: left at OS default (1); caller may override via
///   [`StdSourceNet::set_multicast_ttl`].
/// - for IPv6, `IPV6_MULTICAST_HOPS`: left OS default; caller may override via
///   [`StdSourceNet::set_multicast_ttl`].
fn make_mcast_socket(family: IpVersion, interface: Option<&NetIntId>) -> Result<Socket> {
    println!("creating mcast {family:?} socket on interface {interface:?}");
    let socket = Socket::new(family.domain(), Type::DGRAM, None)?;

    // Allow multiple processes / sockets to share the sACN port.
    #[cfg(not(target_os = "windows"))]
    socket.set_reuse_port(true)?;
    socket.set_reuse_address(true)?;

    if let Some(netint) = interface
        && !netint.addr.is_unspecified()
    {
        family.set_multicast_if(&socket, netint)?;
    };
    println!("- socket created {:?}", socket);
    Ok(socket)
}

/// Creates and configures a unicast send socket bound to `addr`.
///
/// # Socket configuration
/// - `SO_REUSEADDR` (+ `SO_REUSEPORT` on Linux): consistent with multicast sockets.
/// - Bound to `addr` so the OS assigns a fixed local port for unicast sends.
fn make_ucast_socket(addr: SocketAddr) -> Result<Socket> {
    println!("creating ucast socket for addr {addr:?}");
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, None)?;

    #[cfg(not(target_os = "windows"))]
    socket.set_reuse_port(true)?;
    socket.set_reuse_address(true)?;

    // socket.bind(&addr.into())?; // TODO: check this bind on windows, linux, macos
    println!("- socket created");
    Ok(socket)
}

// ---------------------------------------------------------------------------
// Platform-specific libc constants for multicast address family detection
// ---------------------------------------------------------------------------

/// Constants required to detect if an IP is IPv4 or IPv6.
#[cfg(not(target_os = "windows"))]
use libc::{AF_INET, AF_INET6};

/// The libc constants required are not available on many windows environments and therefore are hard-coded.
/// Defined as per <https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket>
#[cfg(target_os = "windows")]
const AF_INET: i32 = 2;

/// Defined as per <https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket>
#[cfg(target_os = "windows")]
const AF_INET6: i32 = 23;

// ---------------------------------------------------------------------------
// StdReceiverNet
// ---------------------------------------------------------------------------

/// Standard UDP receiver backend for sACN.
///
/// Created by [`StdReceiverNet::new`] and passed to `SacnReceiver::with_net`.
/// Users relying on the default type parameter (`SacnReceiver<StdReceiverNet>`)
/// do not need to construct this directly — `SacnReceiver::with_ip` calls
/// [`StdReceiverNet::new`] internally.
///
/// # Socket layout
///
/// | Socket | Count | Purpose |
/// |---|---|---|
/// | `socket` | 1 | Receive all universes; multicast groups joined per `listen_universes` call |
///
/// # Platform differences
///
/// Windows and Unix differ in socket creation order and multicast join/leave
/// calls. Both are handled within the platform-specific `impl` blocks below.
/// IPv6 multicast is currently unsupported on Windows due to missing `socket2`
/// support; the `is_multicast_enabled` flag reflects this at runtime.
#[derive(Debug)]
pub struct StdReceiverNet {
    /// The underlying UDP network socket used.
    socket: Socket,

    /// The interface that this `StdReceiverNet` is bound to.
    netint: NetIntId,

    /// If true then this receiver supports multicast, is false then it does not.
    /// This flag is set when the receiver is created as not all environments currently support IP multicast.
    /// E.g. IPv6 Windows IP Multicast is currently unsupported.
    is_multicast_enabled: bool,
}

// ---------------------------------------------------------------------------
// StdReceiverNet — shared impl (platform-agnostic methods)
// ---------------------------------------------------------------------------

impl StdReceiverNet {
    /// Sets the value of the `is_multicast_enabled` flag to the given value.
    ///
    /// If set to false then the receiver won't attempt to join any more multicast groups.
    ///
    /// This method does not attempt to leave multicast groups already joined through previous `listen_universe` calls.
    ///
    /// # Arguments
    /// val: The new value for the `is_multicast_enabled` flag.
    fn set_is_multicast_enabled(&mut self, val: bool) -> Result<()> {
        // All multicast modes are supported on Unix — no guard needed.
        self.is_multicast_enabled = val;
        Ok(())
    }

    /// Returns true if multicast is enabled on this receiver and false if not.
    /// This flag is set when the receiver is created as not all environments currently support IP multicast.
    /// E.g. IPv6 Windows IP Multicast is currently unsupported.
    fn is_multicast_enabled(&self) -> bool {
        self.is_multicast_enabled
    }

    /// If set to true then only receive over IPv6. If false then receiving will be over both IPv4 and IPv6.
    /// This will return an error if the receiver wasn't created using an IPv6 address to bind to.
    fn set_only_v6(&mut self, val: bool) -> Result<()> {
        if self.netint.addr.is_ipv4() {
            Err(SacnError::IpVersionError())
        } else {
            Ok(self.socket.set_only_v6(val)?)
        }
    }

    /// Reads raw bytes from the underlying socket into the given buffer.
    /// Returns the number of bytes read.
    ///
    /// # Errors
    /// May return an error if there is an issue receiving data from the underlying socket.
    /// Returns `TooManyBytesRead` if the number of bytes read exceeds the buffer size.
    fn recv_bytes(&mut self, buf: &mut [u8; RCV_BUF_DEFAULT_SIZE]) -> Result<usize> {
        // use read() rather than read_exact() — both platforms behave correctly with read().
        let n = self.socket.read(buf)?;
        if n > RCV_BUF_DEFAULT_SIZE {
            return Err(SacnError::TooManyBytesRead(n, buf.len()));
        }
        Ok(n)
    }

    /// Set the timeout for the recv operation.
    ///
    /// Arguments:
    /// timeout: The new timeout for the receive operation, a value of None means the recv operation will become blocking.
    ///
    /// Errors:
    /// A timeout with Duration 0 will cause an error. See (`set_read_timeout`)[`fn.set_read_timeout.Socket`].
    fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        Ok(self.socket.set_read_timeout(timeout)?)
    }

    /// Resolves `universe` to the appropriate multicast `SockAddr` based on whether
    /// this receiver is bound to an IPv4 or IPv6 address.
    ///
    /// # Errors
    /// Returns an error if the universe cannot be converted to a multicast address.
    fn universe_to_multicast_sockaddr(&self, universe: u16) -> Result<SockAddr> {
        if self.netint.addr.is_ipv4() {
            universe_to_ipv4_multicast_addr(universe) // "Failed to convert universe to IPv4 multicast addr"
        } else {
            universe_to_ipv6_multicast_addr(universe) // "Failed to convert universe to IPv6 multicast addr"
        }
    }

    /// Connects this `StdReceiverNet` to the multicast address which corresponds to the given universe.
    ///
    /// # Errors
    /// Will return an Error if the given universe cannot be converted to an Ipv4 or Ipv6 `multicast_addr`.
    /// See `packet::universe_to_ipv4_multicast_addr` and `packet::universe_to_ipv6_multicast_addr`.
    ///
    /// Will return an Io error if cannot join the universes corresponding multicast group address.
    fn listen_multicast_universe(&self, universe: u16) -> Result<()> {
        let multicast_addr = self.universe_to_multicast_sockaddr(universe)?;
        join_multicast(&self.socket, multicast_addr, self.netint)
    }

    /// Removes this `StdReceiverNet` from the multicast group which corresponds to the given universe.
    ///
    /// # Errors
    /// Will return an Error if the given universe cannot be converted to an Ipv4 or Ipv6 `multicast_addr`.
    /// See `packet::universe_to_ipv4_multicast_addr` and `packet::universe_to_ipv6_multicast_addr`.
    fn mute_multicast_universe(&mut self, universe: u16) -> Result<()> {
        let multicast_addr = self.universe_to_multicast_sockaddr(universe)?;
        leave_multicast(&self.socket, multicast_addr, self.netint)
    }
}

// ---------------------------------------------------------------------------
// StdReceiverNet — Windows impl (platform-specific methods only)
// ---------------------------------------------------------------------------

/// Socket construction and multicast-flag guarding differ on Windows.
/// Tested with Windows 10 1909.
impl StdReceiverNet {
    /// Creates a new receiver on the interface specified by the given address.
    ///
    /// If the given address is an IPv4 address then communication will only work between IPv4 devices, if the given address is IPv6 then communication
    /// will only work between IPv6 devices by default but IPv4 receiving can be enabled using `set_ipv6_only(false)`.
    ///
    /// # Errors
    /// Will return an error if the receiver fails to bind to a socket with the given ip.
    /// For more details see `socket2::Socket::new()`.
    pub fn new(ip: SocketAddr) -> Result<StdReceiverNet> {
        let family = match ip.ip() {
            IpAddr::V4(_) => IpVersion::V4,
            IpAddr::V6(_) => IpVersion::V6,
        };

        let netint = if ip.ip().is_unspecified() {
            NetIntId {
                addr: ip.ip(),
                os_idx: 0,
            }
        } else {
            find_netint(family, ip.ip())?
                .expect("receive IP should match an existing IP on an interface")
        };

        #[cfg(not(target_os = "windows"))]
        let socket = create_recv_unix_socket(ip)?;
        #[cfg(target_os = "windows")]
        let socket = create_recv_win_socket(ip)?;

        let stdrecv = StdReceiverNet {
            socket,
            netint,
            is_multicast_enabled: true,
        };

        Ok(stdrecv)
    }
}

// ---------------------------------------------------------------------------
// SacnReceiverNet impl for StdReceiverNet
// ---------------------------------------------------------------------------

/// Wires [`SacnReceiverNet`] to [`StdReceiverNet`].
///
/// All methods are defined in the unconditional `impl StdReceiverNet` block
/// above; this impl simply satisfies the trait bound.
impl SacnReceiverNet for StdReceiverNet {
    fn recv_bytes(&mut self, buf: &mut [u8; RCV_BUF_DEFAULT_SIZE]) -> Result<usize> {
        self.recv_bytes(buf)
    }

    fn listen_multicast_universe(&self, universe: u16) -> Result<()> {
        self.listen_multicast_universe(universe)
    }

    fn mute_multicast_universe(&mut self, universe: u16) -> Result<()> {
        self.mute_multicast_universe(universe)
    }

    fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        self.set_timeout(timeout)
    }

    fn is_multicast_enabled(&self) -> bool {
        self.is_multicast_enabled()
    }

    fn set_is_multicast_enabled(&mut self, val: bool) -> Result<()> {
        self.set_is_multicast_enabled(val)
    }

    fn set_only_v6(&mut self, val: bool) -> Result<()> {
        self.set_only_v6(val)
    }
}

// ---------------------------------------------------------------------------
// Private receiver socket helpers
// ---------------------------------------------------------------------------

/// Creates a new socket2 receive socket bound to the given address on Unix/Linux.
///
/// The socket is always bound to `UNSPECIFIED:ACN_SDT_MULTICAST_PORT` rather
/// than the caller-supplied address so that multicast packets destined for any
/// interface are accepted. `SO_REUSEADDR` and `SO_REUSEPORT` allow multiple
/// processes to share the sACN port simultaneously.
///
/// # Errors
/// Will return an error if the socket cannot be created, see (Socket::new)[fn.new.Socket].
///
/// Will return an error if the socket cannot be bound to the given address, see (bind)[fn.bind.Socket2].
#[cfg(not(target_os = "windows"))]
fn create_recv_unix_socket(addr: SocketAddr) -> Result<Socket> {
    let (domain, unspecified_sock) = if addr.is_ipv4() {
        (
            Domain::IPV4,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), addr.port()),
        )
    } else {
        (
            Domain::IPV6,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), addr.port()),
        )
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // Multiple different processes might want to listen to the sACN stream so therefore need to allow re-using the ACN port.
    socket.set_reuse_port(true)?;
    socket.set_reuse_address(true)?;

    socket.bind(&unspecified_sock.into())?;

    Ok(socket)
}

/// Creates a new socket2 receive socket bound to the given address on Windows.
///
/// Windows requires binding to the specific address rather than UNSPECIFIED.
/// `SO_REUSEADDR` allows multiple processes to share the sACN port.
///
/// # Errors
/// Will return an error if the socket cannot be created, see [`Socket::new`].
///
/// Will return an error if the socket cannot be bound to the given address, see [`Socket::bind`].
#[cfg(target_os = "windows")]
fn create_recv_win_socket(addr: SocketAddr) -> Result<Socket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_address(true)?;
    socket.bind(&SockAddr::from(addr))?;
    Ok(socket)
}

/// Builds an `UnsupportedIpVersion` error for an unrecognised `SockAddr` address family value.
///
/// Used by [`join_multicast`] and [`leave_multicast`] for their catch-all arms.
fn ip_family_error(context: &str, family: i32) -> SacnError {
    SacnError::UnsupportedIpVersion(format!(
        "IP version not recognised as AF_INET (IPv4) or AF_INET6 (IPv6) during {context} \
         — family value (as i32): {family}"
    ))
}

/// Joins the IP multicast group described by `addr` on the given socket.
///
/// The IPv4 arm uses `interface.addr` to select the outgoing interface.
/// The IPv6 arm uses interface index 0 (OS default).
///
/// # Errors
/// Returns `IpVersionError` if `addr` is `AF_INET` but `interface.addr` is IPv6.
/// Returns `UnsupportedIpVersion` for unknown address families or malformed `SockAddr` values.
/// Returns `Io` if the underlying socket call fails.
fn join_multicast(socket: &Socket, group: SockAddr, interface: NetIntId) -> Result<()> {
    match group.family() as i32 {
        // Cast required because AF_INET is defined in libc in terms of a c_int (i32) but addr.family returns using u16.
        AF_INET => match group.as_socket_ipv4() {
            Some(grp) => match interface.addr {
                IpAddr::V4(ref interface_v4) => {
                    socket.join_multicast_v4(grp.ip(), interface_v4).map_err(|e| {
                        SacnError::Io(std::io::Error::new(e.kind(), "Failed to join IPv4 multicast"))
                    })?;
                }
                IpAddr::V6(_) => return Err(SacnError::IpVersionError()),
            },
            None => return Err(SacnError::UnsupportedIpVersion(
                "IP version recognised as AF_INET but not actually usable as AF_INET so must be unknown type".to_string(),
            )),
        },
        AF_INET6 => match group.as_socket_ipv6() {
            Some(grp) => match interface.addr {
                IpAddr::V6(_) => {
                    socket.join_multicast_v6(grp.ip(), interface.os_idx).map_err(|e| {
                        SacnError::Io(std::io::Error::new(e.kind(), "Failed to join IPv6 multicast"))
                    })?;}
                IpAddr::V4(_) => return Err(SacnError::IpVersionError()),
            }
            None => return Err(SacnError::UnsupportedIpVersion(
                "IP version recognised as AF_INET6 but not actually usable as AF_INET6 so must be unknown type".to_string(),
            )),
        },
        x => return Err(ip_family_error("multicast join", x)),
    }
    Ok(())
}

/// Leaves the IP multicast group described by `addr` on the given socket.
///
/// On Windows, IPv6 leave is unsupported and returns `OsOperationUnsupported`.
/// On Unix, both IPv4 and IPv6 are supported.
///
/// # Errors
/// Returns `OsOperationUnsupported` on Windows when `addr` is `AF_INET6`.
/// Returns `IpVersionError` if `addr` is `AF_INET` but `interface_addr` is IPv6.
/// Returns `UnsupportedIpVersion` for unknown address families or malformed `SockAddr` values.
/// Returns `Io` if the underlying socket call fails.
fn leave_multicast(socket: &Socket, group: SockAddr, interface: NetIntId) -> Result<()> {
    match group.family() as i32 {
        // Cast required because AF_INET is defined in libc in terms of a c_int (i32) but addr.family returns using u16.
        AF_INET => match group.as_socket_ipv4() {
            Some(grp) => {
                leave_multicast_v4(socket, grp.ip(), interface.addr)?;
            }
            None => return Err(SacnError::UnsupportedIpVersion(
                "IP version recognised as AF_INET but not actually usable as AF_INET so must be unknown type".to_string(),
            )),
        },
        AF_INET6 => {
            match group.as_socket_ipv6() {
                Some(grp) => {
                    leave_multicast_v6(socket, grp.ip(), interface.os_idx)?;
                }
                None => return Err(SacnError::UnsupportedIpVersion(
                    "IP version recognised as AF_INET6 but not actually usable as AF_INET so must be unknown type".to_string(),
                )),
            }
        }
        x => return Err(ip_family_error("multicast leave", x)),
    }
    Ok(())
}

/// Leaves an IPv4 multicast group.
///
/// The `interface_addr` must be IPv4; returns `IpVersionError` if it is IPv6.
fn leave_multicast_v4(socket: &Socket, group: &Ipv4Addr, interface_addr: IpAddr) -> Result<()> {
    match interface_addr {
        IpAddr::V4(ref interface_v4) => {
            socket
                .leave_multicast_v4(group, interface_v4)
                .map_err(|e| {
                    SacnError::Io(std::io::Error::new(
                        e.kind(),
                        "Failed to leave IPv4 multicast",
                    ))
                })?;
        }
        IpAddr::V6(_) => return Err(SacnError::IpVersionError()),
    }
    Ok(())
}

/// Leaves an IPv6 multicast group.
///
/// On Windows this is unsupported and returns `OsOperationUnsupported`.
/// On Unix it uses interface index 0 (OS default).
fn leave_multicast_v6(socket: &Socket, group: &Ipv6Addr, idx: u32) -> Result<()> {
    socket.leave_multicast_v6(group, idx).map_err(|e| {
        SacnError::Io(std::io::Error::new(
            e.kind(),
            "Failed to leave IPv6 multicast",
        ))
    })?;

    Ok(())
}
