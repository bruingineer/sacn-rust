#![warn(missing_docs)]

// Copyright 2020 sacn Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/// Socket 2 used for the underlying UDP socket that sACN is sent over.
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Mass import as a very large amount of packet is used here (upwards of 20 items) and this is much cleaner.
use packet::*;

/// Same reasoning as for packet meaning all sacn errors are imported.
use error::errors::{ErrorKind::*, *};

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Extra net imports required for the IPv6 handling on the linux side.
#[cfg(target_os = "linux")]
use std::net::{IpAddr, Ipv6Addr};

/// Constants required to detect if an IP is IPv4 or IPv6.
#[cfg(target_os = "linux")]
use libc::{AF_INET, AF_INET6};

/// The libc constants required are not available on many windows environments and therefore are hard-coded.
/// Defined as per https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket
#[cfg(target_os = "windows")]
const AF_INET: i32 = 2;

/// Defined as per https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket
#[cfg(target_os = "windows")]
const AF_INET6: i32 = 23;

/// The default size of the buffer used to receive E1.31 packets.
/// 1143 bytes is biggest packet required as per Section 8 of ANSI E1.31-2018, aligned to 64 bit that is 1144 bytes.
const RCV_BUF_DEFAULT_SIZE: usize = 1144;

/// DMX payload size in bytes (512 bytes of data + 1 byte start code).
pub const DMX_PAYLOAD_SIZE: usize = 513;

/// Used for receiving dmx or other data on a particular universe using multicast.
#[derive(Debug)]
pub struct SacnNetworkReceiver {
    /// The underlying UDP network socket used.
    socket: Socket,

    /// The address that this SacnNetworkReceiver is bound to.
    addr: SocketAddr,

    /// If true then this receiver supports multicast, is false then it does not.
    /// This flag is set when the receiver is created as not all environments currently support IP multicast.
    /// E.g. IPv6 Windows IP Multicast is currently unsupported.
    is_multicast_enabled: bool,
}


/// In general the lower level transport layer is handled by SacnNetworkReceiver (which itself wraps a Socket).
/// Windows and linux handle multicast sockets differently.
/// This is built for / tested with Windows 10 1909.
#[cfg(target_os = "windows")]
impl SacnNetworkReceiver {
    /// Creates a new DMX receiver on the interface specified by the given address.
    ///
    /// If the given address is an IPv4 address then communication will only work between IPv4 devices, if the given address is IPv6 then communication
    /// will only work between IPv6 devices by default but IPv4 receiving can be enabled using set_ipv6_only(false).
    ///
    /// # Errors
    /// Will return an error if the SacnReceiver fails to bind to a socket with the given ip.
    /// For more details see socket2::Socket::new().
    ///
    pub fn new(ip: SocketAddr) -> Result<SacnNetworkReceiver> {
        Ok(SacnNetworkReceiver {
            socket: create_win_socket(ip)?,
            addr: ip,
            is_multicast_enabled: !(ip.is_ipv6()), // IPv6 Windows IP Multicast is currently unsupported.
        })
    }

    /// Connects this SacnNetworkReceiver to the multicast address which corresponds to the given universe to allow receiving packets for that universe.
    ///
    /// # Errors
    /// Will return an Error if the given universe cannot be converted to an Ipv4 or Ipv6 multicast_addr depending on if the Receiver is bound to an
    /// IPv4 or IPv6 address. See packet::universe_to_ipv4_multicast_addr and packet::universe_to_ipv6_multicast_addr.
    ///
    /// Will return an Io error if cannot join the universes corresponding multicast group address.
    ///
    pub fn listen_multicast_universe(&self, universe: u16) -> Result<()> {
        let multicast_addr;

        if self.addr.is_ipv4() {
            multicast_addr = universe_to_ipv4_multicast_addr(universe)
                .chain_err(|| "Failed to convert universe to IPv4 multicast addr")?;
        } else {
            multicast_addr = universe_to_ipv6_multicast_addr(universe)
                .chain_err(|| "Failed to convert universe to IPv6 multicast addr")?;
        }

        Ok(join_win_multicast(&self.socket, multicast_addr)?)
    }

    /// Removes this SacnNetworkReceiver from the multicast group which corresponds to the given universe.
    ///
    /// # Errors
    /// Will return an Error if the given universe cannot be converted to an Ipv4 or Ipv6 multicast_addr depending on if the Receiver is bound to an
    /// IPv4 or IPv6 address. See packet::universe_to_ipv4_multicast_addr and packet::universe_to_ipv6_multicast_addr.
    ///
    pub fn mute_multicast_universe(&mut self, universe: u16) -> Result<()> {
        let multicast_addr;

        if self.addr.is_ipv4() {
            multicast_addr = universe_to_ipv4_multicast_addr(universe)
                .chain_err(|| "Failed to convert universe to IPv4 multicast addr")?;
        } else {
            multicast_addr = universe_to_ipv6_multicast_addr(universe)
                .chain_err(|| "Failed to convert universe to IPv6 multicast addr")?;
        }

        Ok(leave_win_multicast(&self.socket, multicast_addr)?)
    }

    /// Sets the value of the is_multicast_enabled flag to the given value.
    ///
    /// If set to false then the receiver won't attempt to join any more multicast groups.
    ///
    /// This method does not attempt to leave multicast groups already joined through previous listen_universe calls.
    ///
    /// # Arguments
    /// val: The new value for the is_multicast_enabled flag.
    ///
    /// # Errors
    /// Will return an OsOperationUnsupported error if attempting to set the flag to true in an environment that multicast
    /// isn't supported i.e. Ipv6 on Windows.
    pub fn set_is_multicast_enabled(&mut self, val: bool) -> Result<()> {
        if val && self.is_ipv6() {
            bail!(ErrorKind::OsOperationUnsupported(
                "IPv6 multicast is currently unsupported on Windows".to_string()
            ));
        }
        self.is_multicast_enabled = val;
        Ok(())
    }

    /// Returns true if multicast is enabled on this receiver and false if not.
    /// This flag is set when the receiver is created as not all environments currently support IP multicast.
    /// E.g. IPv6 Windows IP Multicast is currently unsupported.
    pub fn is_multicast_enabled(&self) -> bool {
        return self.is_multicast_enabled;
    }

    /// If set to true then only receive over IPv6. If false then receiving will be over both IPv4 and IPv6.
    /// This will return an error if the SacnReceiver wasn't created using an IPv6 address to bind to.
    pub fn set_only_v6(&mut self, val: bool) -> Result<()> {
        if self.addr.is_ipv4() {
            bail!(IpVersionError(
                "No data available in given timeout".to_string()
            ))
        } else {
            Ok(self.socket.set_only_v6(val)?)
        }
    }

    /// Returns a packet if there is one available.
    ///
    /// The packet may not be ready to transmit if it is awaiting synchronisation.
    /// Will only block if set_timeout was called with a timeout of None so otherwise (and by default) it won't
    /// block so may return a WouldBlock/TimedOut error to indicate that there was no data ready.
    ///
    /// IMPORTANT NOTE:
    /// An explicit lifetime is given to the AcnRootLayerProtocol which comes from the lifetime of the given buffer.
    /// The compiler will prevent usage of the returned AcnRootLayerProtocol after the buffer is dropped normally but may not in the case
    /// of unsafe code .
    ///
    /// Arguments:
    /// buf: The buffer to use for storing the received data into. This buffer shouldn't be accessed or used directly as the data
    /// is returned formatted properly in the AcnRootLayerProtocol. This buffer is used as memory space for the returned AcnRootLayerProtocol.
    ///
    /// # Errors
    /// May return an error if there is an issue receiving data from the underlying socket, see (recv)[fn.recv.Socket].
    ///
    /// May return an error if there is an issue parsing the data from the underlying socket, see (parse)[fn.AcnRootLayerProtocol::parse.packet].
    ///
    pub fn recv<'a>(
        &self,
        buf: &'a mut [u8; RCV_BUF_DEFAULT_SIZE],
    ) -> Result<AcnRootLayerProtocol<'a>> {
        self.socket.recv(&mut buf[0..])?;

        Ok(AcnRootLayerProtocol::parse(buf)?)
    }

    /// Set the timeout for the recv operation.
    ///
    /// Arguments:
    /// timeout: The new timeout for the receive operation, a value of None means the recv operation will become blocking.
    ///
    /// Errors:
    /// A timeout with Duration 0 will cause an error. See (set_read_timeout)[fn.set_read_timeout.Socket].
    ///
    pub fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        Ok(self.socket.set_read_timeout(timeout)?)
    }

    /// Returns true if this SacnNetworkReceiver is bound to an Ipv6 address.
    pub fn is_ipv6(&self) -> bool {
        return self.addr.is_ipv6();
    }
}

/// Windows and linux handle multicast sockets differently.
/// This is built for / tested with Fedora 30/31.
#[cfg(target_os = "linux")]
impl SacnNetworkReceiver {
    /// Creates a new DMX receiver on the interface specified by the given address.
    ///
    /// If the given address is an IPv4 address then communication will only work between IPv4 devices, if the given address is IPv6 then communication
    /// will only work between IPv6 devices by default but IPv4 receiving can be enabled using set_ipv6_only(false).
    ///
    /// # Errors
    /// Will return an Io error if the SacnReceiver fails to bind to a socket with the given ip.
    /// For more details see socket2::Socket::new().
    ///
    pub fn new(ip: SocketAddr) -> Result<SacnNetworkReceiver> {
        Ok(SacnNetworkReceiver {
            socket: create_unix_socket(ip)?,
            addr: ip,
            is_multicast_enabled: true, // Linux IP Multicast is supported for Ipv4 and Ipv6.
        })
    }

    /// Connects this SacnNetworkReceiver to the multicast address which corresponds to the given universe to allow receiving packets for that universe.
    ///
    /// # Errors
    /// Will return an Error if the given universe cannot be converted to an IPv4 or IPv6 multicast_addr depending on if the Receiver is bound to an
    /// IPv4 or IPv6 address. See packet::universe_to_ipv4_multicast_addr and packet::universe_to_ipv6_multicast_addr.
    ///
    /// Will return an Io error if cannot join the universes corresponding multicast group address.
    ///
    pub fn listen_multicast_universe(&self, universe: u16) -> Result<()> {
        let multicast_addr;

        if self.addr.is_ipv4() {
            multicast_addr = universe_to_ipv4_multicast_addr(universe)
                .chain_err(|| "Failed to convert universe to IPv4 multicast addr")?;
        } else {
            multicast_addr = universe_to_ipv6_multicast_addr(universe)
                .chain_err(|| "Failed to convert universe to IPv6 multicast addr")?;
        }

        Ok(join_unix_multicast(
            &self.socket,
            multicast_addr,
            self.addr.ip(),
        )?)
    }

    /// Removes this SacnNetworkReceiver from the multicast group which corresponds to the given universe.
    ///
    /// # Errors
    /// Will return an Error if the given universe cannot be converted to an Ipv4 or Ipv6 multicast_addr depending on if the Receiver is bound to an
    /// IPv4 or IPv6 address. See packet::universe_to_ipv4_multicast_addr and packet::universe_to_ipv6_multicast_addr.
    ///
    pub fn mute_multicast_universe(&mut self, universe: u16) -> Result<()> {
        let multicast_addr;

        if self.addr.is_ipv4() {
            multicast_addr = universe_to_ipv4_multicast_addr(universe)
                .chain_err(|| "Failed to convert universe to IPv4 multicast addr")?;
        } else {
            multicast_addr = universe_to_ipv6_multicast_addr(universe)
                .chain_err(|| "Failed to convert universe to IPv6 multicast addr")?;
        }

        Ok(leave_unix_multicast(
            &self.socket,
            multicast_addr,
            self.addr.ip(),
        )?)
    }

    /// Sets the value of the is_multicast_enabled flag to the given value.
    ///
    /// If set to false then the receiver won't attempt to join any more multicast groups.
    ///
    /// This method does not attempt to leave multicast groups already joined through previous listen_universe calls.
    ///
    /// # Arguments
    /// val: The new value for the is_multicast_enabled flag.
    ///
    /// # Errors
    /// Will return an OsOperationUnsupported error if attempting to set the flag to true in an environment that multicast
    /// isn't supported i.e. Ipv6 on Windows. Note that this is the UNIX implementation
    pub fn set_is_multicast_enabled(&mut self, val: bool) -> Result<()> {
        self.is_multicast_enabled = val;
        Ok(())
    }

    /// Returns true if multicast is enabled on this receiver and false if not.
    /// This flag is set when the receiver is created as not all environments currently support IP multicast.
    /// E.g. IPv6 Windows IP Multicast is currently unsupported.
    pub fn is_multicast_enabled(&self) -> bool {
        return self.is_multicast_enabled;
    }

    /// If set to true then only receive over IPv6. If false then receiving will be over both IPv4 and IPv6.
    /// This will return an error if the SacnReceiver wasn't created using an IPv6 address to bind to.
    pub fn set_only_v6(&mut self, val: bool) -> Result<()> {
        if self.addr.is_ipv4() {
            bail!(IpVersionError(
                "No data available in given timeout".to_string()
            ))
        } else {
            Ok(self.socket.set_only_v6(val)?)
        }
    }

    /// Returns a packet if there is one available.
    ///
    /// The packet may not be ready to transmit if it is awaiting synchronisation.
    /// Will only block if set_timeout was called with a timeout of None so otherwise (and by default) it won't
    /// block so may return a WouldBlock/TimedOut error to indicate that there was no data ready.
    ///
    /// IMPORTANT NOTE:
    /// An explicit lifetime is given to the AcnRootLayerProtocol which comes from the lifetime of the given buffer.
    /// The compiler will prevent usage of the returned AcnRootLayerProtocol after the buffer is dropped.
    ///
    /// Arguments:
    /// buf: The buffer to use for storing the received data into. This buffer shouldn't be accessed or used directly as the data
    /// is returned formatted properly in the AcnRootLayerProtocol. This buffer is used as memory space for the returned AcnRootLayerProtocol.
    ///
    /// # Errors
    /// May return an error if there is an issue receiving data from the underlying socket, see (recv)[fn.recv.Socket].
    ///
    /// May return an error if there is an issue parsing the data from the underlying socket, see (parse)[fn.AcnRootLayerProtocol::parse.packet].
    ///
    pub fn recv<'a>(
        &self,
        buf: &'a mut [u8; RCV_BUF_DEFAULT_SIZE],
    ) -> Result<AcnRootLayerProtocol<'a>> {
        self.socket.recv(&mut buf[0..])?;

        Ok(AcnRootLayerProtocol::parse(buf)?)
    }

    /// Set the timeout for the recv operation.
    ///
    /// Arguments:
    /// timeout: The new timeout for the receive operation, a value of None means the recv operation will become blocking.
    ///
    /// Errors:
    /// A timeout with Duration 0 will cause an error. See (set_read_timeout)[fn.set_read_timeout.Socket].
    ///
    pub fn set_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        Ok(self.socket.set_read_timeout(timeout)?)
    }
}


/// Creates a new Socket2 socket bound to the given address.
///
/// Returns the created socket.
///
/// Arguments:
/// addr: The address that the newly created socket should bind to.
///
/// # Errors
/// Will return an error if the socket cannot be created, see (Socket::new)[fn.new.Socket].
///
/// Will return an error if the socket cannot be bound to the given address, see (bind)[fn.bind.Socket2].
#[cfg(target_os = "linux")]
fn create_unix_socket(addr: SocketAddr) -> Result<Socket> {
    if addr.is_ipv4() {
        let socket = Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp()))?;

        // Multiple different processes might want to listen to the sACN stream so therefore need to allow re-using the ACN port.
        socket.set_reuse_port(true)?;
        socket.set_reuse_address(true)?;

        let socket_addr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), ACN_SDT_MULTICAST_PORT);
        socket.bind(&socket_addr.into())?;
        Ok(socket)
    } else {
        let socket = Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp()))?;

        // Multiple different processes might want to listen to the sACN stream so therefore need to allow re-using the ACN port.
        socket.set_reuse_port(true)?;
        socket.set_reuse_address(true)?;

        let socket_addr =
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), ACN_SDT_MULTICAST_PORT);
        socket.bind(&socket_addr.into())?;
        Ok(socket)
    }
}

/// Joins the multicast group with the given address using the given socket.
///
/// Arguments:
/// socket: The socket to join to the multicast group.
/// addr:   The address of the multicast group to join.
///
/// # Errors
/// Will return an error if the given socket cannot be joined to the given multicast group address.
///     See join_multicast_v4[fn.join_multicast_v4.Socket] and join_multicast_v6[fn.join_multicast_v6.Socket]
///
/// Will return an IpVersionError if addr and interface_addr are not the same IP version.
///
#[cfg(target_os = "linux")]
fn join_unix_multicast(socket: &Socket, addr: SockAddr, interface_addr: IpAddr) -> Result<()> {
    match addr.family() as i32 {
        // Cast required because AF_INET is defined in libc in terms of a c_int (i32) but addr.family returns using u16.
        AF_INET => match addr.as_inet() {
            Some(a) => match interface_addr {
                IpAddr::V4(ref interface_v4) => {
                    socket
                        .join_multicast_v4(a.ip(), &interface_v4)
                        .chain_err(|| "Failed to join IPv4 multicast")?;
                }
                IpAddr::V6(ref _interface_v6) => {
                    bail!(ErrorKind::IpVersionError(
                        "Multicast address and interface_addr not same IP version".to_string()
                    ));
                }
            },
            None => {
                bail!(ErrorKind::UnsupportedIpVersion("IP version recognised as AF_INET but not actually usable as AF_INET so must be unknown type".to_string()));
            }
        },
        AF_INET6 => match addr.as_inet6() {
            Some(a) => {
                socket
                    .join_multicast_v6(a.ip(), 0)
                    .chain_err(|| "Failed to join IPv6 multicast")?;
            }
            None => {
                bail!(ErrorKind::UnsupportedIpVersion("IP version recognised as AF_INET6 but not actually usable as AF_INET6 so must be unknown type".to_string()));
            }
        },
        x => {
            bail!(ErrorKind::UnsupportedIpVersion(format!("IP version not recognised as AF_INET (Ipv4) or AF_INET6 (Ipv6) - family value (as i32): {}", x).to_string()));
        }
    };

    Ok(())
}

/// Leaves the multicast group with the given address using the given socket.
///
/// Arguments:
/// socket: The socket to leave the multicast group.
/// addr:   The address of the multicast group to leave.
///
/// # Errors
/// Will return an error if the given socket cannot leave the given multicast group address.
///     See leave_multicast_v4[fn.leave_multicast_v4.Socket] and leave_multicast_v6[fn.leave_multicast_v6.Socket]
///
/// Will return an IpVersionError if addr and interface_addr are not the same IP version.
///
#[cfg(target_os = "linux")]
fn leave_unix_multicast(socket: &Socket, addr: SockAddr, interface_addr: IpAddr) -> Result<()> {
    match addr.family() as i32 {
        // Cast required because AF_INET is defined in libc in terms of a c_int (i32) but addr.family returns using u16.
        AF_INET => match addr.as_inet() {
            Some(a) => match interface_addr {
                IpAddr::V4(ref interface_v4) => {
                    socket
                        .leave_multicast_v4(a.ip(), &interface_v4)
                        .chain_err(|| "Failed to leave IPv4 multicast")?;
                }
                IpAddr::V6(ref _interface_v6) => {
                    bail!(ErrorKind::IpVersionError(
                        "Multicast address and interface_addr not same IP version".to_string()
                    ));
                }
            },
            None => {
                bail!(ErrorKind::UnsupportedIpVersion("IP version recognised as AF_INET but not actually usable as AF_INET so must be unknown type".to_string()));
            }
        },
        AF_INET6 => match addr.as_inet6() {
            Some(a) => {
                socket
                    .leave_multicast_v6(a.ip(), 0)
                    .chain_err(|| "Failed to leave IPv6 multicast")?;
            }
            None => {
                bail!(ErrorKind::UnsupportedIpVersion("IP version recognised as AF_INET6 but not actually usable as AF_INET6 so must be unknown type".to_string()));
            }
        },
        x => {
            bail!(ErrorKind::UnsupportedIpVersion(format!("IP version not recognised as AF_INET (Ipv4) or AF_INET6 (Ipv6) - family value (as i32): {}", x).to_string()));
        }
    };

    Ok(())
}

/// Creates a new Socket2 socket bound to the given address.
///
/// Returns the created socket.
///
/// Arguments:
/// addr: The address that the newly created socket should bind to.
///
/// # Errors
/// Will return an error if the socket cannot be created, see (Socket::new)[fn.new.Socket].
///
/// Will return an error if the socket cannot be bound to the given address, see (bind)[fn.bind.Socket].
#[cfg(target_os = "windows")]
fn create_win_socket(addr: SocketAddr) -> Result<Socket> {
    if addr.is_ipv4() {
        let socket = Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp()))?;

        socket.set_reuse_address(true)?;
        socket.bind(&SockAddr::from(addr))?;
        Ok(socket)
    } else {
        let socket = Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp()))?;

        socket.set_reuse_address(true)?;
        socket.bind(&SockAddr::from(addr))?;
        Ok(socket)
    }
}

/// Joins the multicast group with the given address using the given socket on the windows operating system.
///
/// Note that Ipv6 is currently unsupported.
///
/// Arguments:
/// socket: The socket to join to the multicast group.
/// addr:   The address of the multicast group to join.
///
/// # Errors
/// Will return an error if the given socket cannot be joined to the given multicast group address.
///     See join_multicast_v4[fn.join_multicast_v4.Socket] and join_multicast_v6[fn.join_multicast_v6.Socket]
///
/// Will return OsOperationUnsupported error if attempt to leave an Ipv6 multicast group as all Ipv6 multicast operations are currently unsupported in Rust on Windows.
///
#[cfg(target_os = "windows")]
fn join_win_multicast(socket: &Socket, addr: SockAddr) -> Result<()> {
    match addr.family() as i32 {
        // Cast required because AF_INET is defined in libc in terms of a c_int (i32) but addr.family returns using u16.
        AF_INET => match addr.as_inet() {
            Some(a) => {
                socket
                    .join_multicast_v4(a.ip(), &Ipv4Addr::new(0, 0, 0, 0))
                    .chain_err(|| "Failed to join IPv4 multicast")?;
            }
            None => {
                bail!(ErrorKind::UnsupportedIpVersion("IP version recognised as AF_INET but not actually usable as AF_INET so must be unknown type".to_string()));
            }
        },
        AF_INET6 => match addr.as_inet6() {
            Some(_) => {
                bail!(ErrorKind::OsOperationUnsupported(
                    "IPv6 multicast is currently unsupported on Windows".to_string()
                ));
            }
            None => {
                bail!(ErrorKind::UnsupportedIpVersion("IP version recognised as AF_INET6 but not actually usable as AF_INET6 so must be unknown type".to_string()));
            }
        },
        x => {
            bail!(ErrorKind::UnsupportedIpVersion(format!("IP version not recognised as AF_INET (Ipv4) or AF_INET6 (Ipv6) - family value (as i32): {}", x).to_string()));
        }
    };

    Ok(())
}

/// Leaves the multicast group with the given address using the given socket.
///
/// Note that Ipv6 is currently unsupported.
///
/// Arguments:
/// socket: The socket to leave the multicast group.
/// addr:   The address of the multicast group to leave.
///
/// # Errors
/// Will return an error if the given socket cannot leave the given multicast group address.
///     See leave_multicast_v4[fn.leave_multicast_v4.Socket] and leave_multicast_v6[fn.leave_multicast_v6.Socket]
///
/// Will return OsOperationUnsupported error if attempt to leave an Ipv6 multicast group as all Ipv6 multicast operations are currently unsupported in Rust on Windows.
///
#[cfg(target_os = "windows")]
fn leave_win_multicast(socket: &Socket, addr: SockAddr) -> Result<()> {
    match addr.family() as i32 {
        // Cast required because AF_INET is defined in libc in terms of a c_int (i32) but addr.family returns using u16.
        AF_INET => match addr.as_inet() {
            Some(a) => {
                socket
                    .leave_multicast_v4(a.ip(), &Ipv4Addr::new(0, 0, 0, 0))
                    .chain_err(|| "Failed to leave IPv4 multicast")?;
            }
            None => {
                bail!(ErrorKind::UnsupportedIpVersion("IP version recognised as AF_INET but not actually usable as AF_INET so must be unknown type".to_string()));
            }
        },
        AF_INET6 => match addr.as_inet6() {
            Some(_) => {
                bail!(ErrorKind::OsOperationUnsupported(
                    "IPv6 multicast is currently unsupported on Windows".to_string()
                ));
            }
            None => {
                bail!(ErrorKind::UnsupportedIpVersion("IP version recognised as AF_INET6 but not actually usable as AF_INET6 so must be unknown type".to_string()));
            }
        },
        x => {
            bail!(ErrorKind::UnsupportedIpVersion(format!("IP version not recognised as AF_INET (Ipv4) or AF_INET6 (Ipv6) - family value (as i32): {}", x).to_string()));
        }
    };

    Ok(())
}
