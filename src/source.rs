#![warn(missing_docs)]

// Copyright 2020 sacn Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
//
// This file was modified as part of a University of St Andrews Computer Science BSC Senior Honours Dissertation Project.
//
// Documentation of private or crate local items that effects public items, such as errors from private functions which get passed up to a
// public function, should be copied into the documentation of the public item so that the public facing documentation is a complete documentation
// of each public item without relying on referring to private items.
//

use crate::error::errors::*;
use crate::net::std_net::StdSourceNet;
use crate::net::{IpVersion, PendingSend, SacnSourceNet, SendDestination};
use crate::packet::*;

use std::cmp::min;
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// UUID library used to handle the UUID's used in the CID fields.
use uuid::Uuid;

/// The name of the thread which runs periodically to perform various actions such as universe discovery adverts for the source.
const SEND_UPDATE_THREAD_NAME: &str = "rust_sacn_send_update_thread";

/// The default startcode used to send stream termination packets when the `SacnSource` is closed.
const DEFAULT_TERMINATE_START_CODE: u8 = 0;

/// The poll rate of the update thread.
/// Discovery updates are sent every `E131_UNIVERSE_DISCOVERY_INTERVAL` so the poll rate must be lower than or equal to this.
// const DEFAULT_POLL_PERIOD: Duration = E131_UNIVERSE_DISCOVERY_INTERVAL;
const DEFAULT_POLL_PERIOD: Duration = Duration::from_secs(1);

/// Holds the per-universe mutable state for an sACN source.
#[derive(Debug, Clone)]
struct SourceUniverseState {
    /// Next sequence number for data packets on this universe.
    data_seq: u8,
    /// Next sequence number for synchronisation packets on this universe.
    sync_seq: u8,
    /// indices of the interfaces on which this universe should be sent
    netint_idx: u32,
}

impl SourceUniverseState {
    fn new(netint_indices: u32) -> Self {
        Self {
            data_seq: STARTING_SEQUENCE_NUMBER,
            sync_seq: STARTING_SEQUENCE_NUMBER,
            netint_idx: netint_indices,
        }
    }

    /// Advance and return the *current* data sequence number, wrapping at 255.
    fn next_data_seq(&mut self) -> u8 {
        let seq = self.data_seq;
        self.data_seq = self.data_seq.wrapping_add(1);
        seq
    }

    /// Advance and return the *current* sync sequence number, wrapping at 255.
    fn next_sync_seq(&mut self) -> u8 {
        let seq = self.sync_seq;
        self.sync_seq = self.sync_seq.wrapping_add(1);
        seq
    }
}

// ---------------------------------------------------------------------------
// Packet builders (pure functions — no socket, no state mutation)
// ---------------------------------------------------------------------------

/// Builds and packs an sACN data packet into an allocated `Vec<u8>`.
///
/// # Arguments
/// * `cid`               – Source CID.
/// * `name`              – Source name string.
/// * `universe`          – Target universe.
/// * `data`              – DMX payload (start-code inclusive).
/// * `priority`          – E1.31 priority (0–200).
/// * `sequence_number`   – Packet sequence number.
/// * `sync_address`      – Synchronisation universe (0 = no sync).
/// * `preview_data`      – Preview-data flag.
/// * `stream_terminated` – Stream-terminated flag.
#[allow(clippy::too_many_arguments)]
fn build_data_packet(
    cid: Uuid,
    name: &str,
    universe: u16,
    data: &[u8],
    priority: u8,
    sequence_number: u8,
    sync_address: u16,
    preview_data: bool,
    stream_terminated: bool,
    force_synchronization: bool,
) -> Result<Vec<u8>> {
    let packet = AcnRootLayerProtocol {
        pdu: E131RootLayer {
            cid,
            data: E131RootLayerData::DataPacket(DataPacketFramingLayer {
                source_name: name.into(),
                priority,
                synchronization_address: sync_address,
                sequence_number,
                preview_data,
                stream_terminated,
                force_synchronization,
                universe,
                data: DataPacketDmpLayer {
                    property_values: {
                        let mut v = Vec::with_capacity(data.len());
                        v.extend_from_slice(data);
                        v.into()
                    },
                },
            }),
        },
    };
    packet.pack_alloc()
}

/// Builds and packs an sACN synchronisation packet into an allocated `Vec<u8>`.
///
/// # Arguments
/// * `cid`             – Source CID.
/// * `universe`        – Synchronisation universe.
/// * `sequence_number` – Packet sequence number.
fn build_sync_packet(cid: Uuid, universe: u16, sequence_number: u8) -> Result<Vec<u8>> {
    let packet = AcnRootLayerProtocol {
        pdu: E131RootLayer {
            cid,
            data: E131RootLayerData::SynchronizationPacket(SynchronizationPacketFramingLayer {
                sequence_number,
                synchronization_address: universe,
            }),
        },
    };
    packet.pack_alloc()
}

/// Builds and packs an sACN universe discovery packet page into an allocated `Vec<u8>`.
///
/// # Arguments
/// * `cid`       – Source CID.
/// * `name`      – Source name string.
/// * `page`      – Current page number.
/// * `last_page` – Last page number for this discovery cycle.
/// * `universes` – Slice of universe numbers to include on this page.
fn build_discovery_packet(
    cid: Uuid,
    name: &str,
    page: u8,
    last_page: u8,
    universes: &[u16],
) -> Result<Vec<u8>> {
    let packet = AcnRootLayerProtocol {
        pdu: E131RootLayer {
            cid,
            data: E131RootLayerData::UniverseDiscoveryPacket(UniverseDiscoveryPacketFramingLayer {
                source_name: name.into(),
                data: UniverseDiscoveryPacketUniverseDiscoveryLayer {
                    page,
                    last_page,
                    universes: universes.into(),
                },
            }),
        },
    };
    packet.pack_alloc()
}

/// A DMX over sACN sender.
///
/// `SacnSource` is used for sending sACN packets over an IP network.
///
/// # Examples
///
/// ```no_run
/// // Example showing creation of a source and then sending some data.
/// use sacn::source::SacnSource;
/// use sacn::packet::ACN_SDT_MULTICAST_PORT;
/// use std::net::{IpAddr, SocketAddr};
///
/// let local_addr: SocketAddr = SocketAddr::new(IpAddr::V4("0.0.0.0".parse().unwrap()), ACN_SDT_MULTICAST_PORT + 1);
///
/// let mut src = SacnSource::with_ip("Source", local_addr).unwrap();
///
/// let universe: u16 = 1;                        // Universe the data is to be sent on.
/// let sync_uni: Option<u16> = None;             // Don't want the packet to be delayed on the receiver awaiting synchronisation.
/// let priority: u8 = 100;                       // The priority for the sending data, must be 1-200 inclusive,  None means use default.
/// let dst_ip: Option<SocketAddr> = None;        // Sending the data using IP multicast so don't have a destination IP.
///
/// src.register_universe(universe).unwrap(); // Register with the source that will be sending on the given universe.
///
/// let mut data: Vec<u8> = vec![0, 0, 0, 0, 255, 255, 128, 128]; // Some arbitrary data, must have length <= 513 (including start-code).
///
/// src.send(&[universe], &data, Some(priority), dst_ip, sync_uni).unwrap(); // Actually send the data
/// ```
///
/// An ANSI E1.31-2018 sACN source.
///
/// Allows sending DMX data over an IPv4 or IPv6 network using sACN.
#[derive(Debug)]
pub struct SacnSource<N: SacnSourceNet + 'static = StdSourceNet> {
    /// The DMX source used for actually sending the sACN packets.
    /// Protected by a Mutex lock to allow concurrent access between user threads and the update thread below.
    internal: Arc<Mutex<SacnSourceInternal<N>>>,

    /// Update thread which performs actions every `DEFAULT_POLL_PERIOD` such as checking if a universe
    /// discovery packet should be sent.
    update_thread: Option<JoinHandle<()>>,
}

/// Convenience alias for the common case of using the standard UDP backend.
pub type SacnSourceStd = SacnSource<StdSourceNet>;

/// Internal sACN sender. Thin runtime wrapper around [`SacnSourceCore`] and a
/// [`SacnNet`] backend. All protocol logic lives in the core; this struct is
/// responsible only for driving the core and dispatching the resulting
/// [`PendingSend`]s through the network backend.
#[derive(Debug)]
struct SacnSourceInternal<N: SacnSourceNet> {
    /// Pure protocol state machine
    core: SacnSourceCore,

    /// Pluggable network backend — owns sockets and dispatches datagrams.
    net: N,
}

impl SacnSource<StdSourceNet> {
    /// Constructs a new `SacnSource` with the given name, binding to an IPv4 address.
    /// This generates a new CID automatically using random values.
    ///
    /// # Errors
    /// See (`with_cid_ip`)[`with_cid_ip`]
    pub fn new_v4(name: &str) -> Result<SacnSource<StdSourceNet>> {
        SacnSource::with_cid_v4(name, Uuid::new_v4())
    }

    /// Constructs a new `SacnSource` with the given name and specified CID binding to an IPv4 address.
    ///
    /// # Errors
    /// See (`with_cid_ip`)[`with_cid_ip`]
    pub fn with_cid_v4(name: &str, cid: Uuid) -> Result<SacnSource<StdSourceNet>> {
        let ip = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), ACN_SDT_MULTICAST_PORT);
        SacnSource::with_cid_ip(name, cid, ip)
    }

    /// Constructs a new `SacnSource` with the given name, binding to an IPv6 address.
    /// By default this will only receive IPv6 data but IPv4 can also be enabled by calling `set_ipv6_only(false)`.
    ///
    /// # Errors
    /// See (`with_cid_ip`)[`with_cid_ip`]
    pub fn new_v6(name: &str) -> Result<SacnSource<StdSourceNet>> {
        SacnSource::with_cid_v6(name, Uuid::new_v4())
    }

    /// Constructs a new `SacnSource` with the given name and specified CID binding to an IPv6 address.
    ///
    /// # Errors
    /// See (`with_cid_ip`)[`with_cid_ip`]
    pub fn with_cid_v6(name: &str, cid: Uuid) -> Result<SacnSource<StdSourceNet>> {
        let ip = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), ACN_SDT_MULTICAST_PORT);
        SacnSource::with_cid_ip(name, cid, ip)
    }

    /// Constructs a new `SacnSource` with the given name and binding to the supplied ip.
    ///
    /// # Errors
    /// See (`with_cid_ip`)[`with_cid_ip`]
    pub fn with_ip(name: &str, ip: SocketAddr) -> Result<SacnSource<StdSourceNet>> {
        SacnSource::with_cid_ip(name, Uuid::new_v4(), ip)
    }

    /// Constructs a new `SacnSource` with the given name, cid and binding to the supplied ip.
    ///
    /// # Errors
    /// Io: Returned if the underlying UDP socket cannot be created and bound or if the thread used for sending periodic
    ///     discovery adverts fails to be created. Causes can be distinguished by looking at the error chain.
    ///
    /// `UnsupportedIpVersion`: Returned if the `SocketAddr` is not IPv4 or IPv6.
    ///
    /// `MalformedSourceName`: Returned if the given source name is longer than the maximum allowed size of `E131_SOURCE_NAME_FIELD_LENGTH`.
    pub fn with_cid_ip(name: &str, cid: Uuid, ip: SocketAddr) -> Result<SacnSource<StdSourceNet>> {
        if name.len() > E131_SOURCE_NAME_FIELD_LENGTH {
            return Err(SacnError::MalformedSourceName(
                "Source name provided is longer than maximum allowed".to_string(),
            ));
        }
        let net = StdSourceNet::new(ip)?;
        SacnSource::with_net(name, cid, net)
    }
}

impl<N: SacnSourceNet + 'static + Debug> SacnSource<N> {
    /// Constructs a new `SacnSource` with the given name, cid and a custom
    /// [`SacnSourceNet`] backend.
    ///
    /// This is the primary constructor when using an alternative network
    /// backend (e.g. a test double or user provided).
    ///
    /// # Errors
    /// `MalformedSourceName`: Returned if the given source name is longer than the maximum allowed size of `E131_SOURCE_NAME_FIELD_LENGTH`.
    ///
    /// `Io`: Returned if the update thread fails to spawn.
    pub fn with_net(name: &str, cid: Uuid, net: N) -> Result<SacnSource<N>> {
        if name.len() > E131_SOURCE_NAME_FIELD_LENGTH {
            return Err(SacnError::MalformedSourceName(
                "Source name provided is longer than maximum allowed".to_string(),
            ));
        }

        let core = SacnSourceCore::new(cid, name, net.ip_version());
        let internal = SacnSourceInternal::new(core, net);
        let internal_arc = Arc::new(Mutex::new(internal));
        let mut trd_src = internal_arc.clone();

        let trd_builder = thread::Builder::new().name(SEND_UPDATE_THREAD_NAME.into());

        let src = SacnSource {
            internal: internal_arc,
            update_thread: Some(trd_builder.spawn(move || {
                while trd_src.lock().unwrap().running() {
                    thread::sleep(DEFAULT_POLL_PERIOD);
                    if let Err(e) = perform_periodic_update(&mut trd_src) {
                        println!("Periodic error: {e:?}");
                    } else {
                        // In-case of an error on the discovery thread the source continues to operate and tries again.
                        // As no unsafe code blocks are used the rust compiler guarantees this is memory safe.
                    }
                }
            })?),
        };
        Ok(src)
    }

    /// Sets the network interface on which the given universe will be sent.
    ///
    /// `idx` refers to a position within the interface list returned by
    /// `net.enumerate_netints()`. By default each universe sends on interface
    /// index 0 only, matching the behaviour of a single-socket implementation.
    ///
    /// # Errors
    /// `UniverseNotRegistered`
    /// `SourceCorrupt`
    pub fn set_universe_netint(&mut self, universe: u16, netint: IpAddr) -> Result<()> {
        unlock_internal_mut(&mut self.internal)?.set_universe_netint(universe, netint)
    }

    /// Returns the number of network interfaces available to this source.
    ///
    /// # Errors
    /// `SourceCorrupt`
    pub fn netint_count(&self) -> Result<usize> {
        Ok(unlock_internal(&self.internal)?
            .net
            .enumerate_netints()
            .len())
    }

    /// Returns the network interfaces available to this source.
    ///
    /// # Errors  
    /// `SourceCorrupt`
    pub fn netints(&self) -> Result<Vec<crate::net::NetIntId>> {
        Ok(unlock_internal(&self.internal)?
            .net
            .enumerate_netints()
            .to_vec())
    }

    /// Registers the given universes on this source in addition to already registered universes.
    ///
    /// This allows sending data to those universes or using them as synchronisation addresses as well as adding them to
    /// the list of universes that appear in universe discovery packets that are sent (depending on the
    /// `set_is_sending_discovery` flag) periodically.
    ///
    /// This is more efficient than repeated calls to `register_universe` as it means only 1 mutex unlock is required.
    ///
    /// # Arguments
    /// universes: The sACN universes to register for usage as data universes and/or synchronisation addresses. Note that sACN
    ///     universes start at 1 not 0.
    ///
    /// # Errors
    /// `IllegalUniverse`: Returned if a universe is outwith the range permitted by ANSI E1.31-2018.
    ///
    /// `SourceCorrupt`: Returned if the Mutex used to control access to the internal sender is poisoned by a thread encountering
    /// a panic while accessing causing the source to be left in a potentially inconsistent state.
    pub fn register_universes(&mut self, universes: &[u16]) -> Result<()> {
        unlock_internal_mut(&mut self.internal)?.register_universes(universes)
    }

    /// Registers a single universe on this source in addition to already registered universes.
    ///
    /// This allows sending data to those universes or using them as synchronisation addresses as well as adding them to
    /// the list of universes that appear in universe discovery packets that are sent (depending on the
    /// `set_is_sending_discovery` flag) periodically.
    ///
    /// If registering multiple universes see (`register_universes`)[`register_universes`].
    ///
    /// # Arguments
    /// universe: The sACN universe to register for usage as a data universe and/or synchronisation address. Note that sACN
    ///     universes start at 1 not 0.
    ///
    /// # Errors
    /// `IllegalUniverse`: Returned if the universe is outwith the range permitted by ANSI E1.31-2018.
    ///
    /// `SourceCorrupt`: Returned if the Mutex used to control access to the internal sender is poisoned by a thread encountering
    /// a panic while accessing causing the source to be left in a potentially inconsistent state.
    pub fn register_universe(&mut self, universe: u16) -> Result<()> {
        unlock_internal_mut(&mut self.internal)?.register_universe(universe)
    }

    /// Sends the given data to the given universes with the given priority, synchronisation address (universe) and destination ip.
    ///
    /// # Arguments
    ///
    /// universe:     The sACN universes that the data should be set on, the data will be split over these universes with each `UNIVERSE_CHANNEL_CAPACITY`
    ///                 sized chunk sent to the next universe.
    ///
    /// data:         The data that should be sent, must have a length greater than 0.
    ///
    /// priority:     The E131 priority that the data should be sent with, must be less than `E131_MAX_PRIORITY` (`const.E131_MAX_PRIORITY.packet`),
    ///                 if a value of None is provided then the default of `E131_DEFAULT_PRIORITY` (`const.E131_DEFAULT_PRIORITY.packet`) is used.
    ///
    /// `dst_ip`:       The destination IP, can be Ipv4 or Ipv6, None if should be sent using ip multicast.
    ///
    /// `sync_address`: The address to use for synchronisation, must be a valid universe, None indicates no synchronisation. If synchronisation is required a
    ///                 reasonable default address to use is the first universe that this data is being sent to.
    ///
    /// As per ANSI E1.31-2018 Section 6.6.1 this method shouldn't be called at a higher refresher rate than specified in ANSI E1.11 [DMX] unless
    ///     configured by the user to do so in an environment which doesn't contain any E1.31 to DMX512-A converters.
    ///
    /// Note as per ANSI-E1.31-2018 Appendix B.1 it is recommended to have a small delay before sending the follow up sync packet.
    ///
    /// # Errors
    /// `SenderAlreadyTerminated`: Returned if this method is called on an `SacnSourceInternal` that has already terminated.
    ///
    /// `InvalidInput`: Returned if the data array has length 0 or if an insufficient number of universes for the given data are provided (each universe takes 513 bytes of data).
    ///
    /// `InvalidPriority`: Returned if the priority is greater than the allowed maximum priority of `E131_MAX_PRIORITY`.
    ///
    /// `IllegalUniverse`: Returned if the universe is outwith the allowed range as specified by ANSI E1.31-2018 Section 6.2.7.
    ///
    /// `UniverseNotRegistered`: Returned if the universe is not registered on the given `SacnSourceInternal`.
    ///
    /// `ExceedUniverseCapacity`: Returned if the data has a length greater than the maximum allowed within a universe (`packet::UNIVERSE_CHANNEL_CAPACITY`).
    ///
    /// Io: Returned if the data fails to be sent on the socket, see `send_to(fn.send_to.Socket)`.
    ///
    /// `SourceCorrupt`: Returned if the Mutex used to control access to the internal sender is poisoned by a thread encountering
    /// a panic while accessing causing the source to be left in a potentially inconsistent state.
    pub fn send(
        &mut self,
        universes: &[u16],
        data: &[u8],
        priority: Option<u8>,
        dst_ip: Option<SocketAddr>,
        synchronisation_addr: Option<u16>,
    ) -> Result<()> {
        unlock_internal_mut(&mut self.internal)?.send(
            universes,
            data,
            priority,
            dst_ip,
            synchronisation_addr,
        )
    }

    /// Sends a synchronisation packet to trigger the sending of packets waiting to be sent together.
    ///
    /// A common pattern would be to use the send method to send data to all the universes that should be synchronised using a
    /// chosen synchronisation universe then wait for a small time as per the recommendation in ANSI-E1.31-2018 Appendix B.1 and
    /// then send a synchronisation packet with the address of the synchronisation universe chosen to trigger the packets.
    ///
    /// # Arguments
    /// universe: The universe of this synchronisation packet.
    /// `dst_ip`:   The destination IP address for this packet or None if it should be sent using multicast.
    ///
    /// # Errors
    /// `IllegalUniverse`: Returned if the universe is outwith the allowed range of sACN universes as defined in ANSI E1.31-2018 Section 6.2.7.
    ///
    /// `UniverseNotRegistered`: Returned if the universe is not registered on the given `SacnSourceInternal`.
    ///
    /// Io: Returned if the packet fails to be sent using the underlying network socket.
    ///
    /// `SacnParsePackError`: Returned if the sync packet fails to be packed.
    ///
    /// `SourceCorrupt`: Returned if the Mutex used to control access to the internal sender is poisoned by a thread encountering
    /// a panic while accessing causing the source to be left in a potentially inconsistent state.
    pub fn send_sync_packet(&mut self, universe: u16, dst_ip: Option<SocketAddr>) -> Result<()> {
        unlock_internal_mut(&mut self.internal)?.send_sync_packet(universe, dst_ip)
    }

    /// Terminates sending on the given universe.
    ///
    /// # Errors:
    /// `IllegalUniverse`: Returned if the universe is outwith the allowed range of sACN universes as defined in ANSI E1.31-2018 Section 6.2.7.
    ///
    /// `UniverseNotRegistered`: Returned if the universe is not registered on this source.
    ///
    /// Io: Returned if the termination packets fail to be sent on the socket.
    ///
    /// `SourceCorrupt`: Returned if the Mutex used to control access to the internal sender is poisoned by a thread encountering
    /// a panic while accessing causing the source to be left in a potentially inconsistent state.
    pub fn terminate_stream(&mut self, universe: u16, start_code: u8) -> Result<()> {
        unlock_internal_mut(&mut self.internal)?.terminate_stream(universe, start_code)
    }

    /// Returns the ACN CID device identifier of the `SacnSourceInternal`.
    ///
    /// # Errors
    /// `SourceCorrupt`: Returned if the Mutex used to control access to the internal sender is poisoned by a thread encountering
    /// a panic while accessing causing the source to be left in a potentially inconsistent state.
    pub fn cid(&self) -> Result<Uuid> {
        Ok(*unlock_internal(&self.internal)?.cid())
    }

    /// Sets the ACN CID device identifier.
    ///
    /// # Arguments
    /// cid: The new CID identifier for this source. It is left to the user to ensure that this is always unique within the network the source is in.
    ///
    /// # Errors
    /// `SourceCorrupt`: Returned if the Mutex used to control access to the internal sender is poisoned by a thread encountering
    /// a panic while accessing causing the source to be left in a potentially inconsistent state.
    pub fn set_cid(&mut self, cid: Uuid) -> Result<()> {
        unlock_internal_mut(&mut self.internal)?.set_cid(cid);
        Ok(())
    }

    /// Returns the ACN source name.
    ///
    /// # Errors
    /// `SourceCorrupt`: Returned if the Mutex used to control access to the internal sender is poisoned by a thread encountering
    /// a panic while accessing causing the source to be left in a potentially inconsistent state.
    pub fn name(&self) -> Result<String> {
        Ok(unlock_internal(&self.internal)?.name().into())
    }

    /// Sets ACN source name.
    ///
    /// # Argument
    /// name: The new name for the source, it is left to the user to ensure this is unique within the sACN network.
    ///
    /// # Errors
    /// `SourceCorrupt`: Returned if the Mutex used to control access to the internal sender is poisoned by a thread encountering
    /// a panic while accessing causing the source to be left in a potentially inconsistent state.
    ///
    /// `MalformedSourceName`: Returned to indicate that the given source name is longer than the maximum allowed as per `E131_SOURCE_NAME_FIELD_LENGTH`.
    pub fn set_name(&mut self, name: &str) -> Result<()> {
        unlock_internal_mut(&mut self.internal)?.set_name(name)
    }

    /// Returns true if `SacnSourceInternal` is in preview mode, false if not.
    ///
    /// For details of `preview_mode` see (`set_preview_mode`)[`set_preview_mode`].
    ///
    /// # Errors
    /// `SourceCorrupt`: Returned if the Mutex used to control access to the internal sender is poisoned by a thread encountering
    /// a panic while accessing causing the source to be left in a potentially inconsistent state.
    pub fn preview_mode(&self) -> Result<bool> {
        Ok(unlock_internal(&self.internal)?.preview_mode())
    }

    /// Sets the value of the `Preview_Data` flag in packets from this `SacnSource`.
    ///
    /// # Arguments
    /// `preview_mode`: If true then all data packets from this `SacnSource` will have the `Preview_Data` flag set to true indicating that the data is not
    ///     for live output. If false then the flag will be set to false.
    ///
    /// # Errors
    /// `SourceCorrupt`: Returned if the Mutex used to control access to the internal sender is poisoned by a thread encountering
    /// a panic while accessing causing the source to be left in a potentially inconsistent state.
    pub fn set_preview_mode(&mut self, preview_mode: bool) -> Result<()> {
        unlock_internal_mut(&mut self.internal)?.set_preview_mode(preview_mode);
        Ok(())
    }

    /// Sets the `is_sending_discovery` flag to the given value.
    ///
    /// # Arguments
    /// val: The new value for the `is_sending_discovery` flag, if true then source will send periodic universe discovery packets
    /// and if false it won't.
    pub fn set_is_sending_discovery(&mut self, val: bool) {
        self.internal.lock().unwrap().set_is_sending_discovery(val);
    }

    /// Returns the multicast time to live of the socket.
    pub fn multicast_ttl(&self) -> Result<u32> {
        unlock_internal(&self.internal)?.multicast_ttl()
    }

    /// Sets the multicast time to live.
    ///
    /// # Arguments
    /// `multicast_ttl`: The new time to live value for network packets sent using multicast.
    ///
    /// # Errors
    /// Io: Returned if the multicast TTL fails to be set on the underlying socket.
    ///
    /// `SourceCorrupt`: Returned if the Mutex used to control access to the internal sender is poisoned by a thread encountering
    /// a panic while accessing causing the source to be left in a potentially inconsistent state.
    pub fn set_multicast_ttl(&mut self, multicast_ttl: u32) -> Result<()> {
        unlock_internal_mut(&mut self.internal)?.set_multicast_ttl(multicast_ttl)
    }

    /// Returns the current Time To Live for unicast packets send by this source.
    ///
    /// # Errors
    /// Io: Returned if the TTL cannot be retrieved from the underlying socket.
    ///
    /// `SourceCorrupt`: Returned if the Mutex used to control access to the internal sender is poisoned by a thread encountering
    /// a panic while accessing causing the source to be left in a potentially inconsistent state.
    pub fn ttl(&self) -> Result<u32> {
        unlock_internal(&self.internal)?.ttl()
    }

    /// Sets the Time To Live for packets sent by this source.
    ///
    /// # Arguments
    /// ttl: The new time to live value for new packets.
    ///
    /// # Errors
    /// Io: Returned if the TTL value cannot be changed.
    ///
    /// `SourceCorrupt`: Returned if the Mutex used to control access to the internal sender is poisoned by a thread encountering
    /// a panic while accessing causing the source to be left in a potentially inconsistent state.
    pub fn set_ttl(&mut self, ttl: u32) -> Result<()> {
        unlock_internal_mut(&mut self.internal)?.set_ttl(ttl)
    }

    /// Sets if multicast loop is enabled.
    ///
    /// # Arguments:
    /// `multicast_loop`: If true then multicast loop is enabled, if false it is not.
    ///
    /// # Errors
    /// Io: Returned if the `set_multicast_loop` option fails to be set on the socket.
    ///
    /// `SourceCorrupt`: Returned if the Mutex used to control access to the internal sender is poisoned by a thread encountering
    /// a panic while accessing causing the source to be left in a potentially inconsistent state.
    pub fn set_multicast_loop_v4(&mut self, multicast_loop: bool) -> Result<()> {
        unlock_internal_mut(&mut self.internal)?.set_multicast_loop(multicast_loop)
    }

    /// Returns true if multicast loop is enabled, false if not.
    ///
    /// # Errors
    /// `SourceCorrupt`: Returned if the Mutex used to control access to the internal sender is poisoned by a thread encountering
    /// a panic while accessing causing the source to be left in a potentially inconsistent state.
    pub fn multicast_loop(&self) -> Result<bool> {
        unlock_internal(&self.internal)?.multicast_loop()
    }

    /// Returns the universes currently registered on this source.
    ///
    /// # Errors
    /// `SourceCorrupt`: Returned if the Mutex used to control access to the internal sender is poisoned by a thread encountering
    /// a panic while accessing causing the source to be left in a potentially inconsistent state.
    pub fn universes(&self) -> Result<Vec<u16>> {
        Ok(unlock_internal(&self.internal)?.universes())
    }
}

/// By implementing the Drop trait for `SacnSource` it means that the user doesn't have to explicitly clean up the source
/// and if it goes out of reference it will clean itself up and send the required termination packets etc.
impl<N: SacnSourceNet + 'static> Drop for SacnSource<N> {
    fn drop(&mut self) {
        match unlock_internal_mut(&mut self.internal) {
            Ok(mut i) => {
                i.set_running(false);
            }
            Err(_) => {
                return;
            } // As drop isn't always explicitly called and cannot return an error the error is ignored. Memory safety is maintain and this prevents causing a panic!.
        };

        if let Some(thread) = self.update_thread.take() {
            // Internal is accessed twice separately, this allows the discovery thread to interleave between running being set to false speeding up termination.
            if let Ok(mut i) = unlock_internal_mut(&mut self.internal) {
                let _ = i.terminate(DEFAULT_TERMINATE_START_CODE);
                {} // For same reasons as above a potential error is ignored and a 'best attempt' is used to clean up.
            } else {
                {} // As drop isn't always explicitly called and cannot return an error the error is ignored. Memory safety is maintain and this prevents causing a panic!.
            };

            thread.join().unwrap();
        }
    }
}

impl<N: SacnSourceNet> SacnSourceInternal<N> {
    /// Constructs a new `SacnSourceInternal` from a pre-built core and network backend.
    fn new(core: SacnSourceCore, net: N) -> Self {
        Self { core, net }
    }

    /// Sets the network interface on which the given universe will be sent.
    ///
    /// `idx` refers to a position within the interface list returned by
    /// `net.enumerate_netints()`. By default each universe sends on interface
    /// index 0 only, matching the behaviour of a single-socket implementation.
    ///
    /// # Errors
    /// `UniverseNotRegistered`: Returned if the universe is not registered.
    fn set_universe_netint(&mut self, universe: u16, if_addr: IpAddr) -> Result<()> {
        let os_idx = self.net.resolve_netint_idx(if_addr).ok_or_else(|| {
            SacnError::UnsupportedIpVersion(format!("No interface with address {} found", if_addr))
        })?;
        self.core.set_universe_netint(universe, os_idx)
    }

    // -----------------------------------------------------------------------
    // Send methods — call core, dispatch sends through net
    // -----------------------------------------------------------------------

    /// Sends the given data to the given universes.
    ///
    /// # Errors
    /// See [`SacnSource::send`] for full error documentation.
    fn send(
        &mut self,
        universes: &[u16],
        data: &[u8],
        priority: Option<u8>,
        dst_ip: Option<SocketAddr>,
        synchronisation_addr: Option<u16>,
    ) -> Result<()> {
        let sends = self
            .core
            .send(universes, data, priority, dst_ip, synchronisation_addr)?;
        self.net.execute_batch(&sends)
    }

    /// Sends a synchronisation packet for the given universe.
    ///
    /// # Errors
    /// See [`SacnSource::send_sync_packet`] for full error documentation.
    fn send_sync_packet(&mut self, universe: u16, dst_ip: Option<SocketAddr>) -> Result<()> {
        let send = self.core.send_sync_packet(universe, dst_ip)?;
        self.net.execute_batch(&[send])
    }

    /// Terminates the stream for the given universe.
    ///
    /// # Errors
    /// See [`SacnSource::terminate_stream`] for full error documentation.
    fn terminate_stream(&mut self, universe: u16, start_code: u8) -> Result<()> {
        let sends = self.core.terminate_stream(universe, start_code)?;
        self.net.execute_batch(&sends)
    }

    /// Terminates all universe streams and marks the source as stopped.
    ///
    /// # Errors
    /// `Io`: Returned if termination packets fail to send.
    fn terminate(&mut self, start_code: u8) -> Result<()> {
        let sends = self.core.terminate(start_code)?;
        self.net.execute_batch(&sends)
    }

    /// Called by the update thread. Checks if a universe discovery packet is
    /// due and dispatches it if so.
    ///
    /// Returns the next deadline so the update thread can sleep accurately,
    /// though the current implementation uses a fixed poll period.
    ///
    /// # Errors
    /// `Io` | `SacnParsePackError`: Returned if discovery packets fail to build or send.
    fn tick(&mut self) -> Result<Option<Instant>> {
        let (sends, deadline) = self.core.tick(self.net.default_netint_idx())?;
        self.net.execute_batch(&sends)?;
        Ok(deadline)
    }

    // -----------------------------------------------------------------------
    // Universe registration — threads n_netints through to core
    // -----------------------------------------------------------------------

    /// Registers a single universe with this source.
    ///
    /// # Errors
    /// `IllegalUniverse`: Returned if the universe is outwith the allowed range.
    fn register_universe(&mut self, universe: u16) -> Result<()> {
        self.core
            .register_universe(universe, self.net.default_netint_idx())
    }

    /// Registers multiple universes with this source.
    ///
    /// # Errors
    /// `IllegalUniverse`: Returned if any universe is outwith the allowed range.
    fn register_universes(&mut self, universes: &[u16]) -> Result<()> {
        self.core
            .register_universes(universes, self.net.default_netint_idx())
    }

    // -----------------------------------------------------------------------
    // Protocol state accessors — delegate to core
    // -----------------------------------------------------------------------

    fn running(&self) -> bool {
        self.core.running
    }

    fn set_running(&mut self, val: bool) {
        self.core.running = val;
    }

    fn cid(&self) -> &Uuid {
        self.core.cid()
    }

    fn set_cid(&mut self, cid: Uuid) {
        self.core.set_cid(cid);
    }

    fn name(&self) -> &str {
        self.core.name()
    }

    fn set_name(&mut self, name: &str) -> Result<()> {
        self.core.set_name(name)
    }

    fn preview_mode(&self) -> bool {
        self.core.preview_mode()
    }

    fn set_preview_mode(&mut self, preview_mode: bool) {
        self.core.set_preview_mode(preview_mode);
    }

    fn set_is_sending_discovery(&mut self, val: bool) {
        self.core.set_is_sending_discovery(val);
    }

    fn universes(&self) -> Vec<u16> {
        self.core.universes()
    }

    // -----------------------------------------------------------------------
    // Socket option accessors — delegate to net
    // -----------------------------------------------------------------------

    fn set_multicast_ttl(&self, ttl: u32) -> Result<()> {
        self.net.set_multicast_ttl(ttl)
    }

    fn multicast_ttl(&self) -> Result<u32> {
        self.net.multicast_ttl()
    }

    fn set_multicast_loop(&self, val: bool) -> Result<()> {
        self.net.set_multicast_loop(val)
    }

    fn multicast_loop(&self) -> Result<bool> {
        self.net.multicast_loop()
    }

    fn ttl(&self) -> Result<u32> {
        self.net.ttl()
    }

    fn set_ttl(&mut self, ttl: u32) -> Result<()> {
        self.net.set_ttl(ttl)
    }
}

/// Returns the locked internal `SacnSourceInternal` used within the `SacnSource`.
///
/// This centralises the locking of the source to a single point within the code allowing any changes to the mechanism to be made in one place.
///
/// This differs to (`unlock_internal_mut`) as it takes an immutable reference to internal.
///
/// # Arguments
/// internal: The `SacnSourceInternal` to unlock encapsulated within an Arc and Mutex.
///
/// # Errors
/// `SourceCorrupt`: Returned if the Mutex used to control access to the internal sender is poisoned by a thread encountering
/// a panic while accessing causing the source to be left in a potentially inconsistent state.
fn unlock_internal<N: SacnSourceNet>(
    internal: &Arc<Mutex<SacnSourceInternal<N>>>,
) -> Result<MutexGuard<'_, SacnSourceInternal<N>>> {
    // The PoisonError returned doesn't contain further information and just allows access to the internal potentially inconsistent sender which
    // shouldn't be exposed to the user (as its internal and would have no use).
    // Cannot directly return the PoisonError due to PoisonError using a different error system to other std modules which doesn't work with
    // error_chain.
    internal
        .lock()
        .map_err(|_e| SacnError::SourceCorrupt("Mutex poisoned".to_string()))
}

/// Returns the locked internal `SacnSourceInternal` used within the `SacnSource`.
///
/// This centralises the locking of the source to a single point within the code allowing any changes to the mechanism to be made in one place.
///
/// This differs to (`unlock_internal`) as it takes an mutable reference to internal.
///
/// # Arguments
/// internal: The `SacnSourceInternal` to unlock encapsulated within an Arc and Mutex.
///
/// # Errors
/// Returns an `SourceCorrupt` error if the Mutex used to control access to the internal sender is poisoned by a thread encountering
/// a panic while accessing causing the source to be left in a potentially inconsistent state.
fn unlock_internal_mut<N: SacnSourceNet>(
    internal: &mut Arc<Mutex<SacnSourceInternal<N>>>,
) -> Result<MutexGuard<'_, SacnSourceInternal<N>>> {
    // The PoisonError returned doesn't contain further information and just allows access to the internal potentially inconsistent sender which
    // shouldn't be exposed to the user (as its internal and would have no use).
    // Cannot directly return the PoisonError due to PoisonError using a different error system to other std modules which doesn't work with
    // error_chain.
    internal
        .lock()
        .map_err(|_e| SacnError::SourceCorrupt("Mutex poisoned".to_string()))
}

/// Called periodically by the source update thread.
///
/// Is responsible for sending the periodic universe discovery packets.
///
/// # Arguments:
/// src: A reference to the `SacnSourceInternal` for which to send the universe discovery packet with/from.
///
/// # Errors
/// Returns a `SourceCorrupt` error if the internal source mutex has been corrupted, see (`unlock_internal`)[`unlock_internal`].
///
/// Returns an error if a discovery packet cannot be sent, see (`send_universe_discovery`)[`fn.send_universe_discovery.source`].
fn perform_periodic_update<N>(
    src: &mut Arc<Mutex<SacnSourceInternal<N>>>,
) -> Result<Option<Instant>>
where
    N: SacnSourceNet,
{
    let mut unwrap_src = unlock_internal_mut(src)?;
    unwrap_src.tick()
}

#[derive(Debug)]
struct SacnSourceCore {
    /// The unique ID of this `SacnSourceInternal`.
    /// It is the job of the user of the library to ensure that the cid is given on creation of the `SacnSourceInternal` is unique.
    cid: Uuid,

    /// The human readable name of this source.
    name: String,

    /// Flag which is included in sACN packets to indicate that the data shouldn't be used for live output
    /// (ie. on actual lighting fixtures). A receiver may or may not be compliant with this so it should not be relied
    /// upon in an untested environment.
    preview_data: bool,

    /// Per-universe state (sequence numbers etc.).
    universe_states: HashMap<u16, SourceUniverseState>,

    /// A list of the universes registered to send by this source, used for universe discovery.
    /// Always sorted with lowest universe first to allow quicker usage.
    /// This may never contain duplicate universe values.
    universe_order: Vec<u16>,

    /// Flag that indicates if the `SacnSourceInternal` is running (the update thread should be triggering periodic discovery packets).
    running: bool,

    /// The time that the last universe discovery advert was send.
    last_discovery_advert_timestamp: Instant,

    /// Flag that is set to True to indicate that the source is sending periodic universe discovery packets.
    is_sending_discovery: bool,

    /// which IP version to use
    ip_version: IpVersion,
}

impl SacnSourceCore {
    pub fn new(cid: Uuid, name: &str, ip_version: IpVersion) -> Self {
        SacnSourceCore {
            cid,
            name: name.to_string(),
            preview_data: false,
            universe_states: HashMap::new(),
            universe_order: Vec::new(),
            running: true,
            last_discovery_advert_timestamp: Instant::now(),
            is_sending_discovery: true,
            ip_version,
        }
    }

    /// Sets the netint index for the given universe.
    ///
    /// # Errors
    /// `UniverseNotRegistered`: Returned if the universe is not registered.
    fn set_universe_netint(&mut self, universe: u16, netint_idx: u32) -> Result<()> {
        match self.universe_states.get_mut(&universe) {
            None => Err(SacnError::UniverseNotRegistered(universe)),
            Some(state) => {
                state.netint_idx = netint_idx;
                Ok(())
            }
        }
    }

    /// Sets the `is_sending_discovery` flag to the given value.
    ///
    /// If `is_sending_discovery` is set to false then no discovery adverts for this source
    /// will be sent otherwise (and by default) they will be sent every `UNIVERSE_DISCOVERY_INTERVAL`.
    ///
    /// # Arguments:
    /// val: The new value of the `is_sending_discovery` flag.
    fn set_is_sending_discovery(&mut self, val: bool) {
        self.is_sending_discovery = val;
    }

    /// Returns the ACN CID device identifier of the `SacnSourceInternal`.
    fn cid(&self) -> &Uuid {
        &self.cid
    }

    /// Sets the ACN CID device identifier.
    ///
    /// # Arguments
    /// cid: The new CID identifier for this source. It is left to the user to ensure that this is always unique within the network the source is in.
    fn set_cid(&mut self, cid: Uuid) {
        self.cid = cid;
    }

    /// Returns the ACN source name.
    fn name(&self) -> &str {
        &self.name
    }

    /// Sets ACN source name.
    ///
    /// # Argument
    /// name: The new name for the source, it is left to the user to ensure this is unique within the sACN network.
    ///
    /// # Errors
    /// `MalformedSourceName`: Returned to indicate that the given source name is longer than the maximum allowed as per `E131_SOURCE_NAME_FIELD_LENGTH`.
    fn set_name(&mut self, name: &str) -> Result<()> {
        if name.len() > E131_SOURCE_NAME_FIELD_LENGTH {
            return Err(SacnError::MalformedSourceName(
                "Source name provided is longer than maximum allowed".to_string(),
            ));
        }
        self.name = name.to_string();

        Ok(())
    }

    fn universes(&self) -> Vec<u16> {
        self.universe_order.clone()
    }

    /// Registers the given array of universes with this source.
    ///
    /// Any universes already registered won't be re-registered and will have no effect.
    ///
    /// # Arguments:
    /// universes: The sACN universe to register. Note that sACN universes start at 1 not 0.
    ///
    /// # Errors
    /// See `register_universe(fn.register_universe.source)` for more details.
    fn register_universes(&mut self, universes: &[u16], netint_idx: u32) -> Result<()> {
        for u in universes {
            self.register_universe(*u, netint_idx)?;
        }
        Ok(())
    }

    /// Registers the given universe for sending with this source.
    ///
    /// If a universe is already registered then this method has no effect.
    ///
    /// # Errors
    /// `IllegalUniverse`: Returned if the universe is outwith the allowed range, see (`is_universe_in_range`)[`fn.is_universe_in_range.packet`].
    fn register_universe(&mut self, universe: u16, netint_idx: u32) -> Result<()> {
        is_universe_in_range(universe)?;

        if let Err(i) = self.universe_order.binary_search(&universe) {
            // Value not found, i is the position it should be inserted
            self.universe_order.insert(i, universe);
            self.universe_states
                .entry(universe)
                .or_insert_with(|| SourceUniverseState::new(netint_idx));
        }
        // If binary search returns Ok(_), then the value is found.
        // Don't insert to avoid duplicates.

        Ok(())
    }

    /// De-registers the given universe for sending with this source.
    ///
    /// # Errors
    /// `IllegalUniverse`: Returned if the universe is outwith the allowed range, see (`is_universe_in_range`)[`fn.is_universe_in_range.packet`].
    ///
    /// `UniverseNotFound`: Returned if the given universe was never registered originally.
    fn deregister_universe(&mut self, universe: u16) -> Result<()> {
        is_universe_in_range(universe)?;

        match self.universe_order.binary_search(&universe) {
            Err(_) => {
                // Value not found
                Err(SacnError::UniverseNotFound(universe))
            }
            Ok(i) => {
                // Value found, i is index.
                self.universe_order.remove(i);
                self.universe_states.remove(&universe);
                Ok(())
            }
        }
    }

    /// Checks if the given universe is a valid universe to send on (within allowed range) and that it is registered with this `SacnSourceInternal`.
    ///
    /// # Errors
    /// `IllegalUniverse`: Returned if the universe is outwith the allowed range, see (`is_universe_in_range`)[`fn.is_universe_in_range.packet`].
    ///
    /// `UniverseNotRegistered`: Returned if the universe is not registered on the given `SacnSourceInternal`.
    fn universe_allowed(&self, u: u16) -> Result<()> {
        is_universe_in_range(u)?;

        if !self.universe_states.contains_key(&u) {
            return Err(SacnError::UniverseNotRegistered(u));
        }

        Ok(())
    }

    /// Returns if `SacnSourceInternal` is in preview mode.
    fn preview_mode(&self) -> bool {
        self.preview_data
    }

    /// Sets the value of the `Preview_Data` flag in packets from this `SacnSourceInternal`.
    ///
    /// # Arguments
    /// `preview_mode`: If true then all data packets from this `SacnSourceInternal` will have the `Preview_Data` flag set to true indicating that the data is not
    ///     for live output. If false then the flag will be set to false.
    fn set_preview_mode(&mut self, preview_mode: bool) {
        self.preview_data = preview_mode;
    }

    /// Sends the given data to the given universes with the given priority, synchronisation address (universe) and destination ip.
    ///
    /// # Arguments
    ///
    /// universe:     The sACN universes that the data should be set on, the data will be split over these universes with each `UNIVERSE_CHANNEL_CAPACITY`
    ///                 sized chunk sent to the next universe.
    ///
    /// data:         The data that should be sent, must have a length greater than 0.
    ///
    /// priority:     The E131 priority that the data should be sent with, must be less than `E131_MAX_PRIORITY` (`const.E131_MAX_PRIORITY.packet`),
    ///                 if a value of None is provided then the default of `E131_DEFAULT_PRIORITY` (`const.E131_DEFAULT_PRIORITY.packet`) is used.
    ///
    /// `dst_ip`:       The destination IP, can be Ipv4 or Ipv6, None if should be sent using ip multicast.
    ///
    /// `sync_address`: The address to use for synchronisation, must be a valid universe, None indicates no synchronisation. If synchronisation is required a
    ///                 reasonable default address to use is the first universe that this data is being sent to.
    ///
    /// As per ANSI E1.31-2018 Section 6.6.1 this method shouldn't be called at a higher refresher rate than specified in ANSI E1.11 [DMX] unless
    ///     configured by the user to do so in an environment which doesn't contain any E1.31 to DMX512-A converters.
    ///
    /// Note as per ANSI-E1.31-2018 Appendix B.1 it is recommended to have a small delay before sending the follow up sync packet.
    ///
    /// # Errors
    /// `SenderAlreadyTerminated`: Returned if this method is called on an `SacnReceiverInternal` that has already terminated.
    ///
    /// `InvalidInput`: Returned if the data array has length 0 or if an insufficient number of universes for the given data are provided (each universe takes 513 bytes of data).
    ///
    /// `InvalidPriority`: Returned if the priority is greater than the allowed maximum priority of `E131_MAX_PRIORITY`.
    ///
    /// `IllegalUniverse`: Returned if the universe is outwith the allowed range as specified by ANSI E1.31-2018 Section 6.2.7.
    ///
    /// `UniverseNotRegistered`: Returned if the universe is not registered on the given `SacnSourceInternal`.
    ///
    /// `ExceedUniverseCapacity`: Returned if the data has a length greater than the maximum allowed within a universe (`packet::UNIVERSE_CHANNEL_CAPACITY`).
    ///
    /// Io: Returned if the data fails to be sent on the socket, see `send_to(fn.send_to.Socket)`.
    fn send(
        &mut self,
        universes: &[u16],
        data: &[u8],
        priority: Option<u8>,
        dst_ip: Option<SocketAddr>,
        synchronisation_addr: Option<u16>,
    ) -> Result<Vec<PendingSend>> {
        if !self.running {
            // Indicates that this sender has been terminated.
            return Err(SacnError::SenderAlreadyTerminated(
                "Attempted to send".to_string(),
            ));
        }

        if data.is_empty() {
            return Err(SacnError::DataArrayEmpty());
        }

        // Check all the given universes are valid before doing any action.
        // This prevents leaving the source in an inconsistent state if later a universe is found to be invalid.
        for u in universes {
            self.universe_allowed(*u)?;
        }

        // Check that the synchronisation universe is also valid.
        if let Some(sync) = synchronisation_addr {
            self.universe_allowed(sync)
                .map_err(|_e| SacnError::IllegalSyncUniverse(sync))?;
        }

        // + 1 as there must be at least 1 universe required as the data isn't empty then additional universes for any more.
        let required_universes =
            (data.len() as f64 / UNIVERSE_CHANNEL_CAPACITY as f64).ceil() as usize;

        if universes.len() < required_universes {
            return Err(SacnError::UniverseListEmpty());
        }

        let priority = priority.unwrap_or(E131_DEFAULT_PRIORITY);
        let sync_address = synchronisation_addr.unwrap_or(NO_SYNC_UNIVERSE);

        let mut sends = Vec::new();
        for (i, &universe) in universes.iter().enumerate().take(required_universes) {
            let start_index = i * UNIVERSE_CHANNEL_CAPACITY;
            // Safety check to make sure that the end index doesn't exceed the data length
            let end_index = min(data.len(), (i + 1) * UNIVERSE_CHANNEL_CAPACITY);

            sends.push(self.send_universe(
                universe,
                &data[start_index..end_index],
                priority,
                &dst_ip,
                sync_address,
            )?);
        }

        Ok(sends)
    }

    /// Sends the given data to the given universe with the given priority, synchronisation address (universe) and destination ip.
    ///
    /// # Arguments
    /// universe:     The sACN universe that the data should be set on.
    ///
    /// data:         The data that should be sent, must be less than or equal in length to `UNIVERSE_CHANNEL_CAPACITY(const.UNIVERSE_CHANNEL_CAPACITY.packet)`.
    ///
    /// priority:     The E131 priority that the data should be sent with, must be less than `E131_MAX_PRIORITY` (`const.E131_MAX_PRIORITY.packet`), default `E131_DEFAULT_PRIORITY`.
    ///
    /// `dst_ip`:       The destination IP, can be Ipv4 or Ipv6, None if should be sent using ip multicast.
    ///
    /// `sync_address`: The address to use for synchronisation, must be a valid universe, 0 indicates no synchronisation.
    ///
    /// # Errors
    /// `InvalidInput`: Returned if the priority is greater than the allowed maximum priority of `E131_MAX_PRIORITY`.
    ///
    /// `ExceedUniverseCapacity`: Returned if the data has a length greater than the maximum allowed within a universe.
    ///
    /// `IllegalUniverse`: Returned if the given universe is outwith the allowed range of universes,
    ///                     see (`universe_to_ipv4_multicast_addr`)[`fn.universe_to_ipv4_multicast_addr.packet`] and (`universe_to_ipv6_multicast_addr`)[`fn.universe_to_ipv6_multicast_addr.packet`].
    ///
    /// Io: Returned if the data fails to be sent on the socket, see `send_to(fn.send_to.Socket)`.
    fn send_universe(
        &mut self,
        universe: u16,
        data: &[u8],
        priority: u8,
        dst_ip: &Option<SocketAddr>,
        sync_address: u16,
    ) -> Result<PendingSend> {
        if priority > E131_MAX_PRIORITY {
            return Err(SacnError::InvalidPriority(priority));
        }

        if data.len() > UNIVERSE_CHANNEL_CAPACITY {
            return Err(SacnError::ExceedUniverseCapacity(data.len()));
        }

        let sequence_number = self
            .universe_states
            .get_mut(&universe)
            .expect("universe_allowed() was checked before send_universe()")
            .next_data_seq();

        let bytes = build_data_packet(
            self.cid,
            &self.name,
            universe,
            data,
            priority,
            sequence_number,
            sync_address,
            self.preview_data,
            false, // stream terminated
            false, // force sync
        )?;

        let destination = self.resolve_dst(dst_ip, universe)?;

        Ok(PendingSend { destination, bytes })
    }

    /// Sends a synchronisation packet to trigger the sending of packets waiting to be sent together.
    ///
    /// A common pattern would be to use the send method to send data to all the universes that should be synchronised using a
    /// chosen synchronisation universe then wait for a small time as per the recommendation in ANSI-E1.31-2018 Appendix B.1 and
    /// then send a synchronisation packet with the address of the synchronisation universe chosen to trigger the packets.
    ///
    /// # Arguments
    /// universe: The universe of this synchronisation packet.
    /// `dst_ip`:   The destination IP address for this packet or None if it should be sent using multicast.
    ///
    /// # Errors
    /// `IllegalUniverse`: Returned if the universe is outwith the allowed range of sACN universes as defined in ANSI E1.31-2018 Section 6.2.7.
    ///
    /// `UniverseNotRegistered`: Returned if the universe is not registered on the given `SacnSourceInternal`.
    ///
    /// Io: Returned if the packet fails to be sent using the underlying network socket.
    ///
    /// `SacnParsePackError`: Returned if the sync packet fails to be packed.
    fn send_sync_packet(
        &mut self,
        universe: u16,
        dst_ip: Option<SocketAddr>,
    ) -> Result<PendingSend> {
        self.universe_allowed(universe)?;

        let sequence_number = self
            .universe_states
            .get_mut(&universe)
            .expect("universe_allowed() was checked above")
            .next_sync_seq();

        let bytes = build_sync_packet(self.cid, universe, sequence_number)?;

        let destination = self.resolve_dst(&dst_ip, universe)?;

        Ok(PendingSend { destination, bytes })
    }

    /// Sends a stream termination packet for the given universe.
    ///
    /// In normal usage this method would be called three times to send three packets for termination as per
    ///     ANSI E1.31-2018 Section 6.2.6, `Stream_Terminated`: Bit 6.
    ///
    /// # Arguments
    /// universe: The universe of this synchronisation packet.
    /// `dst_ip`:   The destination IP address for this packet or None if it should be sent using multicast.
    ///
    /// # Errors
    /// `IllegalUniverse`: Returned if the universe is outwith the allowed range of sACN universes as defined in ANSI E1.31-2018 Section 6.2.7.
    ///
    /// `UniverseNotRegistered`: Returned if the universe is not registered on the given `SacnSourceInternal`.
    ///
    /// Io: Returned if the termination packets fail to be sent on the underlying socket.
    fn send_terminate_stream_pkt(
        &mut self,
        universe: u16,
        dst_ip: Option<SocketAddr>,
        start_code: u8,
    ) -> Result<PendingSend> {
        self.universe_allowed(universe)?;

        let sequence_number = self
            .universe_states
            .get_mut(&universe)
            .expect("universe_allowed() checked above")
            .next_data_seq();

        let bytes = build_data_packet(
            self.cid,
            &self.name,
            universe,
            &[start_code],
            100,
            sequence_number,
            0,
            self.preview_data,
            true,
            false,
        )?;

        let destination = self.resolve_dst(&dst_ip, universe)?;

        Ok(PendingSend { destination, bytes })
    }

    /// Terminates a universe stream.
    ///
    /// Terminates a stream to the specified universe by sending packets with the `Stream_Terminated` flag set to 1.
    /// Number of packets sent as per section 6.2.6 , `Stream_Terminated`: Bit 6 of ANSI E1.31-2018.
    ///
    /// Arguments:
    /// universe: The universe that is being terminated.
    /// `start_code`: used for the first byte of the otherwise empty data payload to indicate the `start_code` of the data.
    ///
    /// # Errors:
    /// `IllegalUniverse`: Returned if the universe is outwith the allowed range of sACN universes as defined in ANSI E1.31-2018 Section 6.2.7.
    ///
    /// `UniverseNotRegistered`: Returned if the universe is not registered on this source.
    ///
    /// Io: Returned if the termination packets fail to be sent on the socket.
    fn terminate_stream(&mut self, universe: u16, start_code: u8) -> Result<Vec<PendingSend>> {
        let mut sends = Vec::with_capacity(E131_TERMINATE_STREAM_PACKET_COUNT);
        for _ in 0..E131_TERMINATE_STREAM_PACKET_COUNT {
            sends.push(self.send_terminate_stream_pkt(universe, None, start_code)?);
        }

        self.deregister_universe(universe)?;
        Ok(sends)
    }

    /// Terminates the DMX source.
    ///
    /// This includes terminating each registered universe with the `start_code` given.
    ///
    /// Arguments:
    /// `start_code`: used for the first byte of the otherwise empty data payload to indicate the `start_code` of the data.
    ///
    /// # Errors:
    /// Io: Returned if the termination packets fail to be sent on the underlying socket.
    fn terminate(&mut self, start_code: u8) -> Result<Vec<PendingSend>> {
        self.running = false;
        let universes = self.universe_order.clone(); // About to start manipulating self.universes as universes are removed so clone original list.
        let mut sends = Vec::with_capacity(E131_TERMINATE_STREAM_PACKET_COUNT * universes.len());
        for u in universes {
            sends.append(&mut self.terminate_stream(u, start_code)?);
        }
        Ok(sends)
    }

    /// Sends a universe discovery packet advertising the universes that this source is registered to send.
    ///
    /// This packet may be broken down into multiple pages internally resulting in multiple UDP packets.
    ///
    /// # Errors
    /// See (`send_universe_discovery_detailed`)[`fn.send_universe_discovery_detailed.source`].
    fn send_universe_discovery(&self, netint_idx: u32) -> Result<Vec<PendingSend>> {
        // Given a u16 universe field and self.universes containing no duplicates it means that the maximum total number of universes (65536, ignoring sACN restrictions)
        // divided by the number of universes per page (512) is 128 which therefore fits into the discovery universe 8 bit page field making this cast safe.
        let pages_req: u8 = ((self.universe_order.len() / DISCOVERY_UNI_PER_PAGE) + 1) as u8;

        let mut sends = Vec::new();
        for p in 0..pages_req {
            let start_index = (p as usize) * DISCOVERY_UNI_PER_PAGE;
            let end_index = min(
                ((p as usize) + 1) * DISCOVERY_UNI_PER_PAGE,
                self.universe_order.len(),
            );

            sends.push(self.send_universe_discovery_detailed(
                p,
                pages_req - 1,
                &self.universe_order[start_index..end_index],
                netint_idx,
            )?);
        }
        Ok(sends)
    }

    /// Sends a page of a universe discovery packet.
    ///
    /// There may be 1 or more pages for each full universe discovery packet with each page sent separately.
    ///
    /// # Arguments
    ///
    /// page: The page number of this universe discovery page.
    ///
    /// `last_page`: The last page that is expected as part of this universe discovery packet.
    ///
    /// universes: The universes to include on the page.
    ///
    /// # Errors
    /// Io: Returned if the discovery packet fails to be sent on the socket.
    ///
    /// `SacnParsePackError`: Returned if the discovery packet cannot be packed to send.
    fn send_universe_discovery_detailed(
        &self,
        page: u8,
        last_page: u8,
        universes: &[u16],
        netint_idx: u32,
    ) -> Result<PendingSend> {
        let bytes = build_discovery_packet(self.cid, &self.name, page, last_page, universes)?;

        let addr = match self.ip_version {
            IpVersion::V4 => universe_to_ipv4_multicast_addr(E131_DISCOVERY_UNIVERSE)?,
            IpVersion::V6 => universe_to_ipv6_multicast_addr(E131_DISCOVERY_UNIVERSE)?,
        };

        let multicast_addr = addr.as_socket().ok_or_else(|| {
            SacnError::UnsupportedIpVersion(
                "Discovery multicast address could not be converted to SocketAddr".to_string(),
            )
        })?;

        Ok(PendingSend {
            destination: SendDestination::Multicast {
                netint_os_idx: netint_idx,
                multicast_addr,
            },
            bytes,
        })
    }

    /// Resolves the send destination: uses `dst_ip` if provided, otherwise derives
    /// the multicast address for the given universe based on the socket's IP family.
    fn resolve_dst(&self, dst_ip: &Option<SocketAddr>, universe: u16) -> Result<SendDestination> {
        Ok(if let Some(addr) = dst_ip {
            SendDestination::Unicast { addr: (*addr) }
        } else {
            let s = match self.ip_version {
                IpVersion::V4 => universe_to_ipv4_multicast_addr(universe)?,
                IpVersion::V6 => universe_to_ipv6_multicast_addr(universe)?,
            };
            SendDestination::Multicast {
                netint_os_idx: self
                    .universe_states
                    .get(&universe)
                    .expect("Universe_allowed() checked before resolve_dst()")
                    .netint_idx,
                multicast_addr: s.as_socket().expect("Socket should be in IPv4 or IPv6"),
            }
        })
    }

    fn tick(&mut self, netint_idx: u32) -> Result<(Vec<PendingSend>, Option<Instant>)> {
        let mut sends = Vec::new();
        let next_deadline;
        if self.is_sending_discovery
            && self.last_discovery_advert_timestamp.elapsed() >= E131_UNIVERSE_DISCOVERY_INTERVAL
        {
            sends.extend(self.send_universe_discovery(netint_idx)?);
            self.last_discovery_advert_timestamp = Instant::now();
            next_deadline = self
                .last_discovery_advert_timestamp
                .checked_add(E131_UNIVERSE_DISCOVERY_INTERVAL);
        } else {
            next_deadline = None;
        }
        Ok((sends, next_deadline))
    }
}
