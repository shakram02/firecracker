// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fs::File;
use std::io::{Error as IoError, Read, Result as IoResult, Write};
use std::net;
use std::os::raw::*;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use super::{create_sockaddr, create_socket, Error as NetUtilError};
use libc;
use net_gen;
use sys_util::{ioctl_with_mut_ref, ioctl_with_ref, ioctl_with_val};

#[derive(Debug)]
pub enum Error {
    /// Couldn't open /dev/net/tun.
    OpenTun(IoError),
    /// Unable to create tap interface.
    CreateTap(IoError),
    /// ioctl failed.
    IoctlError(IoError),
    /// Failed to create a socket.
    NetUtil(NetUtilError),
    InvalidIfname,
}

pub type Result<T> = ::std::result::Result<T, Error>;

/// Handle for a network tap interface.
///
/// For now, this simply wraps the file descriptor for the tap device so methods
/// can run ioctls on the interface. The tap interface fd will be closed when
/// Tap goes out of scope, and the kernel will clean up the interface
/// automatically.
#[derive(Debug)]
pub struct Tap {
    tap_file: File,
    if_name: [u8; 16usize],
}

impl PartialEq for Tap {
    fn eq(&self, other: &Tap) -> bool {
        self.if_name == other.if_name
    }
}

// Returns a byte vector representing the contents of a null terminated C string which
// contains if_name.
fn build_terminated_if_name(if_name: &str) -> Result<Vec<u8>> {
    // Convert the string slice to bytes, and shadow the variable,
    // since we no longer need the &str version.
    let if_name = if_name.as_bytes();

    // TODO: the 16usize limit of the if_name member from struct Tap is pretty arbitrary.
    // We leave it as is for now, but this should be refactored at some point.
    if if_name.len() > 15 {
        return Err(Error::InvalidIfname);
    }

    let mut terminated_if_name = vec![b'\0'; if_name.len() + 1];
    terminated_if_name[..if_name.len()].copy_from_slice(if_name);

    Ok(terminated_if_name)
}

impl Tap {
    pub fn open_named(if_name: &str) -> Result<Tap> {
        let terminated_if_name = build_terminated_if_name(if_name)?;

        let fd = unsafe {
            // Open calls are safe because we give a constant null-terminated
            // string and verify the result.
            libc::open(
                b"/dev/net/tun\0".as_ptr() as *const c_char,
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Error::OpenTun(IoError::last_os_error()));
        }

        // We just checked that the fd is valid.
        let tuntap = unsafe { File::from_raw_fd(fd) };

        // This is pretty messy because of the unions used by ifreq. Since we
        // don't call as_mut on the same union field more than once, this block
        // is safe.
        let mut ifreq: net_gen::ifreq = Default::default();
        unsafe {
            let ifrn_name = ifreq.ifr_ifrn.ifrn_name.as_mut();
            let ifru_flags = ifreq.ifr_ifru.ifru_flags.as_mut();
            let name_slice = &mut ifrn_name[..terminated_if_name.len()];
            name_slice.copy_from_slice(terminated_if_name.as_slice());
            *ifru_flags =
                (net_gen::IFF_TAP | net_gen::IFF_NO_PI | net_gen::IFF_VNET_HDR) as c_short;
        }

        // ioctl is safe since we call it with a valid tap fd and check the return
        // value.
        let ret = unsafe { ioctl_with_mut_ref(&tuntap, net_gen::TUNSETIFF(), &mut ifreq) };

        if ret < 0 {
            return Err(Error::CreateTap(IoError::last_os_error()));
        }

        // Safe since only the name is accessed, and it's cloned out.
        Ok(Tap {
            tap_file: tuntap,
            if_name: unsafe { *ifreq.ifr_ifrn.ifrn_name.as_ref() },
        })
    }

    /// Create a new tap interface.
    pub fn new() -> Result<Tap> {
        Self::open_named("vmtap%d")
    }

    /// Set the host-side IP address for the tap interface.
    pub fn set_ip_addr(&self, ip_addr: net::Ipv4Addr) -> Result<()> {
        let sock = create_socket().map_err(Error::NetUtil)?;
        let addr = create_sockaddr(ip_addr);

        let mut ifreq = self.get_ifreq();

        // We only access one field of the ifru union, hence this is safe.
        unsafe {
            let ifru_addr = ifreq.ifr_ifru.ifru_addr.as_mut();
            *ifru_addr = addr;
        }

        // ioctl is safe. Called with a valid sock fd, and we check the return.
        #[allow(clippy::cast_lossless)]
        let ret =
            unsafe { ioctl_with_ref(&sock, net_gen::sockios::SIOCSIFADDR as c_ulong, &ifreq) };
        if ret < 0 {
            return Err(Error::IoctlError(IoError::last_os_error()));
        }

        Ok(())
    }

    /// Set the netmask for the subnet that the tap interface will exist on.
    pub fn set_netmask(&self, netmask: net::Ipv4Addr) -> Result<()> {
        let sock = create_socket().map_err(Error::NetUtil)?;
        let addr = create_sockaddr(netmask);

        let mut ifreq = self.get_ifreq();

        // We only access one field of the ifru union, hence this is safe.
        unsafe {
            let ifru_addr = ifreq.ifr_ifru.ifru_addr.as_mut();
            *ifru_addr = addr;
        }

        // ioctl is safe. Called with a valid sock fd, and we check the return.
        #[allow(clippy::cast_lossless)]
        let ret =
            unsafe { ioctl_with_ref(&sock, net_gen::sockios::SIOCSIFNETMASK as c_ulong, &ifreq) };
        if ret < 0 {
            return Err(Error::IoctlError(IoError::last_os_error()));
        }

        Ok(())
    }

    /// Set the offload flags for the tap interface.
    pub fn set_offload(&self, flags: c_uint) -> Result<()> {
        // ioctl is safe. Called with a valid tap fd, and we check the return.
        #[allow(clippy::cast_lossless)]
        let ret =
            unsafe { ioctl_with_val(&self.tap_file, net_gen::TUNSETOFFLOAD(), flags as c_ulong) };
        if ret < 0 {
            return Err(Error::IoctlError(IoError::last_os_error()));
        }

        Ok(())
    }

    /// Enable the tap interface.
    pub fn enable(&self) -> Result<()> {
        let sock = create_socket().map_err(Error::NetUtil)?;

        let mut ifreq = self.get_ifreq();

        // We only access one field of the ifru union, hence this is safe.
        unsafe {
            let ifru_flags = ifreq.ifr_ifru.ifru_flags.as_mut();
            *ifru_flags =
                (net_gen::net_device_flags_IFF_UP | net_gen::net_device_flags_IFF_RUNNING) as i16;
        }

        // ioctl is safe. Called with a valid sock fd, and we check the return.
        #[allow(clippy::cast_lossless)]
        let ret =
            unsafe { ioctl_with_ref(&sock, net_gen::sockios::SIOCSIFFLAGS as c_ulong, &ifreq) };
        if ret < 0 {
            return Err(Error::IoctlError(IoError::last_os_error()));
        }

        Ok(())
    }

    /// Set the size of the vnet hdr.
    pub fn set_vnet_hdr_size(&self, size: c_int) -> Result<()> {
        // ioctl is safe. Called with a valid tap fd, and we check the return.
        let ret = unsafe { ioctl_with_ref(&self.tap_file, net_gen::TUNSETVNETHDRSZ(), &size) };
        if ret < 0 {
            return Err(Error::IoctlError(IoError::last_os_error()));
        }

        Ok(())
    }

    fn get_ifreq(&self) -> net_gen::ifreq {
        let mut ifreq: net_gen::ifreq = Default::default();

        // This sets the name of the interface, which is the only entry
        // in a single-field union.
        unsafe {
            let ifrn_name = ifreq.ifr_ifrn.ifrn_name.as_mut();
            ifrn_name.clone_from_slice(&self.if_name);
        }

        ifreq
    }
}

impl Read for Tap {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.tap_file.read(buf)
    }
}

impl Write for Tap {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.tap_file.write(&buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

impl AsRawFd for Tap {
    fn as_raw_fd(&self) -> RawFd {
        self.tap_file.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    extern crate pnet;

    use std::net::{Ipv4Addr, UdpSocket};
    use std::str;
    use std::sync::{mpsc, Mutex};
    use std::thread;
    use std::time::Duration;

    use self::pnet::datalink::Channel::Ethernet;
    use self::pnet::datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface};
    use dumbo::pdu::arp::{EthIPv4ArpFrame, ETH_IPV4_FRAME_LEN};
    use dumbo::pdu::ethernet::{EthernetFrame, ETHERTYPE_ARP, ETHERTYPE_IPV4, PAYLOAD_OFFSET};
    use dumbo::pdu::ipv4::{IPv4Packet, DEFAULT_TTL, IPV4_VERSION, PROTOCOL_UDP};
    use dumbo::pdu::mac::MacAddr;
    use dumbo::pdu::udp::{UdpDatagram, UDP_HEADER_SIZE};

    use super::*;

    static DATA_STRING: &str = "test for tap";
    static SUBNET_MASK: &str = "255.255.255.0";
    // We skip the first 10 bytes because the IFF_VNET_HDR flag is set when the interface
    // is created, and the legacy header is 10 bytes long without a certain flag which
    // is not set in Tap::new().
    const VETH_OFFSET: usize = 10;
    // We needed to have a mutex as a global variable, so we used the crate that provides the
    // lazy_static! macro for testing. The main potential problem, caused by tests being run in
    // parallel by cargo, is creating different TAPs and trying to associate the same address,
    // so we hide the IP address &str behind this mutex, more as a convention to remember to lock
    // it at the very beginning of each function susceptible to this issue. Another variant is
    // to use a different IP address per function, but we must remember to pick an unique one
    // each time.
    // TODO: get the host's IP
    lazy_static! {
        static ref TAP_IP_LOCK: Mutex<&'static str> = Mutex::new("192.168.1.115");
    }

    // Describes the outcomes we are currently interested in when parsing a packet (we use
    // an UDP packet for testing).
    struct ParsedPkt<'a> {
        eth: EthernetFrame<'a, &'a [u8]>,
        ipv4: Option<IPv4Packet<'a, &'a [u8]>>,
        udp: Option<UdpDatagram<'a, &'a [u8]>>,
    }

    impl<'a> ParsedPkt<'a> {
        fn new(buf: &'a [u8]) -> Self {
            let eth = EthernetFrame::from_bytes(buf).unwrap();
            let mut ipv4 = None;
            let mut udp = None;

            if eth.ethertype() == ETHERTYPE_IPV4 {
                let ipv4_start = 14;
                ipv4 = Some(IPv4Packet::from_bytes(&buf[ipv4_start..], false).unwrap());

                // Hiding the old ipv4 variable for the rest of this block.
                let ipv4 = IPv4Packet::from_bytes(eth.payload(), false).unwrap();
                let (_, header_length) = ipv4.version_and_header_len();

                if ipv4.protocol() == PROTOCOL_UDP {
                    let udp_start = ipv4_start + header_length;
                    udp = Some(UdpDatagram::from_bytes(&buf[udp_start..], None).unwrap());
                }
            }

            ParsedPkt { eth, ipv4, udp }
        }

        fn print(&self) {
            print!(
                "{} {} {} ",
                self.eth.src_mac().to_string(),
                self.eth.dst_mac().to_string(),
                self.eth.ethertype()
            );
            if let Some(ref ipv4) = self.ipv4 {
                print!(
                    "{} {} {} ",
                    ipv4.source_address(),
                    ipv4.destination_address(),
                    ipv4.protocol()
                );
            }
            if let Some(ref udp) = self.udp {
                print!(
                    "{} {} {}",
                    udp.source_port(),
                    udp.destination_port(),
                    str::from_utf8(udp.payload()).unwrap()
                );
            }
            println!();
        }
    }

    fn tap_name_to_string(tap: &Tap) -> String {
        let null_pos = tap.if_name.iter().position(|x| *x == 0).unwrap();
        str::from_utf8(&tap.if_name[..null_pos])
            .unwrap()
            .to_string()
    }

    // Given a buffer of appropriate size, this fills in the relevant fields based on the
    // provided information. Payload refers to the UDP payload.
    fn pnet_build_packet(buf: &mut [u8], dst_mac: MacAddr, payload: &[u8]) {
        let mut eth = EthernetFrame::from_bytes(buf).unwrap();

        let src_mac = MacAddr::from_bytes(&[0x06, 0, 0, 0, 0, 0]).unwrap();
        eth.set_src_mac(src_mac);
        eth.set_dst_mac(dst_mac);
        eth.set_ethertype(ETHERTYPE_IPV4);

        let mut ipv4 = IPv4Packet::from_bytes_unchecked(eth.payload_mut());
        let ip_header_len_bytes = 20;
        ipv4.set_version_and_header_len(IPV4_VERSION, ip_header_len_bytes);
        ipv4.set_total_len((ip_header_len_bytes + UDP_HEADER_SIZE + payload.len()) as u16);
        ipv4.set_ttl(DEFAULT_TTL);
        ipv4.set_protocol(PROTOCOL_UDP);
        ipv4.set_source_address(Ipv4Addr::new(192, 168, 241, 1));
        ipv4.set_destination_address(Ipv4Addr::new(192, 168, 241, 2));

        let src_port = 1000;
        let dst_port = 1001;
        let udp = UdpDatagram::write_incomplete_datagram(ipv4.payload_mut(), payload).unwrap();
        udp.finalize(src_port, dst_port, None);
    }

    // For a given interface name, this returns a tuple that contains the MAC address of the
    // interface, an object that can be used to send Ethernet frames, and a receiver of
    // Ethernet frames arriving at the specified interface.
    fn pnet_get_mac_tx_rx(ifname: String) -> (MacAddr, Box<DataLinkSender>, Box<DataLinkReceiver>) {
        let interface_name_matches = |iface: &NetworkInterface| iface.name == ifname;

        // Find the network interface with the provided name.
        let interfaces = datalink::interfaces();
        let interface = interfaces.into_iter().find(interface_name_matches).unwrap();

        if let Ok(Ethernet(tx, rx)) = datalink::channel(&interface, Default::default()) {
            let mac_addr = interface.mac_address();
            // TODO: replace pnet interfaces
            let mut mac_bytes = [0u8; 6];
            mac_bytes[0] = mac_addr.0;
            mac_bytes[1] = mac_addr.1;
            mac_bytes[2] = mac_addr.2;
            mac_bytes[3] = mac_addr.3;
            mac_bytes[4] = mac_addr.4;
            mac_bytes[5] = mac_addr.5;
            let mac = MacAddr::from_bytes(mac_bytes.as_mut()).unwrap();
            (mac, tx, rx)
        } else {
            panic!("datalink channel error or unhandled channel type");
        }
    }

    #[test]
    fn test_tap_create() {
        let t = Tap::new().unwrap();
        println!("created tap: {:?}", t);
    }

    #[test]
    fn test_tap_configure() {
        // This should be the first thing to be called inside the function, so everything else
        // is torn down by the time the mutex is automatically released. Also, we should
        // explicitly bind the MutexGuard to a variable via let, the make sure it lives until
        // the end of the function.
        let tap_ip_guard = TAP_IP_LOCK.lock().unwrap();

        let tap = Tap::new().unwrap();
        let ip_addr: net::Ipv4Addr = (*tap_ip_guard).parse().unwrap();
        let netmask: net::Ipv4Addr = SUBNET_MASK.parse().unwrap();

        let ret = tap.set_ip_addr(ip_addr);
        assert!(ret.is_ok());
        let ret = tap.set_netmask(netmask);
        assert!(ret.is_ok());
    }

    #[test]
    fn test_set_options() {
        // This line will fail to provide an initialized FD if the test is not run as root.
        let tap = Tap::new().unwrap();
        tap.set_vnet_hdr_size(16).unwrap();
        tap.set_offload(0).unwrap();
    }

    #[test]
    fn test_tap_enable() {
        let tap = Tap::new().unwrap();
        let ret = tap.enable();
        assert!(ret.is_ok());
    }

    #[test]
    fn test_tap_get_ifreq() {
        let tap = Tap::new().unwrap();
        let ret = tap.get_ifreq();
        assert_eq!(
            "__BindgenUnionField",
            format!("{:?}", ret.ifr_ifrn.ifrn_name)
        );
    }

    #[test]
    fn test_raw_fd() {
        let tap = Tap::new().unwrap();
        assert_eq!(tap.as_raw_fd(), tap.tap_file.as_raw_fd());
    }

    fn construct_arp_reply<'a>(
        buf: &'a mut [u8],
        arp_frame: &EthernetFrame<&[u8]>,
    ) -> EthernetFrame<'a, &'a mut [u8]> {
        let arp_bytes = arp_frame.payload();
        let arp_request = EthIPv4ArpFrame::request_from_bytes(arp_bytes).unwrap();
        // Will be used as the mac of the UDP endpoint
        let fake_mac = MacAddr::parse_str("12:34:56:78:9a:BC").unwrap();
        let mut reply_frame =
            EthernetFrame::write_incomplete(buf, arp_frame.src_mac(), fake_mac, ETHERTYPE_ARP)
                .unwrap();
        let sha = arp_request.sha();
        let spa = arp_request.spa();
        let tpa = arp_request.tpa();

        EthIPv4ArpFrame::write_reply(
            reply_frame.inner_mut().payload_mut(),
            fake_mac,
            tpa,
            sha,
            spa,
        )
        .unwrap();
        reply_frame.with_payload_len_unchecked(ETH_IPV4_FRAME_LEN)
    }

    #[test]
    fn test_read() {
        let tap_ip_guard = TAP_IP_LOCK.lock().unwrap();

        let mut tap = Tap::new().unwrap();
        tap.set_ip_addr((*tap_ip_guard).parse().unwrap()).unwrap();
        tap.set_netmask(SUBNET_MASK.parse().unwrap()).unwrap();
        tap.enable().unwrap();

        // Send a packet to the interface. We expect to be able to receive it on the associated fd.
        let udp_src_port = 44444;
        let udp_dst_port = 44445;

        // TODO: figure out host's IP address to use it
        let udp_socket_addr = format!("{}:{}", "192.168.1.107", udp_src_port);
        let socket = UdpSocket::bind(udp_socket_addr).expect("Failed to bind UDP socket");
        // Now we want to set the target address to something that's near the IP address
        // of the TAP (within its subnet) so the OS will think that the TAP is the next hop
        // and forward the Udp packet through the TAP, where we can read it.
        let next_to_tap_addr = format!("{}:{}", "192.168.1.120", udp_dst_port);
        socket
            .send_to(DATA_STRING.as_bytes(), next_to_tap_addr)
            .unwrap();

        let mut found_packet_sz = None;

        // In theory, this could actually loop forever if something keeps sending data through the
        // tap interface, but it's highly unlikely.
        while found_packet_sz.is_none() {
            let mut buf = [0u8; 1024];
            let result = tap.read(&mut buf);
            assert!(result.is_ok());

            let size = result.unwrap();

            let eth_bytes = &buf[VETH_OFFSET..size];
            let packet = EthernetFrame::from_bytes(eth_bytes).unwrap();

            if packet.ethertype() == ETHERTYPE_ARP {
                // Veth header + ARP reply
                let reply_buf = &mut [0u8; VETH_OFFSET + PAYLOAD_OFFSET + ETH_IPV4_FRAME_LEN];
                construct_arp_reply(&mut reply_buf[10..], &packet);

                assert!(tap.write(reply_buf).is_ok());
                assert!(tap.flush().is_ok());
                continue;
            }

            if packet.ethertype() != ETHERTYPE_IPV4 {
                // not an IPv4 packet
                continue;
            }

            let ipv4_bytes = &eth_bytes[PAYLOAD_OFFSET..];
            let packet = IPv4Packet::from_bytes(ipv4_bytes, false).unwrap();

            // Our packet should carry an UDP payload, and not contain IP options.
            if packet.protocol() != PROTOCOL_UDP && packet.header_len() != 5 {
                continue;
            }

            let ipv4_data_start = 20;
            let udp_bytes = &ipv4_bytes[ipv4_data_start..];

            let packet = UdpDatagram::from_bytes(udp_bytes, None).unwrap();
            let udp_len = packet.len() as usize;
            // Avoid parsing RIP packets (or whatever we don't want)
            if packet.destination_port() != udp_dst_port && packet.source_port() != udp_src_port {
                continue;
            }

            // Skip the header bytes.
            let inner_string = str::from_utf8(&udp_bytes[UDP_HEADER_SIZE..udp_len]).unwrap();

            if inner_string.eq(DATA_STRING) {
                found_packet_sz = Some(size);
                break;
            }
        }

        assert!(found_packet_sz.is_some());
    }

    #[test]
    fn test_write() {
        let tap_ip_guard = TAP_IP_LOCK.lock().unwrap();

        let mut tap = Tap::new().unwrap();
        tap.set_ip_addr((*tap_ip_guard).parse().unwrap()).unwrap();
        tap.set_netmask(SUBNET_MASK.parse().unwrap()).unwrap();
        tap.enable().unwrap();

        let (mac, _, mut rx) = pnet_get_mac_tx_rx(tap_name_to_string(&tap));

        let payload = DATA_STRING.as_bytes();

        // vnet hdr + eth hdr + ip hdr + udp hdr + payload len
        let buf_size = 10 + 14 + 20 + 8 + payload.len();

        let mut buf = vec![0u8; buf_size];
        // leave the vnet hdr as is
        pnet_build_packet(&mut buf[10..], mac, payload);

        assert!(tap.write(&buf[..]).is_ok());
        assert!(tap.flush().is_ok());

        let (channel_tx, channel_rx) = mpsc::channel();

        // We use a separate thread to wait for the test packet because the API exposed by pnet is
        // blocking. This thread will be killed when the main thread exits.
        let _handle = thread::spawn(move || loop {
            let buf = rx.next().unwrap();
            let p = ParsedPkt::new(buf);
            p.print();

            if let Some(ref udp) = p.udp {
                if payload == udp.payload() {
                    channel_tx.send(true).unwrap();
                    break;
                }
            }
        });

        // We wait for at most SLEEP_MILLIS * SLEEP_ITERS milliseconds for the reception of the
        // test packet to be detected.
        static SLEEP_MILLIS: u64 = 500;
        static SLEEP_ITERS: u32 = 6;

        let mut found_test_packet = false;

        for _ in 0..SLEEP_ITERS {
            thread::sleep(Duration::from_millis(SLEEP_MILLIS));
            if let Ok(true) = channel_rx.try_recv() {
                found_test_packet = true;
                break;
            }
        }

        assert!(found_test_packet);
    }
}
