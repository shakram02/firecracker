// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contains support for parsing and writing User Datagram Protocol (UDP) packets
//!
//! Details of the UDP packet specification can be found at [1] [2]
//!
//! [1]: https://tools.ietf.org/html/rfc768
//! [2]: https://tools.ietf.org/html/rfc5405

use std::net::Ipv4Addr;

use pdu::bytes::NetworkBytesMut;
use pdu::ipv4::PROTOCOL_UDP;
use pdu::Incomplete;

use super::bytes::{InnerBytes, NetworkBytes};

/// The header length is 8 octets (bytes)
const HEADER_SIZE: usize = 8;

const SOURCE_PORT_OFFSET: usize = 0;
const DESTINATION_PORT_OFFSET: usize = 2;
const LENGTH_OFFSET: usize = 4;
const CHECKSUM_OFFSET: usize = 6;
/// Payload offset also denotes the header size
const PAYLOAD_OFFSET: usize = 8;

// A UDP datagram is carried in a single IP packet and is hence limited
// to a maximum payload of 65,507 bytes for IPv4 and 65,527 bytes for IPv6 [2]
const IPV4_MAX_UDP_PACKET_SIZE: usize = 65507;

/// Represents errors which may occur while parsing or writing a datagram.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Error {
    /// Invalid checksum
    Checksum,
    /// The specified byte sequence is shorter than the Ethernet header length.
    DatagramTooShort,
    /// The payload to be added to the UDP packet exceeds the size allowed
    /// by the used IP version
    PayloadTooBig,
}

/// Interprets the inner bytes as a UDP datagram.
pub struct UdpDatagram<'a, T: 'a> {
    bytes: InnerBytes<'a, T>,
}

impl<'a, T: NetworkBytes> UdpDatagram<'a, T> {
    /// Interprets `bytes` as a UDP datagram without any validity checks.
    ///
    /// # Panics
    ///
    ///  This method does not panic, but further method calls on the resulting object may panic if
    /// `bytes` contains invalid input.
    #[inline]
    fn from_bytes_unchecked(bytes: T) -> Self {
        UdpDatagram {
            bytes: InnerBytes::new(bytes),
        }
    }

    /// Interprets `bytes` as a UDP datagram if possible or returns
    /// the reason for failing to do so
    #[inline]
    fn from_bytes(bytes: T, verify_checksum: Option<(Ipv4Addr, Ipv4Addr)>) -> Result<Self, Error> {
        if bytes.len() < PAYLOAD_OFFSET {
            return Err(Error::DatagramTooShort);
        }

        let datagram = UdpDatagram::from_bytes_unchecked(bytes);
        if let Some((src_addr, dst_addr)) = verify_checksum {
            if datagram.compute_checksum(src_addr, dst_addr) != 0 {
                return Err(Error::Checksum);
            }
        }

        // src port (optional): If not used, a value of zero is inserted.
        // src port be assumed  to be the port  to which a reply should
        // be addressed  in the absence of any other information (?)
        Ok(datagram)
    }

    /// Returns the source port of the UDP datagram
    #[inline]
    pub fn source_port(&self) -> u16 {
        self.bytes.ntohs_unchecked(SOURCE_PORT_OFFSET)
    }

    /// Returns the destination port of the UDP datagram
    #[inline]
    pub fn destination_port(&self) -> u16 {
        self.bytes.ntohs_unchecked(DESTINATION_PORT_OFFSET)
    }

    /// Returns the length of the datagram from its header
    #[inline]
    pub fn length(&self) -> u16 {
        self.bytes.ntohs_unchecked(LENGTH_OFFSET)
    }

    /// Returns the checksum value of the packet
    #[inline]
    pub fn checksum(&self) -> u16 {
        self.bytes.ntohs_unchecked(CHECKSUM_OFFSET)
    }

    /// Returns the payload of the UDP datagram as an `[&u8]` slice.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        // Payload offset is header len.
        self.bytes.split_at(PAYLOAD_OFFSET).1
    }

    /// Computes the checksum of a UDP datagram
    #[inline]
    pub fn compute_checksum(&self, src_addr: Ipv4Addr, dst_addr: Ipv4Addr) -> u16 {
        crate::pdu::compute_checksum(&self.bytes, src_addr, dst_addr, PROTOCOL_UDP)
    }
}

impl<'a, T: NetworkBytesMut> UdpDatagram<'a, T> {
    /// Writes an incomplete UDP datagram, which is missing the `checksum` field.
    ///
    /// # Arguments
    ///
    /// * `buf` - A buffer containing `NetworkBytesMut` representing a datagram
    /// * `src_port` - Source port
    /// * `dst_port` - Destination port
    /// * `payload` - Datagram payload
    #[inline] // TODO remove inlining?
    fn write_incomplete_datagram(buf: T, payload: &[u8]) -> Result<Incomplete<Self>, Error> {
        let mut packet = match UdpDatagram::from_bytes(buf, None) {
            Ok(packet) => packet,
            Err(e) => return Err(e),
        };

        let len = payload.len() + PAYLOAD_OFFSET;

        // TODO working with IPv4 only for now
        if len > IPV4_MAX_UDP_PACKET_SIZE {
            return Err(Error::PayloadTooBig);
        }

        packet.bytes.shrink_unchecked(len as usize);
        packet.set_payload(payload).set_length(len as u16);

        Ok(Incomplete::new(packet))
    }

    /// Sets the source port of the UDP data gram
    #[inline]
    fn set_source_port(&mut self, src_port: u16) -> &mut Self {
        self.bytes.htons_unchecked(SOURCE_PORT_OFFSET, src_port);
        self
    }

    /// Sets the destination port of the UDP data gram
    #[inline]
    fn set_destination_port(&mut self, dst_port: u16) -> &mut Self {
        self.bytes
            .htons_unchecked(DESTINATION_PORT_OFFSET, dst_port);
        self
    }

    /// Sets the payload of the UDP datagram
    #[inline]
    fn set_payload(&mut self, payload: &[u8]) -> &mut Self {
        self.bytes[PAYLOAD_OFFSET..].copy_from_slice(payload);
        self
    }

    /// Sets the length field in the UDP datagram header
    #[inline]
    fn set_length(&mut self, len: u16) -> &mut Self {
        self.bytes.htons_unchecked(LENGTH_OFFSET, len);
        self
    }

    /// Sets the checksum of a UDP datagram
    #[inline]
    fn set_checksum(&mut self, checksum: u16) -> &mut Self {
        self.bytes.htons_unchecked(CHECKSUM_OFFSET, checksum);
        self
    }
}

impl<'a, T: NetworkBytesMut> Incomplete<UdpDatagram<'a, T>> {
    /// Transforms `self` into a `UdpDatagram<T>` by specifying values for the `source port`,
    /// `destination port`, and (optionally) the information required to compute the checksum.
    fn finalize(
        mut self,
        src_port: u16,
        dst_port: u16,
        compute_checksum: Option<(Ipv4Addr, Ipv4Addr)>,
    ) -> UdpDatagram<'a, T> {
        self.inner.set_source_port(src_port);
        self.inner.set_destination_port(dst_port);

        if let Some((src_addr, dst_addr)) = compute_checksum {
            let checksum = self.inner.compute_checksum(src_addr, dst_addr);
            self.inner.set_checksum(checksum);
        }

        self.inner
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use pdu::udp::UdpDatagram;

    use super::*;

    impl<'a, T: NetworkBytes> fmt::Debug for UdpDatagram<'a, T> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "(UDP datagram)")
        }
    }

    impl<'a, T: NetworkBytes> fmt::Debug for Incomplete<UdpDatagram<'a, T>> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "(Incomplete UDP datagram)")
        }
    }

    #[test]
    fn test_set_get() {
        let mut raw = [0u8; 30];
        let total_len = raw.len();
        let mut p: UdpDatagram<&mut [u8]> = UdpDatagram::from_bytes_unchecked(raw.as_mut());

        assert_eq!(p.source_port(), 0);
        let src_port: u16 = 213;
        p.set_source_port(src_port);
        assert_eq!(p.source_port(), src_port);

        assert_eq!(p.destination_port(), 0);
        let dst_port: u16 = 64193;
        p.set_destination_port(dst_port);
        assert_eq!(p.destination_port(), dst_port);

        assert_eq!(p.length(), 0);
        let len = 12;
        p.set_length(len);
        assert_eq!(p.length(), len);

        assert_eq!(p.checksum(), 0);
        let checksum: u16 = 32;
        p.set_checksum(32);
        assert_eq!(p.checksum(), checksum);

        let payload_length = total_len - PAYLOAD_OFFSET;
        assert_eq!(p.payload().len(), payload_length);

        let payload: Vec<u8> = (0..(payload_length as u8)).collect();
        p.set_payload(&payload);
        assert_eq!(*p.payload(), payload[..]);
    }

    #[test]
    fn test_failing_construction() {
        let mut raw = [0u8; 8];
        let huge_payload = [0u8; IPV4_MAX_UDP_PACKET_SIZE];

        assert_eq!(
            UdpDatagram::write_incomplete_datagram(raw.as_mut(), &huge_payload).unwrap_err(),
            Error::PayloadTooBig
        );

        let mut short_header = [0u8; super::PAYLOAD_OFFSET - 1];
        assert_eq!(
            UdpDatagram::from_bytes(short_header.as_mut(), None).unwrap_err(),
            Error::DatagramTooShort
        )
    }

    #[test]
    fn test_construction() {
        let mut packet = [0u8; 32 + super::PAYLOAD_OFFSET]; // 32-byte payload
        let payload: Vec<u8> = (0..32).collect();
        let src_port = 32133;
        let dst_port = 22113;
        let src_addr = Ipv4Addr::new(10, 100, 11, 21);
        let dst_addr = Ipv4Addr::new(192, 168, 121, 35);
        let p = UdpDatagram::write_incomplete_datagram(packet.as_mut(), &payload[..]).unwrap();
        let mut p = p.finalize(src_port, dst_port, Some((src_addr, dst_addr)));

        let checksum = p.checksum();
        p.set_checksum(0);
        let computed_checksum = p.compute_checksum(src_addr, dst_addr);
        assert_eq!(checksum, computed_checksum);

        p.set_checksum(checksum);
        assert_eq!(p.compute_checksum(src_addr, dst_addr), 0);

        let mut a = [1u8; 128];
        let checksum = UdpDatagram::from_bytes_unchecked(a.as_mut()).checksum();
        // Modify bytes in a by making a fake packet,
        // to allow us to modify the checksum manually
        let _ =
            UdpDatagram::from_bytes_unchecked(a.as_mut()).set_checksum(checksum.wrapping_add(1));
        let p_err = UdpDatagram::from_bytes(a.as_mut(), Some((src_addr, dst_addr))).unwrap_err();
        assert_eq!(p_err, Error::Checksum);
    }
}
