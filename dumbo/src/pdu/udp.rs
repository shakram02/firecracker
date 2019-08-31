// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contains support for parsing and writing User Datagram Protocol (UDP) packets
//!
//! Details of the UDP packet specification can be found at [1] [2]
//!
//! [1]: https://tools.ietf.org/html/rfc768
//! [2]: https://tools.ietf.org/html/rfc5405

use super::bytes::{InnerBytes, NetworkBytes};

const SOURCE_PORT_OFFSET: usize = 0;
const DESTINATION_PORT_OFFSET: usize = 2;
const LENGTH_OFFSET: usize = 4;
const CHECKSUM_OFFSET: usize = 6;
const PAYLOAD_OFFSET: usize = 8;

/// Represents errors which may occur while parsing or writing a datagram.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Error {
    /// Invalid checksum
    Checksum,
    /// Invalid source port
    SrcPort,
    /// Invalid destination port.
    DstPort,
    /// The specified byte sequence is shorter than the Ethernet header length.
    SliceTooShort,
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
    fn from_bytes(bytes: T) -> Result<Self, Error> {
        if bytes.len() < PAYLOAD_OFFSET {
            return Err(Error::SliceTooShort);
        }

        // src port (optional): If not used, a value of zero is inserted.
        // src port be assumed  to be the port  to which a reply should
        // be addressed  in the absence of any other information (?)
        Ok(UdpDatagram::from_bytes_unchecked(bytes))
    }

    /// Returns the source port of the UDP datagram
    #[inline]
    pub fn src_port(&self) -> u16 {
        self.bytes.ntohs_unchecked(SOURCE_PORT_OFFSET)
    }

    /// Returns the destination port of the UDP datagram
    #[inline]
    pub fn dst_port(&self) -> u16 {
        self.bytes.ntohs_unchecked(DESTINATION_PORT_OFFSET)
    }

    /// Returns the length of the packet in byets (including its header)
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns the checksum value of the packet
    #[inline]
    pub fn checksum(&self) -> u16 {
        self.bytes.ntohs_unchecked(CHECKSUM_OFFSET)
    }

    /// Returns the payload of the UDP datagram as an `[&u8]` slice.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        self.bytes.split_at(PAYLOAD_OFFSET).1
    }
}
