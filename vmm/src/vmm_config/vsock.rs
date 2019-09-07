// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter, Result};
use std::result;

/// This struct represents the strongly typed equivalent of the json body
/// from vsock related requests.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VsockDeviceConfig {
    /// ID of the vsock device.
    pub vsock_id: String,
    /// A 32-bit Context Identifier (CID) used to identify the guest.
    pub guest_cid: u32,
    /// Path to local unix socket.
    pub uds_path: String,
}

/// Errors associated with `VsockDeviceConfig`.
#[derive(Debug)]
pub enum VsockError {
    /// The Context Identifier is already in use.
    GuestCIDAlreadyInUse(u32),
    /// The update is not allowed after booting the microvm.
    UpdateNotAllowedPostBoot,
}

impl Display for VsockError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use self::VsockError::*;
        match *self {
            GuestCIDAlreadyInUse(ref cid) => {
                write!(f, "{}", format!("The guest CID {} is already in use.", cid))
            }
            UpdateNotAllowedPostBoot => {
                write!(f, "The update operation is not allowed after boot.",)
            }
        }
    }
}

/// A list with all the vsock devices.
#[derive(Default)]
pub struct VsockDeviceConfigs {
    configs: Vec<VsockDeviceConfig>,
}

impl VsockDeviceConfigs {
    /// Creates an empty list of NetworkInterfaceConfig.
    pub fn new() -> Self {
        VsockDeviceConfigs {
            configs: Vec::new(),
        }
    }

    fn contains_cid(&self, cid: u32) -> bool {
        for cfg in self.configs.iter() {
            if cfg.guest_cid == cid {
                return true;
            }
        }
        false
    }
    /// Adds `vsock_config` in the list of vsock device configurations.
    /// If an entry with the same id already exists, it will update the existing
    /// entry.
    pub fn add(&mut self, cfg: VsockDeviceConfig) -> result::Result<(), VsockError> {
        if self.contains_cid(cfg.guest_cid) {
            return Err(VsockError::GuestCIDAlreadyInUse(cfg.guest_cid));
        }

        match self
            .configs
            .iter()
            .position(|cfg_from_list| cfg_from_list.vsock_id.as_str() == cfg.vsock_id.as_str())
        {
            Some(index) => self.configs[index] = cfg,
            None => self.configs.push(cfg),
        }

        Ok(())
    }

    /// Returns an immutable iterator over the vsock available configurations.
    pub fn iter(&mut self) -> ::std::slice::Iter<VsockDeviceConfig> {
        self.configs.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vsock_device_config() {
        const CID: u32 = 52;
        let cfg = VsockDeviceConfig {
            vsock_id: String::from("vsock"),
            guest_cid: CID,
            uds_path: String::from("/tmp/vsock.sock"),
        };
        let mut cfg_list = VsockDeviceConfigs::new();

        cfg_list.add(cfg.clone()).unwrap();
        assert!(cfg_list.contains_cid(CID));

        assert_eq!(
            format!("{}", cfg_list.add(cfg.clone()).err().unwrap()),
            format!("The guest CID {} is already in use.", CID),
        );

        let mut cfg2 = cfg.clone();
        cfg2.guest_cid = CID + 1;
        assert!(cfg_list.add(cfg2).is_ok());
    }
}
