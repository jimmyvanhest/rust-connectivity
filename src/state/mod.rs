// SPDX-License-Identifier: MIT
use crate::{Connectivity, ConnectivityState};
use rtnetlink::{packet::constants::*, IpVersion};
use std::{
    cmp::max,
    collections::{HashMap, HashSet},
};

/// Represents an interface index.
type InterfaceIndex = u32;
/// Represents interface flags.
type InterfaceFlags = u32;
/// Represents a route priority.
type Priority = u32;
/// Represents an Ip Address.
type IpAddress = Vec<u8>;

/// Required information for links
pub(crate) type LinkInfo = (InterfaceIndex, InterfaceFlags);
/// Required information for addresses
pub(crate) type AddressInfo = (InterfaceIndex, IpVersion, IpAddress);
/// Required information for routes
pub(crate) type RouteInfo = (InterfaceIndex, IpVersion, IpAddress, Priority);

/// Records the state for a specific ip type.
#[derive(Debug)]
struct IpState {
    addresses: HashSet<IpAddress>,
    gateways: HashSet<(IpAddress, u32)>,
}
impl IpState {
    /// Convert to [ConnectivityState]
    fn connectivity_state(&self, up: bool) -> ConnectivityState {
        let addr = up && !self.addresses.is_empty();
        let addr_route = addr && !self.gateways.is_empty();
        match (addr, addr_route) {
            (false, _) => ConnectivityState::None,
            (true, false) => ConnectivityState::Network,
            (true, true) => ConnectivityState::Internet,
        }
    }
}
/// Records the complete state for a single interface.
#[derive(Debug)]
struct InterfaceState {
    up: bool,
    ipv4: IpState,
    ipv6: IpState,
}
impl InterfaceState {
    /// Create a new [InterfaceState] instance
    fn new(up: bool) -> Self {
        Self {
            up,
            ipv4: IpState {
                addresses: HashSet::new(),
                gateways: HashSet::new(),
            },
            ipv6: IpState {
                addresses: HashSet::new(),
                gateways: HashSet::new(),
            },
        }
    }

    /// Convert to [Connectivity]
    fn connectivity(&self) -> Connectivity {
        Connectivity {
            ipv4: self.ipv4.connectivity_state(self.up),
            ipv6: self.ipv6.connectivity_state(self.up),
        }
    }
}

/// Records the complete state for all interfaces.
pub(crate) struct InterfacesState {
    state: HashMap<InterfaceIndex, InterfaceState>,
}
impl InterfacesState {
    /// Create a new [InterfacesState] instance
    pub(crate) fn new() -> Self {
        Self {
            state: HashMap::new(),
        }
    }

    /// Convert to [Connectivity]
    pub(crate) fn connectivity(&self) -> Connectivity {
        self.state.values().fold(
            Connectivity {
                ipv4: ConnectivityState::None,
                ipv6: ConnectivityState::None,
            },
            |mut accumulator, interface_state| {
                let interface_connectivity = interface_state.connectivity();
                accumulator.ipv4 = max(accumulator.ipv4, interface_connectivity.ipv4);
                accumulator.ipv6 = max(accumulator.ipv6, interface_connectivity.ipv6);
                accumulator
            },
        )
    }

    /// Adds a link entry
    pub(crate) fn add_link(&mut self, link: LinkInfo) {
        let (index, flags) = link;
        if flags & IFF_LOOPBACK == 0 {
            let s = self
                .state
                .entry(index)
                .or_insert_with(|| InterfaceState::new(false));
            s.up = flags & IFF_LOWER_UP != 0;
        }
    }
    /// Removes a link entry
    pub(crate) fn remove_link(&mut self, link: LinkInfo) {
        let (index, _) = link;
        self.state.remove(&index);
    }

    /// Adds an address entry
    pub(crate) fn add_address(&mut self, address: AddressInfo) {
        let (index, ip_version, address) = address;
        let s = self
            .state
            .entry(index)
            .or_insert_with(|| InterfaceState::new(false));
        match ip_version {
            IpVersion::V4 => s.ipv4.addresses.insert(address),
            IpVersion::V6 => s.ipv6.addresses.insert(address),
        };
    }
    /// Removes an address entry
    pub(crate) fn remove_address(&mut self, address: AddressInfo) {
        let (index, ip_version, address) = address;
        self.state.entry(index).and_modify(|state| {
            match ip_version {
                IpVersion::V4 => state.ipv4.addresses.remove(&address),
                IpVersion::V6 => state.ipv6.addresses.remove(&address),
            };
        });
    }

    /// Adds a default route entry
    pub(crate) fn add_default_route(&mut self, route: RouteInfo) {
        let (index, ip_version, address, priority) = route;
        let s = self
            .state
            .entry(index)
            .or_insert_with(|| InterfaceState::new(false));
        match ip_version {
            IpVersion::V4 => s.ipv4.gateways.insert((address, priority)),
            IpVersion::V6 => s.ipv6.gateways.insert((address, priority)),
        };
    }
    /// Removes a default route entry
    pub(crate) fn remove_default_route(&mut self, route: RouteInfo) {
        let (index, ip_version, address, priority) = route;
        self.state.entry(index).and_modify(|state| {
            match ip_version {
                IpVersion::V4 => state.ipv4.gateways.remove(&(address, priority)),
                IpVersion::V6 => state.ipv6.gateways.remove(&(address, priority)),
            };
        });
    }
}
