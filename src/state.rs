// SPDX-License-Identifier: MIT

//! The platform independent internal state for this crate

use crate::{Connectivity, ConnectivityState};
use core::cmp::max;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// Represents an interface index.
type InterfaceIndex = u32;
/// Boolean indicating an interface is a loopback device
type LoopBack = bool;
/// Boolean indicating an interface has a carrier
type Carrier = bool;
/// Represents a route priority.
type Priority = u32;

/// Required information for links
pub type LinkInfo = (InterfaceIndex, LoopBack, Carrier);
/// Required information for addresses
pub type AddressInfo = (InterfaceIndex, IpAddr);
/// Required information for routes
pub type RouteInfo = (InterfaceIndex, IpAddr, Priority);

/// Records the state for a specific ip type.
#[derive(Debug)]
struct AddressGateway<T> {
    /// The addresses associated with this [AddressGateway]
    addresses: HashSet<T>,
    /// The gateways associated with this [AddressGateway]
    gateways: HashSet<(T, Priority)>,
}
impl<T> AddressGateway<T> {
    /// Convert to [`ConnectivityState`]
    fn connectivity_state(&self, up: bool) -> ConnectivityState {
        let address = !self.addresses.is_empty();
        let gateway = !self.gateways.is_empty();
        match (up, address, gateway) {
            (false, _, _) | (true, false, _) => ConnectivityState::None,
            (true, true, false) => ConnectivityState::Network,
            (true, true, true) => ConnectivityState::Internet,
        }
    }
}
/// Records the complete state for a single interface.
#[derive(Debug)]
struct Interface {
    /// Whether the interface is able to communicate with the network
    up: bool,
    /// The ipv4 [AddressGateway]  for the interface
    ipv4: AddressGateway<Ipv4Addr>,
    /// The ipv6 [AddressGateway]  for the interface
    ipv6: AddressGateway<Ipv6Addr>,
}
impl Interface {
    /// Create a new [`Interface`] instance
    fn new(up: bool) -> Self {
        Self {
            up,
            ipv4: AddressGateway {
                addresses: HashSet::new(),
                gateways: HashSet::new(),
            },
            ipv6: AddressGateway {
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
pub struct Interfaces {
    /// The mapping between [InterfaceIndex] and [Interface]
    state: HashMap<InterfaceIndex, Interface>,
}
impl Interfaces {
    /// Create a new [`Interfaces`] instance
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
        let (index, loop_back, carrier) = link;
        if !loop_back {
            let s = self
                .state
                .entry(index)
                .or_insert_with(|| Interface::new(false));
            s.up = carrier;
        }
    }
    /// Removes a link entry
    pub(crate) fn remove_link(&mut self, link: LinkInfo) {
        let (index, _, _) = link;
        self.state.remove(&index);
    }

    /// Adds an address entry
    pub(crate) fn add_address(&mut self, address_info: AddressInfo) {
        let (index, address) = address_info;
        let entry = self
            .state
            .entry(index)
            .or_insert_with(|| Interface::new(false));
        match address {
            IpAddr::V4(ipv4_address) => entry.ipv4.addresses.insert(ipv4_address),
            IpAddr::V6(ipv6_address) => entry.ipv6.addresses.insert(ipv6_address),
        };
    }
    /// Removes an address entry
    pub(crate) fn remove_address(&mut self, address_info: AddressInfo) {
        let (index, address) = address_info;
        self.state.entry(index).and_modify(|entry| {
            match address {
                IpAddr::V4(ipv4_address) => entry.ipv4.addresses.remove(&ipv4_address),
                IpAddr::V6(ipv6_address) => entry.ipv6.addresses.remove(&ipv6_address),
            };
        });
    }

    /// Adds a default route entry
    pub(crate) fn add_default_route(&mut self, route: RouteInfo) {
        let (index, address, priority) = route;
        let entry = self
            .state
            .entry(index)
            .or_insert_with(|| Interface::new(false));
        match address {
            IpAddr::V4(ipv4_address) => entry.ipv4.gateways.insert((ipv4_address, priority)),
            IpAddr::V6(ipv6_address) => entry.ipv6.gateways.insert((ipv6_address, priority)),
        };
    }
    /// Removes a default route entry
    pub(crate) fn remove_default_route(&mut self, route: RouteInfo) {
        let (index, address, priority) = route;
        self.state.entry(index).and_modify(|entry| {
            match address {
                IpAddr::V4(ipv4_address) => entry.ipv4.gateways.remove(&(ipv4_address, priority)),
                IpAddr::V6(ipv6_address) => entry.ipv6.gateways.remove(&(ipv6_address, priority)),
            };
        });
    }
}
