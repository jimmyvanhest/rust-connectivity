use crate::InternetConnectivity;
use rtnetlink::{packet::constants::*, IpVersion};
use std::collections::{HashMap, HashSet};

/// Represents an interface index.
type InterfaceIndex = u32;
/// Represents interface flags.
type InterfaceFlags = u32;
/// Represents a route priority.
type Priority = u32;
/// Represents an Ip Address.
type IpAddress = Vec<u8>;

/// Required information for links
pub type LinkInfo = (InterfaceIndex, InterfaceFlags);
/// Required information for addresses
pub type AddressInfo = (InterfaceIndex, IpVersion, IpAddress);
/// Required information for routes
pub type RouteInfo = (InterfaceIndex, IpVersion, IpAddress, Priority);

/// Records the state for a specific ip type.
#[derive(Debug)]
struct IpState {
    addresses: HashSet<IpAddress>,
    gateways: HashSet<(IpAddress, u32)>,
}
/// Records the complete state for a single interface.
#[derive(Debug)]
struct InterfaceState {
    up: bool,
    ipv4: IpState,
    ipv6: IpState,
}
impl InterfaceState {
    fn new(up: bool) -> Self {
        Self {
            up,
            ipv4: IpState {
                addresses: HashSet::<IpAddress>::new(),
                gateways: HashSet::<(IpAddress, u32)>::new(),
            },
            ipv6: IpState {
                addresses: HashSet::<IpAddress>::new(),
                gateways: HashSet::<(IpAddress, u32)>::new(),
            },
        }
    }
}

/// Records the complete state for all interfaces.
pub struct InterfacesState {
    state: HashMap<InterfaceIndex, InterfaceState>,
}
impl InterfacesState {
    /// Create a new InterfacesState instance
    pub fn new() -> Self {
        Self {
            state: HashMap::new(),
        }
    }

    /// Convert to [InternetConnectivity]
    pub fn internet_connectivity(&self) -> InternetConnectivity {
        let ipv4 = self
            .state
            .values()
            .any(|s| s.up && !s.ipv4.addresses.is_empty() && !s.ipv4.gateways.is_empty());
        let ipv6 = self
            .state
            .values()
            .any(|s| s.up && !s.ipv6.addresses.is_empty() && !s.ipv6.gateways.is_empty());

        match (ipv4, ipv6) {
            (true, true) => InternetConnectivity::All,
            (true, false) => InternetConnectivity::IpV4,
            (false, true) => InternetConnectivity::IpV6,
            (false, false) => InternetConnectivity::None,
        }
    }

    /// Adds a link entry
    pub fn add_link(&mut self, link: LinkInfo) {
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
    pub fn remove_link(&mut self, link: LinkInfo) {
        let (index, _) = link;
        self.state.remove(&index);
    }

    /// Adds an address entry
    pub fn add_address(&mut self, address: AddressInfo) {
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
    pub fn remove_address(&mut self, address: AddressInfo) {
        let (index, ip_version, address) = address;
        self.state.entry(index).and_modify(|state| {
            match ip_version {
                IpVersion::V4 => state.ipv4.addresses.remove(&address),
                IpVersion::V6 => state.ipv6.addresses.remove(&address),
            };
        });
    }

    /// Adds a default route entry
    pub fn add_default_route(&mut self, route: RouteInfo) {
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
    pub fn remove_default_route(&mut self, route: RouteInfo) {
        let (index, ip_version, address, priority) = route;
        self.state.entry(index).and_modify(|state| {
            match ip_version {
                IpVersion::V4 => state.ipv4.gateways.remove(&(address, priority)),
                IpVersion::V6 => state.ipv6.gateways.remove(&(address, priority)),
            };
        });
    }
}
