// SPDX-License-Identifier: MIT

use futures::{channel::mpsc::UnboundedReceiver, stream::StreamExt, Future, TryStreamExt};
use log::trace;
use rtnetlink::{
    new_connection,
    packet::{
        constants::{self, *},
        nlas, AddressMessage, LinkMessage, RouteMessage, RtnlMessage,
    },
    proto::NetlinkMessage,
    sys::{AsyncSocket, SocketAddr},
    Handle, IpVersion,
};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    u16,
};

/// Represents connectivity to the internet.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum InternetConnectivity {
    None,
    IpV4,
    IpV6,
    All,
}

/// Creates a connection with rtnetlink and sends connectivity updates.
///
/// # Returns
///
/// The return value consists of a future that must be awaited and the receive end of a channel through which connectivity updates are received.
///
/// # Errors
///
/// This function will return an error if the rtnetlink connection failed or memberships couldn't be added
pub fn new() -> Result<
    (
        impl Future<Output = Result<(), Box<dyn Error + Send + Sync>>>,
        tokio::sync::mpsc::UnboundedReceiver<InternetConnectivity>,
    ),
    Box<dyn Error + Send + Sync>,
> {
    trace!("building rtnetlink connection");
    let (mut conn, handle, messages) = new_connection()?;

    trace!("add group membership for rtnetlink");
    let groups = vec![
        RTNLGRP_LINK,
        RTNLGRP_IPV4_IFADDR,
        RTNLGRP_IPV6_IFADDR,
        RTNLGRP_IPV4_ROUTE,
        RTNLGRP_IPV6_ROUTE,
    ];
    for group in groups {
        conn.socket_mut().socket_mut().add_membership(group)?;
    }

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    trace!("building connectivity checker");
    let checker = check_internet_connectivity(handle, messages, tx);

    let driver = async {
        trace!("waiting on rtnetlink connection and connectivity checker");
        // waiting for both of these futures can be done with a select because when one finishes the other one will not do anymore meaningful work and can be dropped.
        let r = tokio::select! {
            biased;
            r_check = checker => match r_check {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            },
            _ = conn => Ok(()),
        };
        trace!("done waiting on rtnetlink connection and connectivity checker");
        r
    };

    Ok((driver, rx))
}

/// Represents an interface index.
type InterfaceIndex = u32;
/// Represents an Ip Address.
type IpAddress = Vec<u8>;

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

/// Maps an [InterfaceIndex] to an [InterfaceState]
struct InterfacesState {
    state: HashMap<InterfaceIndex, InterfaceState>,
}
impl InterfacesState {
    fn new() -> Self {
        Self {
            state: HashMap::new(),
        }
    }
    /// convert to [InternetConnectivity]
    fn internet_connectivity(&self) -> InternetConnectivity {
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
    fn add_link(&mut self, link: &LinkMessage) {
        if link.header.flags & IFF_LOOPBACK == 0 {
            let s = self
                .state
                .entry(link.header.index)
                .or_insert_with(|| InterfaceState::new(false));
            s.up = link.header.flags & IFF_LOWER_UP != 0;
        }
    }
    /// Removes a link entry
    fn remove_link(&mut self, link: &LinkMessage) {
        if link.header.flags & IFF_LOOPBACK == 0 {
            self.state.remove(&link.header.index);
        }
    }

    /// Adds an address entry
    fn add_address(&mut self, address: &AddressMessage) {
        if let Some((index, ip_version, address)) = parse_address(address) {
            let s = self
                .state
                .entry(index)
                .or_insert_with(|| InterfaceState::new(false));
            match ip_version {
                IpVersion::V4 => s.ipv4.addresses.insert(address),
                IpVersion::V6 => s.ipv6.addresses.insert(address),
            };
        }
    }
    /// Removes an address entry
    fn remove_address(&mut self, address: &AddressMessage) {
        if let Some((index, ip_version, address)) = parse_address(address) {
            self.state.entry(index).and_modify(|state| {
                match ip_version {
                    IpVersion::V4 => state.ipv4.addresses.remove(&address),
                    IpVersion::V6 => state.ipv6.addresses.remove(&address),
                };
            });
        }
    }

    /// Adds a default route entry
    fn add_default_route(&mut self, route: &RouteMessage) {
        if let Some((index, ip_version, address, priority)) = parse_default_route(route) {
            let s = self
                .state
                .entry(index)
                .or_insert_with(|| InterfaceState::new(false));
            match ip_version {
                IpVersion::V4 => s.ipv4.gateways.insert((address, priority)),
                IpVersion::V6 => s.ipv6.gateways.insert((address, priority)),
            };
        }
    }
    /// Removes a default route entry
    fn remove_default_route(&mut self, route: &RouteMessage) {
        if let Some((index, ip_version, address, priority)) = parse_default_route(route) {
            self.state.entry(index).and_modify(|state| {
                match ip_version {
                    IpVersion::V4 => state.ipv4.gateways.remove(&(address, priority)),
                    IpVersion::V6 => state.ipv6.gateways.remove(&(address, priority)),
                };
            });
        }
    }
}

/// Extract useful information from an [AddressMessage].
///
/// Has a valid result if the address is not permanent and actually has an address.
fn parse_address(addr: &AddressMessage) -> Option<(InterfaceIndex, IpVersion, IpAddress)> {
    let flags = addr
        .nlas
        .iter()
        .find_map(|nla| {
            if let nlas::address::Nla::Flags(flags) = nla {
                Some(*flags | u32::from(addr.header.flags))
            } else {
                None
            }
        })
        .unwrap_or_else(|| addr.header.flags.into());
    if flags & constants::IFA_F_PERMANENT == 0 {
        let address = addr.nlas.iter().find_map(|nla| {
            if let nlas::address::Nla::Address(address) = nla {
                Some(address.to_vec())
            } else {
                None
            }
        });
        if let Some(address) = address {
            let ip_version = if u16::from(addr.header.family) == AF_INET {
                IpVersion::V4
            } else {
                IpVersion::V6
            };
            Some((addr.header.index, ip_version, address))
        } else {
            None
        }
    } else {
        None
    }
}
/// Extract useful information from a [RouteMessage].
///
/// Has a valid result when the message has an Output Interface and a Gateway attribute.
fn parse_default_route(
    route: &RouteMessage,
) -> Option<(InterfaceIndex, IpVersion, IpAddress, u32)> {
    let oif = route.nlas.iter().find_map(|nla| {
        if let nlas::route::Nla::Oif(oif) = nla {
            Some(*oif)
        } else {
            None
        }
    });
    let gateway = route.nlas.iter().find_map(|nla| {
        if let nlas::route::Nla::Gateway(address) = nla {
            Some(address.to_vec())
        } else {
            None
        }
    });
    let priority = route.nlas.iter().find_map(|nla| {
        if let nlas::route::Nla::Priority(priority) = nla {
            Some(priority)
        } else {
            None
        }
    });
    if let (Some(oif), Some(gateway), Some(priority)) = (oif, gateway, priority) {
        let ip_version = if u16::from(route.header.address_family) == AF_INET {
            IpVersion::V4
        } else {
            IpVersion::V6
        };
        Some((oif, ip_version, gateway, *priority))
    } else {
        None
    }
}

#[derive(Debug, thiserror::Error)]
enum ConnectivityError {
    #[error("an overrun occurred with data {0:?}")]
    Overrun(Vec<u8>),
}

/// Builds and updates an internal state with a subset of the information provided by rtnetlink.
///
/// From this state the internet connectivity with will be determined and send to tx.
///
/// This function will compete when the receiving end of tx is dropped.
///
/// # Errors
///
/// This function will return an error if any of the underlying rtnetlink requests return an error.
async fn check_internet_connectivity(
    handle: Handle,
    mut messages: UnboundedReceiver<(NetlinkMessage<RtnlMessage>, SocketAddr)>,
    tx: tokio::sync::mpsc::UnboundedSender<InternetConnectivity>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    trace!("getting initial state");
    let mut state = InterfacesState::new();
    get_links(&handle, &mut state).await?;
    get_addresses(&handle, &mut state).await?;
    get_default_routes(&handle, IpVersion::V4, &mut state).await?;
    get_default_routes(&handle, IpVersion::V6, &mut state).await?;
    trace!("got initial state");

    let mut conn = state.internet_connectivity();
    trace!("emit initial connectivity {:?}", conn);
    tx.send(conn)?;

    trace!("waiting for rtnetlink messages");
    let closed = tx.closed();
    tokio::pin!(closed);
    while let Some((message, _)) = tokio::select! {
        biased;
        _ = &mut closed => None,
        message = messages.next() => message,
    } {
        match &message.payload {
            rtnetlink::proto::NetlinkPayload::Error(e) => {
                return Err(Box::new(rtnetlink::Error::NetlinkError(e.clone())));
            }
            rtnetlink::proto::NetlinkPayload::Overrun(e) => {
                return Err(Box::new(ConnectivityError::Overrun(e.clone())));
            }
            rtnetlink::proto::NetlinkPayload::InnerMessage(message) => match message {
                rtnetlink::packet::RtnlMessage::NewLink(link) => {
                    state.add_link(link);
                }
                rtnetlink::packet::RtnlMessage::DelLink(link) => {
                    state.remove_link(link);
                }
                rtnetlink::packet::RtnlMessage::NewAddress(address) => {
                    state.add_address(address);
                }
                rtnetlink::packet::RtnlMessage::DelAddress(address) => {
                    state.remove_address(address);
                }
                rtnetlink::packet::RtnlMessage::NewRoute(route) => {
                    state.add_default_route(route);
                }
                rtnetlink::packet::RtnlMessage::DelRoute(route) => {
                    state.remove_default_route(route);
                }
                _ => {}
            },
            _ => {}
        }

        let new_conn = state.internet_connectivity();
        if conn != new_conn {
            conn = new_conn;
            trace!("emit updated connectivity {:?}", conn);
            tx.send(conn)?;
        }
    }
    trace!("no more rtnetlink messages");

    Ok(())
}

/// Gets all interfaces from rtnetlink ignoring the loopback interfaces and records them in the [state](InterfacesState).
///
/// # Errors
///
/// This function will return an error if the underlying request has an error.
async fn get_links(
    handle: &Handle,
    state: &mut InterfacesState,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut links = handle.link().get().execute();

    while let Some(link) = links.try_next().await? {
        state.add_link(&link);
    }

    Ok(())
}
/// Gets all addresses from rtnetlink and records them in the [state](InterfacesState).
///
/// # Errors
///
/// This function will return an error if the underlying request has an error.
async fn get_addresses(
    handle: &Handle,
    state: &mut InterfacesState,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut addresses = handle.address().get().execute();

    while let Some(address) = addresses.try_next().await? {
        state.add_address(&address);
    }

    Ok(())
}
/// Gets all default routes from rtnetlink for a specified [IpVersion] and records them in the [state](InterfacesState).
///
/// # Errors
///
/// This function will return an error if the underlying request has an error.
async fn get_default_routes(
    handle: &Handle,
    ip_version: IpVersion,
    state: &mut InterfacesState,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut routes = handle.route().get(ip_version).execute();

    while let Some(route) = routes.try_next().await? {
        state.add_default_route(&route);
    }

    Ok(())
}
