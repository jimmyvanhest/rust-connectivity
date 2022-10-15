// SPDX-License-Identifier: MIT

use anyhow::{Context, Error, Result};
use futures::{
    channel::mpsc::{self, UnboundedReceiver, UnboundedSender},
    future::join,
    stream::StreamExt,
    Future, SinkExt, TryStreamExt,
};
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
pub fn new() -> Result<(
    impl Future<Output = Result<(), Error>>,
    UnboundedReceiver<InternetConnectivity>,
)> {
    let (mut conn, handle, messages) = new_connection()?;

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

    let (tx, rx) = mpsc::unbounded();

    let checker = check_internet_connectivity(handle, messages, tx);

    let fut = async {
        join(conn, checker).await.1?;
        Ok::<(), Error>(())
    };

    Ok((fut, rx))
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
type InterfacesState = HashMap<InterfaceIndex, InterfaceState>;
/// map [InterfacesState] to [InternetConnectivity]
fn interfaces_state_to_internet_connectivity(state: &InterfacesState) -> InternetConnectivity {
    let ipv4 = state
        .values()
        .any(|s| s.up && !s.ipv4.addresses.is_empty() && !s.ipv4.gateways.is_empty());
    let ipv6 = state
        .values()
        .any(|s| s.up && !s.ipv6.addresses.is_empty() && !s.ipv6.gateways.is_empty());

    match (ipv4, ipv6) {
        (true, true) => InternetConnectivity::All,
        (true, false) => InternetConnectivity::IpV4,
        (false, true) => InternetConnectivity::IpV6,
        (false, false) => InternetConnectivity::None,
    }
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
    mut tx: UnboundedSender<InternetConnectivity>,
) -> Result<(), Error> {
    let mut state = InterfacesState::new();

    get_links(&handle, &mut state)
        .await
        .with_context(|| "get links failed")?;
    get_addresses(&handle, &mut state)
        .await
        .with_context(|| "get addresses failed")?;
    get_default_routes(&handle, IpVersion::V4, &mut state)
        .await
        .with_context(|| "get default routes ipv4 failed")?;
    get_default_routes(&handle, IpVersion::V6, &mut state)
        .await
        .with_context(|| "get default routes ipv6 failed")?;

    let mut conn = interfaces_state_to_internet_connectivity(&state);
    tx.send(conn)
        .await
        .with_context(|| "sending initial connectivity state failed")?;

    while let Some((message, _)) = futures::select! {
        // TODO add some awaitable that resolves when the receiving side of tx is closed and let it resolve None in this select, resulting in the shutdown of this while loop
        message = messages.next() => message,
    } {
        match &message.payload {
            rtnetlink::proto::NetlinkPayload::Error(e) => {
                return Err(rtnetlink::Error::NetlinkError(e.clone()))
                    .with_context(|| "received rtnetlink error");
            }
            rtnetlink::proto::NetlinkPayload::Overrun(_) => todo!(),
            rtnetlink::proto::NetlinkPayload::InnerMessage(message) => match message {
                rtnetlink::packet::RtnlMessage::NewLink(link) => {
                    add_link(link, &mut state);
                }
                rtnetlink::packet::RtnlMessage::DelLink(link) => {
                    remove_link(link, &mut state);
                }
                rtnetlink::packet::RtnlMessage::NewAddress(address) => {
                    add_address(address, &mut state);
                }
                rtnetlink::packet::RtnlMessage::DelAddress(address) => {
                    remove_address(address, &mut state);
                }
                rtnetlink::packet::RtnlMessage::NewRoute(route) => {
                    add_default_route(route, &mut state);
                }
                rtnetlink::packet::RtnlMessage::DelRoute(route) => {
                    remove_default_route(route, &mut state);
                }
                _ => {}
            },
            _ => {}
        }

        let new_conn = interfaces_state_to_internet_connectivity(&state);
        if conn != new_conn {
            conn = new_conn;
            tx.send(conn)
                .await
                .with_context(|| "sending connectivity update failed")?;
        }
    }

    Ok(())
}

/// Gets all interfaces from rtnetlink ignoring the loopback interfaces and records them in the [state](InterfacesState).
///
/// # Errors
///
/// This function will return an error if the underlying request has an error.
async fn get_links(handle: &Handle, state: &mut InterfacesState) -> Result<(), Error> {
    let mut links = handle.link().get().execute();

    while let Some(link) = links.try_next().await? {
        add_link(&link, state);
    }

    Ok(())
}
/// Gets all addresses from rtnetlink and records them in the [state](InterfacesState).
///
/// # Errors
///
/// This function will return an error if the underlying request has an error.
async fn get_addresses(handle: &Handle, state: &mut InterfacesState) -> Result<(), Error> {
    let mut addresses = handle.address().get().execute();

    while let Some(address) = addresses.try_next().await? {
        add_address(&address, state);
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
) -> Result<(), Error> {
    let mut routes = handle.route().get(ip_version).execute();

    while let Some(route) = routes.try_next().await? {
        add_default_route(&route, state);
    }

    Ok(())
}

/// Adds a link to [state](InterfacesState).
fn add_link(link: &LinkMessage, state: &mut InterfacesState) {
    if link.header.flags & IFF_LOOPBACK == 0 {
        let s = state
            .entry(link.header.index)
            .or_insert_with(|| InterfaceState::new(false));
        s.up = link.header.flags & IFF_LOWER_UP != 0;
    }
}
/// Removes a link from [state](InterfacesState).
fn remove_link(link: &LinkMessage, state: &mut InterfacesState) {
    if link.header.flags & IFF_LOOPBACK == 0 {
        state.remove(&link.header.index);
    }
}

/// Adds an address to [state](InterfacesState).
fn add_address(address: &AddressMessage, state: &mut InterfacesState) {
    if let Some((index, ip_version, address)) = parse_address(address) {
        let s = state
            .entry(index)
            .or_insert_with(|| InterfaceState::new(false));
        match ip_version {
            IpVersion::V4 => s.ipv4.addresses.insert(address),
            IpVersion::V6 => s.ipv6.addresses.insert(address),
        };
    }
}
/// Removes an address from [state](InterfacesState).
fn remove_address(address: &AddressMessage, state: &mut InterfacesState) {
    if let Some((index, ip_version, address)) = parse_address(address) {
        state.entry(index).and_modify(|state| {
            match ip_version {
                IpVersion::V4 => state.ipv4.addresses.remove(&address),
                IpVersion::V6 => state.ipv6.addresses.remove(&address),
            };
        });
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

/// Adds a default route to [state](InterfacesState).
fn add_default_route(route: &RouteMessage, state: &mut InterfacesState) {
    if let Some((index, ip_version, address, priority)) = parse_default_route(route) {
        let s = state
            .entry(index)
            .or_insert_with(|| InterfaceState::new(false));
        match ip_version {
            IpVersion::V4 => s.ipv4.gateways.insert((address, priority)),
            IpVersion::V6 => s.ipv6.gateways.insert((address, priority)),
        };
    }
}
/// Removes a default route from [state](InterfacesState).
fn remove_default_route(route: &RouteMessage, state: &mut InterfacesState) {
    if let Some((index, ip_version, address, priority)) = parse_default_route(route) {
        state.entry(index).and_modify(|state| {
            match ip_version {
                IpVersion::V4 => state.ipv4.gateways.remove(&(address, priority)),
                IpVersion::V6 => state.ipv6.gateways.remove(&(address, priority)),
            };
        });
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
