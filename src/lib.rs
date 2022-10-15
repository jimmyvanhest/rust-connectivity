// SPDX-License-Identifier: MIT

use std::{
    collections::{HashMap, HashSet},
    u16,
};

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
        nlas, AddressMessage, RouteMessage, RtnlMessage,
    },
    proto::NetlinkMessage,
    sys::{AsyncSocket, SocketAddr},
    Handle, IpVersion,
};

/// Represents connectivity to the internet.
#[derive(Clone, Copy)]
pub struct InternetConnectivity {
    ipv4: bool,
    ipv6: bool,
}
impl InternetConnectivity {
    fn new() -> Self {
        Self {
            ipv4: false,
            ipv6: false,
        }
    }

    pub fn ipv4(&self) -> bool {
        self.ipv4
    }

    fn set_ipv4(&mut self, ipv4: bool) {
        self.ipv4 = ipv4;
    }

    pub fn ipv6(&self) -> bool {
        self.ipv6
    }

    fn set_ipv6(&mut self, ipv6: bool) {
        self.ipv6 = ipv6;
    }

    pub fn any(&self) -> bool {
        self.ipv4() || self.ipv6()
    }

    pub fn all(&self) -> bool {
        self.ipv4() && self.ipv6()
    }
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
    gateways: HashSet<IpAddress>,
}
impl IpState {
    fn new() -> Self {
        Self {
            addresses: HashSet::<IpAddress>::new(),
            gateways: HashSet::<IpAddress>::new(),
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
    fn new(up: bool) -> Self {
        Self {
            up,
            ipv4: IpState::new(),
            ipv6: IpState::new(),
        }
    }
}

/// Maps an [InterfaceIndex] to an [InterfaceState]
type InterfacesState = HashMap<InterfaceIndex, InterfaceState>;
/// Check if the current representation of [state](InterfacesState) has an ipv6 connection.
fn has_ipv4_connectivity(state: &InterfacesState) -> bool {
    state
        .iter()
        .any(|(_, s)| s.up && !s.ipv4.addresses.is_empty() && !s.ipv4.gateways.is_empty())
}
/// Check if the current representation of [state](InterfacesState) has an ipv6 connection.
fn has_ipv6_connectivity(state: &InterfacesState) -> bool {
    state
        .iter()
        .any(|(_, s)| s.up && !s.ipv6.addresses.is_empty() && !s.ipv6.gateways.is_empty())
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
    let mut conn = InternetConnectivity::new();
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

    conn.set_ipv4(has_ipv4_connectivity(&state));
    conn.set_ipv6(has_ipv6_connectivity(&state));
    tx.send(conn)
        .await
        .with_context(|| "sending initial connectivity state failed")?;

    while let Some((message, _)) = futures::select! {
        // TODO add some awaitable that resolves when the receiving side of tx is closed and let it resolve None in this select, resulting in the shutdown of this while loop
        message = messages.next() => message,
    } {
        match &message.payload {
            rtnetlink::proto::NetlinkPayload::Error(_) => todo!(),
            rtnetlink::proto::NetlinkPayload::Overrun(_) => todo!(),
            rtnetlink::proto::NetlinkPayload::InnerMessage(message) => match message {
                rtnetlink::packet::RtnlMessage::NewLink(link) => {
                    if link.header.flags & IFF_LOOPBACK == 0 {
                        let up = link.header.flags & IFF_UP != 0;
                        state
                            .entry(link.header.index)
                            .and_modify(|s| {
                                s.up = up;
                            })
                            .or_insert_with(|| InterfaceState::new(up));
                    }
                }
                rtnetlink::packet::RtnlMessage::DelLink(link) => {
                    if link.header.flags & IFF_LOOPBACK == 0 {
                        state.entry(link.header.index).and_modify(|s| {
                            s.up = false;
                        });
                    }
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

        let ipv4 = has_ipv4_connectivity(&state);
        let ipv6 = has_ipv6_connectivity(&state);
        if ipv4 != conn.ipv4() || ipv6 != conn.ipv6() {
            conn.set_ipv4(ipv4);
            conn.set_ipv6(ipv6);
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
        if link.header.flags & IFF_LOOPBACK == 0 {
            state.insert(
                link.header.index,
                InterfaceState::new(link.header.flags & IFF_UP != 0),
            );
        }
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
/// Adds an address to [state](InterfacesState).
fn add_address(address: &AddressMessage, state: &mut InterfacesState) {
    if let Some((index, ip_version, address)) = parse_address(address) {
        state
            .entry(index)
            .and_modify(|state| {
                match ip_version {
                    IpVersion::V4 => state.ipv4.addresses.insert(address.to_vec()),
                    IpVersion::V6 => state.ipv6.addresses.insert(address.to_vec()),
                };
            })
            .or_insert_with(|| {
                let mut s = InterfaceState::new(false);
                match ip_version {
                    IpVersion::V4 => s.ipv4.addresses.insert(address),
                    IpVersion::V6 => s.ipv6.addresses.insert(address),
                };
                s
            });
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
                Some(*flags)
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
/// Adds a default route to [state](InterfacesState).
fn add_default_route(route: &RouteMessage, state: &mut InterfacesState) {
    if let Some((index, ip_version, address)) = parse_default_route(route) {
        state
            .entry(index)
            .and_modify(|state| {
                match ip_version {
                    IpVersion::V4 => state.ipv4.gateways.insert(address.to_vec()),
                    IpVersion::V6 => state.ipv6.gateways.insert(address.to_vec()),
                };
            })
            .or_insert_with(|| {
                let mut s = InterfaceState::new(false);
                match ip_version {
                    IpVersion::V4 => s.ipv4.gateways.insert(address),
                    IpVersion::V6 => s.ipv6.gateways.insert(address),
                };
                s
            });
    }
}
/// Removes a default route from [state](InterfacesState).
fn remove_default_route(route: &RouteMessage, state: &mut InterfacesState) {
    if let Some((index, ip_version, address)) = parse_default_route(route) {
        state.entry(index).and_modify(|state| {
            match ip_version {
                IpVersion::V4 => state.ipv4.gateways.remove(&address),
                IpVersion::V6 => state.ipv6.gateways.remove(&address),
            };
        });
    }
}
/// Extract useful information from a [RouteMessage].
///
/// Has a valid result when the message has an Output Interface and a Gateway attribute.
fn parse_default_route(route: &RouteMessage) -> Option<(InterfaceIndex, IpVersion, IpAddress)> {
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
    if let (Some(oif), Some(gateway)) = (oif, gateway) {
        let ip_version = if u16::from(route.header.address_family) == AF_INET {
            IpVersion::V4
        } else {
            IpVersion::V6
        };
        Some((oif, ip_version, gateway))
    } else {
        None
    }
}
