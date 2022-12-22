// SPDX-License-Identifier: MIT
use crate::{
    state::{AddressInfo, InterfacesState, LinkInfo, RouteInfo},
    Connectivity,
};
use futures::{channel::mpsc::UnboundedReceiver, stream::StreamExt, Future, TryStreamExt};
use log::debug;
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
use std::{error::Error, fmt::Display};

/// Creates a connection with rtnetlink and sends connectivity updates.
///
/// # Returns
///
/// The return value consists of a future that must be awaited and the receive end of a channel through which connectivity updates are received.
///
/// # Notes
/// 
/// When the receive end of the channel is dropped, the future will run to completion.
/// 
/// # Errors
///
/// This function will return an error if the rtnetlink connection failed or memberships couldn't be added.
/// The returned future can fail when a rtnetlink error was received.
pub(crate) fn new() -> Result<
    (
        impl Future<Output = Result<(), Box<dyn Error + Send + Sync>>>,
        tokio::sync::mpsc::UnboundedReceiver<Connectivity>,
    ),
    Box<dyn Error + Send + Sync>,
> {
    debug!("creating rtnetlink connection");
    let (mut conn, handle, messages) = new_connection()?;

    debug!("add group membership for rtnetlink");
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

    let checker = check_internet_connectivity(handle, messages, tx);

    let driver = async {
        debug!("waiting on rtnetlink connection or connectivity checker");
        // waiting for both of these futures can be done with a select because when one finishes the other one will not do anymore meaningful work and can be dropped.
        tokio::select! {
            biased;
            r_check = checker => {
                r_check?;
            },
            _ = conn => (),
        };
        debug!("done waiting on rtnetlink connection or connectivity checker");

        Ok(())
    };

    Ok((driver, rx))
}

/// Extract useful information from a [LinkMessage].
fn parse_link(link: &LinkMessage) -> LinkInfo {
    (link.header.index, link.header.flags)
}
/// Extract useful information from an [AddressMessage].
///
/// Has a valid result if the address is not permanent and actually has an address.
fn parse_address(addr: &AddressMessage) -> Option<AddressInfo> {
    let address = addr.nlas.iter().find_map(|nla| {
        if let nlas::address::Nla::Address(address) = nla {
            Some(address)
        } else {
            None
        }
    })?;
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
        .unwrap_or_else(|| u32::from(addr.header.flags));
    if flags & constants::IFA_F_PERMANENT == 0 {
        let ip_version = if u16::from(addr.header.family) == AF_INET {
            IpVersion::V4
        } else {
            IpVersion::V6
        };
        Some((addr.header.index, ip_version, address.to_vec()))
    } else {
        None
    }
}
/// Extract useful information from a [RouteMessage].
///
/// Has a valid result when the message has an Output Interface, Gateway, and priority.
fn parse_default_route(route: &RouteMessage) -> Option<RouteInfo> {
    let oif = route.nlas.iter().find_map(|nla| {
        if let nlas::route::Nla::Oif(oif) = nla {
            Some(oif)
        } else {
            None
        }
    })?;
    let gateway = route.nlas.iter().find_map(|nla| {
        if let nlas::route::Nla::Gateway(address) = nla {
            Some(address)
        } else {
            None
        }
    })?;
    let priority = route.nlas.iter().find_map(|nla| {
        if let nlas::route::Nla::Priority(priority) = nla {
            Some(priority)
        } else {
            None
        }
    })?;
    let ip_version = if u16::from(route.header.address_family) == AF_INET {
        IpVersion::V4
    } else {
        IpVersion::V6
    };
    Some((*oif, ip_version, gateway.to_vec(), *priority))
}

#[derive(Debug)]
enum ConnectivityError {
    Overrun(Vec<u8>),
}
impl Display for ConnectivityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectivityError::Overrun(data) => {
                write!(f, "An rtnetlink overrun occurred with data: {0:?}", data)?;
            }
        }

        Ok(())
    }
}
impl Error for ConnectivityError {}

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
    tx: tokio::sync::mpsc::UnboundedSender<Connectivity>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    debug!("getting initial state");
    let mut state = InterfacesState::new();
    get_links(&handle, &mut state).await?;
    get_addresses(&handle, &mut state).await?;
    get_default_routes(&handle, IpVersion::V4, &mut state).await?;
    get_default_routes(&handle, IpVersion::V6, &mut state).await?;
    debug!("got initial state");

    let mut conn = state.connectivity();
    debug!("emit initial connectivity {:?}", conn);
    tx.send(conn)?;

    debug!("waiting for rtnetlink messages or transmit channel closed");
    let closed = tx.closed();
    tokio::pin!(closed);
    while let Some((message, _)) = tokio::select! {
        biased;
        _ = &mut closed => {
            debug!("transmit channel closed");
            None
        },
        message = messages.next() => {
            if message.is_none() {
                debug!("no more rtnetlink messages");
            }
            message
        },
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
                    state.add_link(parse_link(link));
                }
                rtnetlink::packet::RtnlMessage::DelLink(link) => {
                    state.remove_link(parse_link(link));
                }
                rtnetlink::packet::RtnlMessage::NewAddress(address) => {
                    if let Some(address) = parse_address(address) {
                        state.add_address(address);
                    }
                }
                rtnetlink::packet::RtnlMessage::DelAddress(address) => {
                    if let Some(address) = parse_address(address) {
                        state.remove_address(address);
                    }
                }
                rtnetlink::packet::RtnlMessage::NewRoute(route) => {
                    if let Some(route) = parse_default_route(route) {
                        state.add_default_route(route);
                    }
                }
                rtnetlink::packet::RtnlMessage::DelRoute(route) => {
                    if let Some(route) = parse_default_route(route) {
                        state.remove_default_route(route);
                    }
                }
                _ => {}
            },
            _ => {}
        }

        let new_conn = state.connectivity();
        if conn != new_conn {
            conn = new_conn;
            debug!("emit updated connectivity {:?}", conn);
            tx.send(conn)?;
        }
    }

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
        state.add_link(parse_link(&link));
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
        if let Some(address) = parse_address(&address) {
            state.add_address(address);
        }
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
        if let Some(route) = parse_default_route(&route) {
            state.add_default_route(route);
        }
    }

    Ok(())
}
