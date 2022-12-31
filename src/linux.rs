// SPDX-License-Identifier: MIT

//! The linux implementation for this crate using rt-netlink.

use crate::{
    state::{AddressInfo, Interfaces, LinkInfo, RouteInfo},
    Connectivity,
};
use core::fmt::Display;
use futures::{channel::mpsc::UnboundedReceiver, stream::StreamExt, Future, TryStreamExt};
use log::debug;
use rtnetlink::{
    new_connection,
    packet::{
        constants::{
            self, AF_INET, AF_INET6, IFF_LOOPBACK, IFF_LOWER_UP, RTNLGRP_IPV4_IFADDR,
            RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV6_IFADDR, RTNLGRP_IPV6_ROUTE, RTNLGRP_LINK,
        },
        nlas, AddressMessage, LinkMessage, RouteMessage, RtnlMessage,
    },
    proto::{NetlinkMessage, NetlinkPayload},
    sys::{AsyncSocket, SocketAddr},
    Handle, IpVersion,
};
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// Converts a vector to an array.
fn vec_to_array<T, const N: usize>(v: Vec<T>) -> Result<[T; N], Vec<T>> {
    v.try_into()
}

/// assigns to assign from assignee only when they are different,
///
/// # Returns
///
/// true if the arguments were different and false otherwise
fn diff_assign<T>(assign: &mut T, assignee: T) -> bool
where
    T: Eq,
{
    if *assign == assignee {
        false
    } else {
        *assign = assignee;
        true
    }
}

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
pub fn new() -> Result<
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

    #[allow(clippy::arithmetic_side_effects, clippy::integer_arithmetic)]
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

/// Extract useful information from a [`LinkMessage`].
const fn parse_link(link: &LinkMessage) -> LinkInfo {
    (
        link.header.index,
        link.header.flags & IFF_LOOPBACK != 0,
        link.header.flags & IFF_LOWER_UP != 0,
    )
}
/// Extract useful information from an [`AddressMessage`].
///
/// Has a valid result if the address is not permanent and actually has an address.
fn parse_address(addr: &AddressMessage) -> Option<AddressInfo> {
    let address = addr.nlas.iter().find_map(|nla| {
        if let nlas::address::Nla::Address(ref address) = *nla {
            Some(address)
        } else {
            None
        }
    })?;
    let flags = addr
        .nlas
        .iter()
        .find_map(|nla| {
            if let nlas::address::Nla::Flags(flags) = *nla {
                Some(flags | u32::from(addr.header.flags))
            } else {
                None
            }
        })
        .unwrap_or_else(|| u32::from(addr.header.flags));
    let ip_address = match u16::from(addr.header.family) {
        AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
            vec_to_array(address.clone()).ok()?,
        ))),
        AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(
            vec_to_array(address.clone()).ok()?,
        ))),
        _ => None,
    }?;
    (flags & constants::IFA_F_PERMANENT == 0).then_some((addr.header.index, ip_address))
}
/// Extract useful information from a [`RouteMessage`].
///
/// Has a valid result when the message has an Output Interface, Gateway, and priority.
fn parse_default_route(route: &RouteMessage) -> Option<RouteInfo> {
    let oif = route.nlas.iter().find_map(|nla| {
        if let nlas::route::Nla::Oif(oif) = *nla {
            Some(oif)
        } else {
            None
        }
    })?;
    let gateway = route.nlas.iter().find_map(|nla| {
        if let nlas::route::Nla::Gateway(ref address) = *nla {
            Some(address)
        } else {
            None
        }
    })?;
    let priority = route.nlas.iter().find_map(|nla| {
        if let nlas::route::Nla::Priority(priority) = *nla {
            Some(priority)
        } else {
            None
        }
    })?;
    let ip_address = match u16::from(route.header.address_family) {
        AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
            vec_to_array(gateway.clone()).ok()?,
        ))),
        AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(
            vec_to_array(gateway.clone()).ok()?,
        ))),
        _ => None,
    }?;
    Some((oif, ip_address, priority))
}

#[derive(Debug)]
/// Error enum for things that are not actual errors
enum ConnectivityError {
    /// Forward for [NetlinkPayload::Overrun]
    Overrun(Vec<u8>),
}
impl Display for ConnectivityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Overrun(_) => {
                write!(f, "An rtnetlink overrun occurred")?;
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
    let mut state = Interfaces::new();
    get_links(&handle, &mut state).await?;
    get_addresses(&handle, &mut state).await?;
    get_default_routes(&handle, IpVersion::V4, &mut state).await?;
    get_default_routes(&handle, IpVersion::V6, &mut state).await?;
    debug!("got initial state");

    let mut connectivity = state.connectivity();
    debug!("emit initial connectivity {:?}", connectivity);
    tx.send(connectivity)?;

    debug!("waiting for rtnetlink messages or transmit channel closed");
    #[allow(clippy::arithmetic_side_effects, clippy::integer_arithmetic)]
    while let Some((message, _)) = tokio::select! {
        biased;
        _ = tx.closed() => {
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
        #[allow(clippy::wildcard_enum_match_arm)]
        match message.payload {
            NetlinkPayload::Error(e) => {
                return Err(Box::new(rtnetlink::Error::NetlinkError(e)));
            }
            NetlinkPayload::Overrun(e) => {
                return Err(Box::new(ConnectivityError::Overrun(e)));
            }
            NetlinkPayload::InnerMessage(inner_message) => match inner_message {
                RtnlMessage::NewLink(ref link) => {
                    state.add_link(parse_link(link));
                }
                RtnlMessage::DelLink(ref link) => {
                    state.remove_link(parse_link(link));
                }
                RtnlMessage::NewAddress(ref address) => {
                    if let Some(parsed_address) = parse_address(address) {
                        state.add_address(parsed_address);
                    }
                }
                RtnlMessage::DelAddress(ref address) => {
                    if let Some(parsed_address) = parse_address(address) {
                        state.remove_address(parsed_address);
                    }
                }
                RtnlMessage::NewRoute(ref route) => {
                    if let Some(parsed_route) = parse_default_route(route) {
                        state.add_default_route(parsed_route);
                    }
                }
                RtnlMessage::DelRoute(ref route) => {
                    if let Some(parsed_route) = parse_default_route(route) {
                        state.remove_default_route(parsed_route);
                    }
                }
                _ => {}
            },
            _ => {}
        }

        if diff_assign(&mut connectivity, state.connectivity()) {
            debug!("emit updated connectivity {:?}", connectivity);
            tx.send(connectivity)?;
        }
    }

    Ok(())
}

/// Gets all interfaces from rtnetlink ignoring the loopback interfaces and records them in the [state](Interfaces).
///
/// # Errors
///
/// This function will return an error if the underlying request has an error.
async fn get_links(
    handle: &Handle,
    state: &mut Interfaces,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut links = handle.link().get().execute();

    while let Some(ref link) = links.try_next().await? {
        state.add_link(parse_link(link));
    }

    Ok(())
}
/// Gets all addresses from rtnetlink and records them in the [state](Interfaces).
///
/// # Errors
///
/// This function will return an error if the underlying request has an error.
async fn get_addresses(
    handle: &Handle,
    state: &mut Interfaces,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut addresses = handle.address().get().execute();

    while let Some(ref address) = addresses.try_next().await? {
        if let Some(parsed_address) = parse_address(address) {
            state.add_address(parsed_address);
        }
    }

    Ok(())
}
/// Gets all default routes from rtnetlink for a specified [`IpVersion`] and records them in the [state](Interfaces).
///
/// # Errors
///
/// This function will return an error if the underlying request has an error.
async fn get_default_routes(
    handle: &Handle,
    ip_version: IpVersion,
    state: &mut Interfaces,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut routes = handle.route().get(ip_version).execute();

    while let Some(ref route) = routes.try_next().await? {
        if let Some(parsed_route) = parse_default_route(route) {
            state.add_default_route(parsed_route);
        }
    }

    Ok(())
}
