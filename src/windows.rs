// SPDX-License-Identifier: MIT

//! The windows implementation for this crate.

use crate::{state::Interfaces, Connectivity};
use core::{
    ffi::c_void,
    mem::size_of_val,
    ptr::{addr_of, addr_of_mut, null_mut},
};
use futures::Future;
use log::{debug, warn};
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use windows::Win32::{
    Foundation::HANDLE,
    NetworkManagement::{
        IpHelper::{
            CancelMibChangeNotify2, FreeMibTable, GetIfTable2, GetIpForwardTable2,
            GetUnicastIpAddressTable, MibAddInstance, MibDeleteInstance, MibInitialNotification,
            MibParameterNotification, NotifyIpInterfaceChange, IF_TYPE_SOFTWARE_LOOPBACK,
            MIB_IF_TABLE2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
            MIB_UNICASTIPADDRESS_TABLE,
        },
        Ndis::IfOperStatusUp,
    },
    Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET},
};

/// Struct with named fields containing the sender channel and the current state
struct SenderState {
    /// The transmit end of a channel to send notifications to
    tx: UnboundedSender<Connectivity>,
    /// The current interfaces state
    state: Interfaces,
}

/// Try to convert a win32 [`SOCKADDR_INET`] to an [`IpAddr`]
unsafe fn sockaddr_inet_to_ip_addr(from: &SOCKADDR_INET) -> Option<IpAddr> {
    match ADDRESS_FAMILY(u32::from(from.si_family)) {
        AF_INET => Some(IpAddr::from(Ipv4Addr::from(from.Ipv4.sin_addr))),
        AF_INET6 => Some(IpAddr::from(Ipv6Addr::from(from.Ipv6.sin6_addr))),
        _ => None,
    }
}

/// Build the interfaces state from the
fn interfaces_from_system() -> Result<Interfaces, Box<dyn Error + Send + Sync>> {
    let mut state = Interfaces::new();

    // SAFETY:
    // Invoking an unsafe windows api
    // interfaces_pointer must be cleaned up at the end
    unsafe {
        let mut interfaces_pointer = null_mut::<MIB_IF_TABLE2>();
        GetIfTable2(addr_of_mut!(interfaces_pointer))?;
        if let Some(interfaces) = interfaces_pointer.as_ref() {
            for index in 0..interfaces.NumEntries.try_into()? {
                let interface = interfaces.Table.get_unchecked(index);
                state.add_link((
                    interface.InterfaceIndex,
                    interface.Type == IF_TYPE_SOFTWARE_LOOPBACK,
                    interface.OperStatus == IfOperStatusUp,
                ));
            }
        }
        FreeMibTable(interfaces_pointer.cast::<c_void>().cast_const());
    }

    // SAFETY:
    // Invoking an unsafe windows api
    // addresses_pointer must be cleaned up at the end
    unsafe {
        let mut addresses_pointer = null_mut::<MIB_UNICASTIPADDRESS_TABLE>();
        GetUnicastIpAddressTable(AF_UNSPEC.0.try_into()?, addr_of_mut!(addresses_pointer))?;
        if let Some(addresses) = addresses_pointer.as_ref() {
            for index in 0..addresses.NumEntries.try_into()? {
                let address = addresses.Table.get_unchecked(index);
                if address.ValidLifetime == 0xffff_ffff {
                    continue;
                }
                if let Some(addr) = sockaddr_inet_to_ip_addr(&address.Address) {
                    state.add_address((address.InterfaceIndex, addr));
                }
            }
        }
        FreeMibTable(addresses_pointer.cast::<c_void>().cast_const());
    }

    // SAFETY:
    // Invoking an unsafe windows api
    // routes_pointer must be cleaned up at the end
    unsafe {
        let mut routes_pointer = null_mut::<MIB_IPFORWARD_TABLE2>();
        GetIpForwardTable2(AF_UNSPEC.0.try_into()?, addr_of_mut!(routes_pointer))?;
        if let Some(routes) = routes_pointer.as_ref() {
            'outer: for index in 0..routes.NumEntries.try_into()? {
                let route = routes.Table.get_unchecked(index);
                if route.DestinationPrefix.PrefixLength != 0 {
                    continue;
                }
                let prefix = addr_of!(route.DestinationPrefix.Prefix).cast::<u8>();
                for prefix_index in 0..size_of_val(&route.DestinationPrefix.Prefix) {
                    match prefix.offset(prefix_index.try_into()?).as_ref() {
                        Some(prefix_element) => {
                            if *prefix_element != 0 {
                                continue 'outer;
                            }
                        }
                        None => {
                            continue 'outer;
                        }
                    }
                }
                state.add_default_route((
                    route.InterfaceIndex,
                    sockaddr_inet_to_ip_addr(&route.NextHop).ok_or("Not an ip address.")?,
                    route.Metric,
                ));
            }
        }
        FreeMibTable(routes_pointer.cast::<c_void>().cast_const());
    }
    Ok(state)
}

#[no_mangle]
/// Callback function for `NotifyIpInterfaceChange`
unsafe extern "system" fn connectivity_changed(
    caller_context: *const c_void,
    _: *const MIB_IPINTERFACE_ROW,
    notification_type: MIB_NOTIFICATION_TYPE,
) {
    debug!("got ip interface change notification");
    let sender_state_pointer = caller_context.cast::<SenderState>().cast_mut();
    if let Some(sender_state) = sender_state_pointer.as_mut() {
        let connectivity = sender_state.state.connectivity();
        #[allow(non_upper_case_globals)]
        match notification_type {
            MibParameterNotification
            | MibAddInstance
            | MibDeleteInstance
            | MibInitialNotification => match interfaces_from_system() {
                Ok(new_state) => {
                    sender_state.state = new_state;
                }
                Err(error) => {
                    warn!("interfaces_from_system failed {error}");
                }
            },
            _ => {}
        };
        let new_connectivity = sender_state.state.connectivity();
        if connectivity != new_connectivity {
            debug!("emit updated connectivity {new_connectivity:?}");
            if let Err(error) = sender_state.tx.send(new_connectivity) {
                warn!("failed to emit {error}");
            }
        }
    }
}

/// Subscribes some functions to the windows api and sends connectivity updates.
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
/// This function will return an error if the subscription failed.
/// The returned future can fail when a cleanup of the subscription failed.
pub fn new() -> Result<
    (
        impl Future<Output = Result<(), Box<dyn Error + Send + Sync>>>,
        UnboundedReceiver<Connectivity>,
    ),
    Box<dyn Error + Send + Sync>,
> {
    let (tx, rx) = unbounded_channel();
    let sender_state = Box::pin(SenderState {
        tx,
        state: interfaces_from_system()?,
    });

    {
        let connectivity = sender_state.state.connectivity();
        debug!("emit initial connectivity {:?}", connectivity);
        sender_state.tx.send(connectivity)?;
    }

    debug!("creating ip interface change notification");
    let mut handle = HANDLE::default();
    // SAFETY:
    // Invoking an unsafe windows api
    // sender_state must be stationary in memory
    // handle must be cleaned up when there is no more interest in the notification
    unsafe {
        NotifyIpInterfaceChange(
            AF_UNSPEC.0.try_into()?,
            Some(connectivity_changed),
            Some(addr_of!(*sender_state).cast::<c_void>()),
            true,
            &mut handle,
        )?;
    }

    let driver = async move {
        debug!("waiting on sender closed");
        sender_state.tx.closed().await;
        debug!("canceling ip interface change notification");
        // SAFETY:
        // cleanup of handle for earlier unsafe windows api
        unsafe {
            CancelMibChangeNotify2(handle)?;
        }
        Ok(())
    };

    Ok((driver, rx))
}
