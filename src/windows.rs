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
    ops::BitAnd,
    sync::Mutex,
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
    tx: Mutex<UnboundedSender<Connectivity>>,
    /// The current interfaces state
    state: Mutex<Interfaces>,
}

/// Try to convert a win32 [`SOCKADDR_INET`] to an [`IpAddr`]
unsafe fn sockaddr_inet_to_ip_addr(from: &SOCKADDR_INET) -> Option<IpAddr> {
    match ADDRESS_FAMILY(u32::from(from.si_family)) {
        AF_INET => Some(IpAddr::from(Ipv4Addr::from(from.Ipv4.sin_addr))),
        AF_INET6 => Some(IpAddr::from(Ipv6Addr::from(from.Ipv6.sin6_addr))),
        _ => None,
    }
}

/// Checks if bit is set
fn is_set<T>(val: T, bit_pos: u32) -> bool
where
    T: BitAnd<Output = T> + From<u32> + PartialEq + Copy,
{
    let mask = (1 << bit_pos).into();
    val & mask == mask
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
                let is_hardware_interface =
                    is_set(interface.InterfaceAndOperStatusFlags._bitfield as u32, 0);
                if is_hardware_interface {
                    state.add_link((
                        interface.InterfaceIndex,
                        interface.Type == IF_TYPE_SOFTWARE_LOOPBACK,
                        interface.OperStatus == IfOperStatusUp,
                    ));
                }
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
                match (
                    sockaddr_inet_to_ip_addr(&address.Address),
                    address.ValidLifetime,
                ) {
                    (Some(ip_address), lifetime) if lifetime != 0xffff_ffff => {
                        state.add_address((address.InterfaceIndex, ip_address));
                    }
                    (_, _) => {}
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
                // when both elements of DestinationPrefix only contain zero(excluding the first byte of the prefix itself), the route is considered default.
                if route.DestinationPrefix.PrefixLength != 0 {
                    continue;
                }
                let prefix = addr_of!(route.DestinationPrefix.Prefix).cast::<u8>();
                for prefix_index in 1..size_of_val(&route.DestinationPrefix.Prefix) {
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
                if let Some(gateway) = sockaddr_inet_to_ip_addr(&route.NextHop) {
                    state.add_default_route((route.InterfaceIndex, gateway, route.Metric));
                }
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
    let sender_state_pointer = caller_context.cast::<SenderState>().cast_mut();
    if let Some(sender_state) = sender_state_pointer.as_mut() {
        match sender_state.state.lock() {
            Ok(mut state) => {
                #[allow(non_upper_case_globals)]
                match notification_type {
                    MibParameterNotification
                    | MibAddInstance
                    | MibDeleteInstance
                    | MibInitialNotification => match interfaces_from_system() {
                        Ok(new_state) => {
                            let new_connectivity = new_state.connectivity();
                            if state.connectivity() != new_connectivity {
                                debug!("emit updated connectivity {new_connectivity:?}");
                                match sender_state.tx.lock() {
                                    Ok(tx) => match tx.send(new_connectivity) {
                                        Ok(_) => {
                                            *state = new_state;
                                        }
                                        Err(tx_send_error) => {
                                            warn!("failed to emit {tx_send_error}");
                                        }
                                    },
                                    Err(tx_lock_error) => {
                                        warn!("failed to lock tx: {tx_lock_error}");
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            warn!("interfaces_from_system failed {error}");
                        }
                    },
                    _ => {}
                };
            }
            Err(state_lock_error) => {
                warn!("failed to lock state: {state_lock_error}");
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
        tx: Mutex::new(tx),
        state: Mutex::new(interfaces_from_system()?),
    });

    {
        let connectivity = sender_state
            .state
            .lock()
            .map_err(|error| error.to_string())?
            .connectivity();
        debug!("emitting initial connectivity {:?}", connectivity);
        sender_state
            .tx
            .lock()
            .map_err(|error| error.to_string())?
            .send(connectivity)?;
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
            false,
            &mut handle,
        )?;
    }

    let driver = async move {
        let tx = sender_state
            .tx
            .lock()
            .map_err(|error| error.to_string())?
            .clone();
        debug!("waiting on sender closed");
        tx.closed().await;
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
