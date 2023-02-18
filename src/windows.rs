// SPDX-License-Identifier: MIT

//! The windows implementation for this crate.

use crate::{Connectivity, ConnectivityState};
use core::{
    cmp::max,
    ffi::c_void,
    ptr::{addr_of, addr_of_mut, null_mut},
};
use futures::Future;
use log::{debug, warn};
use std::{error::Error, sync::Mutex};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use windows::Win32::{
    Foundation::HANDLE,
    NetworkManagement::{
        IpHelper::{
            CancelMibChangeNotify2, FreeMibTable, GetIfTable2, GetIpForwardTable2,
            GetUnicastIpAddressTable, MibAddInstance, MibDeleteInstance, MibInitialNotification,
            MibParameterNotification, NotifyIpInterfaceChange, IF_TYPE_SOFTWARE_LOOPBACK,
            MIB_IF_ROW2, MIB_IF_TABLE2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
            MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
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
    /// The current connectivity
    state: Mutex<Connectivity>,
}

/// Wrapper around windows MIB_*_TABLE* structures which calls `FreeMibTable` on drop
struct MibTable<T> {
    /// The table this wrapper points to
    pointer: *mut T,
}
impl<T> Drop for MibTable<T> {
    fn drop(&mut self) {
        // SAFETY:
        // pointer was created using an unsafe windows api and should be freed as such
        unsafe {
            FreeMibTable(self.pointer.cast::<c_void>().cast_const());
        }
    }
}
/// Iterator for `MibTable`
#[derive(Clone)]
struct MibTableIter<'a, T> {
    /// The table for this iterator
    table: &'a MibTable<T>,
    /// the next index for this iterator
    next_index: u32,
}
/// Helper macro for creating new `MibTable` structures
macro_rules! create_mib_table_new {
    ($table:ty,$getter:expr) => {
        impl MibTable<$table> {
            fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
                // SAFETY:
                // getter is an unsafe windows api that should be dropped with `FreeMibTable`
                unsafe {
                    let mut pointer = null_mut::<$table>();
                    $getter(addr_of_mut!(pointer))?;
                    Ok(Self { pointer })
                }
            }
        }
    };
    ($table:ty,$getter:expr,$arg1:ty) => {
        impl MibTable<$table> {
            fn new(a1: $arg1) -> Result<Self, Box<dyn Error + Send + Sync>> {
                // SAFETY:
                // getter is an unsafe windows api that should be dropped with `FreeMibTable`
                unsafe {
                    let mut pointer = null_mut::<$table>();
                    $getter(a1, addr_of_mut!(pointer))?;
                    Ok(Self { pointer })
                }
            }
        }
    };
}
create_mib_table_new!(MIB_IF_TABLE2, GetIfTable2);
create_mib_table_new!(MIB_UNICASTIPADDRESS_TABLE, GetUnicastIpAddressTable, u16);
create_mib_table_new!(MIB_IPFORWARD_TABLE2, GetIpForwardTable2, u16);
/// Helper macro for creating `MibTable` iterator boilerplate
macro_rules! create_mib_table_iterator {
    ($table:ty,$row:ty) => {
        impl<'a> IntoIterator for &'a MibTable<$table> {
            type Item = &'a $row;

            type IntoIter = MibTableIter<'a, $table>;

            fn into_iter(self) -> Self::IntoIter {
                MibTableIter {
                    table: self,
                    next_index: 0,
                }
            }
        }
        impl<'a> Iterator for MibTableIter<'a, $table> {
            type Item = &'a $row;

            fn next(&mut self) -> Option<Self::Item> {
                // SAFETY:
                // dereferencing raw pointers but it's checked by NumEntries
                unsafe {
                    if self.next_index < (*self.table.pointer).NumEntries {
                        if let Ok(next_index) = self.next_index.try_into() {
                            let n = (*self.table.pointer)
                                .Table
                                .get_unchecked::<usize>(next_index);
                            self.next_index = self.next_index.checked_add(1)?;
                            Some(n)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            }
        }
    };
}
create_mib_table_iterator!(MIB_IF_TABLE2, MIB_IF_ROW2);
create_mib_table_iterator!(MIB_UNICASTIPADDRESS_TABLE, MIB_UNICASTIPADDRESS_ROW);
create_mib_table_iterator!(MIB_IPFORWARD_TABLE2, MIB_IPFORWARD_ROW2);

/// wrapper to check a windows address structure it's ip type
fn sockaddr_inet_check_ip_type(address: SOCKADDR_INET, ip_type: ADDRESS_FAMILY) -> bool {
    // SAFETY:
    // accessing union's identifier field
    ADDRESS_FAMILY(u32::from(unsafe { address.si_family })) == ip_type
}

/// Get the connectivity state from the system
fn connectivity_from_system() -> Result<Connectivity, Box<dyn Error + Send + Sync>> {
    let interfaces = MibTable::<MIB_IF_TABLE2>::new()?;
    let addresses = MibTable::<MIB_UNICASTIPADDRESS_TABLE>::new(AF_UNSPEC.0.try_into()?)?;
    let routes = MibTable::<MIB_IPFORWARD_TABLE2>::new(AF_UNSPEC.0.try_into()?)?;

    let default_routes = routes.into_iter().filter(|route| {
        let mut prefix_compare = SOCKADDR_INET::default();
        unsafe {
            prefix_compare.si_family = route.DestinationPrefix.Prefix.si_family;
        }
        route.DestinationPrefix.PrefixLength == 0
            && route.DestinationPrefix.Prefix == prefix_compare
    });

    let connectivity = interfaces
        .into_iter()
        .filter(|interface| {
            #[allow(clippy::used_underscore_binding)]
            return interface.InterfaceAndOperStatusFlags._bitfield & 1 == 1
                && interface.Type != IF_TYPE_SOFTWARE_LOOPBACK
                && interface.OperStatus == IfOperStatusUp;
        })
        .map(|interface| {
            let interface_addresses = addresses
                .into_iter()
                .filter(|address| address.InterfaceIndex == interface.InterfaceIndex);
            let mut ipv4_interface_addresses = interface_addresses
                .clone()
                .filter(|address| sockaddr_inet_check_ip_type(address.Address, AF_INET));
            let mut ipv6_interface_addresses = interface_addresses
                .clone()
                .filter(|address| sockaddr_inet_check_ip_type(address.Address, AF_INET6));
            let interface_default_routes = default_routes
                .clone()
                .filter(|route| route.InterfaceIndex == interface.InterfaceIndex);
            let mut ipv4_interface_default_routes = interface_default_routes
                .clone()
                .filter(|route| sockaddr_inet_check_ip_type(route.NextHop, AF_INET));
            let mut ipv6_interface_default_routes = interface_default_routes
                .clone()
                .filter(|route| sockaddr_inet_check_ip_type(route.NextHop, AF_INET6));

            let ipv4 = match (
                ipv4_interface_addresses.next(),
                ipv4_interface_default_routes.next(),
            ) {
                (None, _) => ConnectivityState::None,
                (Some(_), None) => ConnectivityState::Network,
                (Some(_), Some(_)) => ConnectivityState::Internet,
            };
            let ipv6 = match (
                ipv6_interface_addresses.next(),
                ipv6_interface_default_routes.next(),
            ) {
                (None, _) => ConnectivityState::None,
                (Some(_), None) => ConnectivityState::Network,
                (Some(_), Some(_)) => ConnectivityState::Internet,
            };

            Connectivity { ipv4, ipv6 }
        })
        .reduce(|a, b| Connectivity {
            ipv4: max(a.ipv4, b.ipv4),
            ipv6: max(a.ipv6, b.ipv6),
        });

    Ok(connectivity.unwrap_or(Connectivity {
        ipv4: ConnectivityState::None,
        ipv6: ConnectivityState::None,
    }))
}

/// the handler function for `connectivity_changed` that returns a result which writes better to read code.
unsafe fn handle_connectivity_changed(
    caller_context: *const c_void,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let sender_state_pointer = caller_context.cast::<SenderState>().cast_mut();
    if let Some(sender_state) = sender_state_pointer.as_mut() {
        let mut state = sender_state
            .state
            .lock()
            .map_err(|error| format!("failed to lock state: {error}"))?;
        let new_connectivity = connectivity_from_system()?;
        if *state != new_connectivity {
            debug!("emitting updated connectivity {new_connectivity:?}");
            sender_state
                .tx
                .lock()
                .map_err(|error| format!("failed to lock sender: {error}"))?
                .send(new_connectivity)?;
            *state = new_connectivity;
        }
    }
    Ok(())
}

#[no_mangle]
/// Callback function for `NotifyIpInterfaceChange`
unsafe extern "system" fn connectivity_changed(
    caller_context: *const c_void,
    _: *const MIB_IPINTERFACE_ROW,
    notification_type: MIB_NOTIFICATION_TYPE,
) {
    #[allow(non_upper_case_globals)]
    match notification_type {
        MibParameterNotification | MibAddInstance | MibDeleteInstance | MibInitialNotification => {
            if let Err(error) = handle_connectivity_changed(caller_context) {
                warn!("handle_connectivity_changed failed {error}");
            }
        }
        _ => {}
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
    let connectivity = connectivity_from_system()?;
    let sender_state = Box::pin(SenderState {
        tx: Mutex::new(tx),
        state: Mutex::new(connectivity),
    });

    {
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
        let locked_tx = sender_state
            .tx
            .lock()
            .map_err(|error| error.to_string())?
            .clone();
        debug!("waiting on sender closed");
        locked_tx.closed().await;
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
