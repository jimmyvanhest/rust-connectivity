// SPDX-License-Identifier: MIT

use crate::{state::InterfacesState, Connectivity};
use futures::Future;
use log::debug;
use std::{
    error::Error,
    ffi::c_void,
    mem::transmute,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr::null_mut,
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

struct SenderState {
    tx: UnboundedSender<Connectivity>,
    state: InterfacesState,
}

unsafe fn sockaddr_inet_to_ip_addr(from: &SOCKADDR_INET) -> Option<IpAddr> {
    match ADDRESS_FAMILY(from.si_family as u32) {
        AF_INET => Some(IpAddr::from(Ipv4Addr::from(from.Ipv4.sin_addr))),
        AF_INET6 => Some(IpAddr::from(Ipv6Addr::from(from.Ipv6.sin6_addr))),
        _ => None,
    }
}

impl InterfacesState {
    fn from_system() -> Result<InterfacesState, Box<dyn Error + Send + Sync>> {
        let mut state = InterfacesState::new();

        unsafe {
            let interfaces = null_mut::<MIB_IF_TABLE2>();
            GetIfTable2(transmute(&interfaces))?;
            if let Some(interfaces) = interfaces.as_ref() {
                for index in 0..interfaces.NumEntries as usize {
                    let interface = interfaces.Table.get_unchecked(index);
                    state.add_link((
                        interface.InterfaceIndex,
                        interface.Type == IF_TYPE_SOFTWARE_LOOPBACK,
                        interface.OperStatus == IfOperStatusUp,
                    ));
                }
            }
            FreeMibTable(transmute(interfaces));
        }

        unsafe {
            let addresses = null_mut::<MIB_UNICASTIPADDRESS_TABLE>();
            GetUnicastIpAddressTable(AF_UNSPEC.0 as u16, transmute(&addresses))?;
            if let Some(addresses) = addresses.as_ref() {
                for index in 0..addresses.NumEntries as usize {
                    let address = addresses.Table.get_unchecked(index);
                    if address.ValidLifetime == 0xffffffff {
                        continue;
                    }
                    if let Some(addr) = sockaddr_inet_to_ip_addr(&address.Address) {
                        state.add_address((address.InterfaceIndex, addr));
                    }
                }
            }
            FreeMibTable(transmute(addresses));
        }

        unsafe {
            let routes = null_mut::<MIB_IPFORWARD_TABLE2>();
            GetIpForwardTable2(AF_UNSPEC.0 as u16, transmute(routes))?;
            if let Some(routes) = routes.as_ref() {
                'outer: for index in 0..routes.NumEntries as usize {
                    let route = routes.Table.get_unchecked(index);
                    if route.DestinationPrefix.PrefixLength != 0 {
                        continue;
                    }
                    let prefix: *const u8 = transmute(&route.DestinationPrefix.Prefix);
                    for index in 0..std::mem::size_of_val(&route.DestinationPrefix.Prefix) as isize
                    {
                        match prefix.offset(index).as_ref() {
                            Some(prefix) => {
                                if *prefix != 0 {
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
                        sockaddr_inet_to_ip_addr(&route.NextHop)
                            .ok_or_else(|| "Not an ip address.")?,
                        route.Metric,
                    ));
                }
            }
            FreeMibTable(transmute(routes));
        }
        Ok(state)
    }
}

#[no_mangle]
unsafe extern "system" fn connectivity_changed(
    caller_context: *const c_void,
    _: *const MIB_IPINTERFACE_ROW,
    notification_type: MIB_NOTIFICATION_TYPE,
) {
    debug!("got ip interface change notification");
    let sender_state = transmute::<_, *const SenderState>(caller_context).cast_mut();
    if let Some(sender_state) = sender_state.as_mut() {
        let connectivity = sender_state.state.connectivity();
        #[allow(non_upper_case_globals)]
        match notification_type {
            MibParameterNotification
            | MibAddInstance
            | MibDeleteInstance
            | MibInitialNotification => {
                sender_state.state = InterfacesState::from_system().unwrap();
            }
            _ => {}
        };
        let new_connectivity = sender_state.state.connectivity();
        if connectivity != new_connectivity {
            debug!("emit updated connectivity {:?}", new_connectivity);
            sender_state.tx.send(new_connectivity).unwrap();
        }
    }
}

pub(crate) fn new() -> Result<
    (
        impl Future<Output = Result<(), Box<dyn Error + Send + Sync>>>,
        UnboundedReceiver<Connectivity>,
    ),
    Box<dyn Error + Send + Sync>,
> {
    let (tx, rx) = unbounded_channel();
    let sender_state = Box::new(SenderState {
        tx,
        state: InterfacesState::from_system()?,
    });

    {
        let connectivity = sender_state.state.connectivity();
        debug!("emit initial connectivity {:?}", connectivity);
        sender_state.tx.send(connectivity)?;
    }

    debug!("creating ip interface change notification");
    let mut handle = HANDLE::default();
    unsafe {
        NotifyIpInterfaceChange(
            AF_UNSPEC.0 as u16,
            Some(connectivity_changed),
            Some(transmute(&*sender_state)),
            true,
            &mut handle,
        )?;
    }

    let driver = async move {
        debug!("waiting on sender closed");
        sender_state.tx.closed().await;
        debug!("canceling ip interface change notification");
        unsafe {
            CancelMibChangeNotify2(handle)?;
        }
        Ok(())
    };

    Ok((driver, rx))
}
