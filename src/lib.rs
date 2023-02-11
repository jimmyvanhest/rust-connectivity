// SPDX-License-Identifier: MIT

//! This crate allows you to receive network connectivity updates through a channel.

#![warn(clippy::cargo, clippy::nursery, clippy::pedantic, clippy::restriction)]
#![allow(
    clippy::blanket_clippy_restriction_lints,
    clippy::implicit_return,
    clippy::missing_inline_in_public_items,
    clippy::missing_trait_methods,
    clippy::single_char_lifetime_names
)]

#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "linux"))]
mod state;
#[cfg(target_os = "windows")]
mod windows;

use futures::Future;
use std::error::Error;

/// Represents connectivity to the internet.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
#[non_exhaustive]
pub enum ConnectivityState {
    /// No connectivity
    None,
    /// Connectivity to the local network
    Network,
    /// Connectivity to the internet
    Internet,
}

/// Represents connectivity to the internet separated by ipv4 and ipv6.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Connectivity {
    /// Ipv4 connectivity
    pub ipv4: ConnectivityState,
    /// Ipv6 connectivity
    pub ipv6: ConnectivityState,
}

impl Connectivity {
    /// Get the highest connectivity state of any ip type
    #[allow(clippy::must_use_candidate)]
    pub fn any(&self) -> ConnectivityState {
        if self.ipv4 > self.ipv6 {
            self.ipv4
        } else {
            self.ipv6
        }
    }

    /// Get the lowest connectivity state of any ip type
    #[allow(clippy::must_use_candidate)]
    pub fn all(&self) -> ConnectivityState {
        if self.ipv4 < self.ipv6 {
            self.ipv4
        } else {
            self.ipv6
        }
    }
}

/// Creates a driver that sends connectivity updates to a channel.
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
/// This function will return an error if the underlying driver failed in some way.
/// The returned future can fail when the underlying driver received an error.
pub fn new() -> Result<
    (
        impl Future<Output = Result<(), Box<dyn Error + Send + Sync>>>,
        tokio::sync::mpsc::UnboundedReceiver<Connectivity>,
    ),
    Box<dyn Error + Send + Sync>,
> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "linux")] {
            linux::new()
        } else if #[cfg(target_os = "windows")] {
            windows::new()
        } else {
            compile_error!("This crate has no implementation for this configuration.");
        }
    }
}
