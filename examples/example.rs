// SPDX-License-Identifier: MIT
use env_logger::{Builder, Target};
use log::{info, LevelFilter};
use std::error::Error;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut builder = Builder::new();
    builder.filter_level(LevelFilter::Debug);
    builder.target(Target::Stderr);
    builder.init();

    // create the internet connectivity checker
    info!("creating internet connectivity checker");
    let (driver, mut rx) = network_connectivity::new()?;

    // spawn the driver in a task to run the required IO
    info!("spawning a task to run internet connectivity driver");
    let driver = tokio::spawn(driver);

    // when there is a result from rx there was a change in internet connectivity.
    // this will only stop when an error was encountered.
    // to stop receiving updates anyway drop rx or call rx.close().
    // this will result in the completion of driver.
    info!("begin waiting on internet connectivity receiver");
    while let Some(connectivity) = tokio::select! {
        biased;
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => None,
        connectivity = rx.recv() => connectivity,
    } {
        info!("detected connectivity: {:?}", connectivity);
    }
    info!("no activity for 5 seconds shuting down");
    drop(rx);

    // await the driver and flatten the result type
    info!("joining internet connectivity driver task");
    let r = match driver.await {
        Ok(v) => match v {
            Ok(v) => Ok(v),
            Err(e) => Err(e)?,
        },
        Err(e) => Err(e)?,
    };
    info!("joined internet connectivity driver task");
    r
}
