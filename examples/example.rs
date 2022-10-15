use anyhow::{Context, Error, Result};
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // create the internet connectivity checker
    let (driver, mut rx) = connectivity::new()?;

    // spawn the driver in a task to run the required IO
    let driver = tokio::spawn(driver);

    // when there is a result from rx there was a change in internet connectivity.
    // this will only stop when an error was encountered.
    // to stop receiving updates anyway call rx.close().
    // this will result in the completion of driver.
    while let Some(connectivity) = rx.next().await {
        println!(
            "detected connectivity: ipv4: {} ipv6: {}",
            connectivity.ipv4(),
            connectivity.ipv6()
        );
    }

    // await the driver and flatten the result type
    match driver
        .await
        .with_context(|| "internet connectivity driver join failed")
    {
        Ok(v) => match v {
            Ok(v) => Ok(v),
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    }
}
