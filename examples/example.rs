use anyhow::{Context, Error, Result};

#[tokio::main]
async fn main() -> Result<(), Error> {
    // create the internet connectivity checker
    let (driver, mut rx) = connectivity::new()?;

    // spawn the driver in a task to run the required IO
    let driver = tokio::spawn(driver);

    // when there is a result from rx there was a change in internet connectivity.
    // this will only stop when an error was encountered.
    // to stop receiving updates anyway drop rx or call rx.close().
    // this will result in the completion of driver.
    while let Some(connectivity) = tokio::select! {
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => None,
        connectivity = rx.recv() => connectivity
    } {
        println!("detected connectivity: {:?}", connectivity);
    }
    println!("no activity for 5 seconds shuting down");
    drop(rx);

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
