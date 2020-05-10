use std::env;
use std::net::SocketAddr;

use warp::Filter;

type DynError = Box<dyn std::error::Error>;

mod filters;
mod handlers;
mod models;
mod tasks;

#[tokio::main]
async fn main() -> Result<(), DynError> {
    if env::var_os("RUST_LOG").is_none() {
        env::set_var("RUST_LOG", "abbot=debug");
    }
    pretty_env_logger::init();

    let state = models::state_from_env()?;

    let api = filters::app(state);

    let routes = api.with(warp::log("abbot"));

    let addr: SocketAddr = ([0, 0, 0, 0], 3030).into();
    log::info!("listening at: {}", addr);

    warp::serve(routes).run(addr).await;
    Ok(())
}
