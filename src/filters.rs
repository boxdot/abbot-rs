use super::handlers;
use super::models::State;
use warp::Filter;

pub fn app(
    state: State,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    post_gitlab(state.clone()).or(post_webex(state))
}

pub fn post_gitlab(
    state: State,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("gitlab")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_state(state))
        .and_then(handlers::gitlab)
}

pub fn post_webex(
    state: State,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("webex")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_state(state))
        .and_then(handlers::webex)
}

fn with_state(
    state: State,
) -> impl Filter<Extract = (State,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || state.clone())
}
