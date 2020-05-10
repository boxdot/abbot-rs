use super::models::{self, State};
use super::tasks;
use std::convert::Infallible;
use warp::http::StatusCode;

pub async fn gitlab(msg: serde_json::Value, state: State) -> Result<impl warp::Reply, Infallible> {
    log::debug!(
        "incoming gitlab web hook: {}",
        serde_json::to_string(&msg).unwrap_or_else(|_| "invalid JSON".to_string())
    );

    let msg = match serde_json::from_value(msg) {
        Ok(msg) => msg,
        Err(e) => {
            log::error!("could not deserialize gitlab webhook: {}", e);
            return Ok(StatusCode::OK);
        }
    };

    tokio::spawn(tasks::notify(state, msg));

    Ok(StatusCode::OK)
}

pub async fn webex(
    msg: models::webex::WebHook,
    state: State,
) -> Result<impl warp::Reply, warp::Rejection> {
    log::debug!("incoming webex web hook: {:?}", msg);

    let client = {
        let state = state.lock().await;
        webex::Webex::new(&state.webex_token)
    };

    let message = match client.get_message(&msg.data.id).await {
        Ok(message) => message,
        Err(e) => {
            log::error!("failed to retrieve message text: {}", e);
            return Ok(StatusCode::OK);
        }
    };

    let user = match &message.person_email {
        Some(mail) => models::User(models::Email::from(mail.clone())),
        None => {
            log::error!("no sender email in message: {:?}", message);
            return Ok(StatusCode::OK);
        }
    };

    log::debug!("message: {:?}", message);
    tokio::spawn(tasks::answer(state.clone(), user, message));

    Ok(StatusCode::OK)
}
