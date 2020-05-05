use std::env;
use std::net::SocketAddr;

use warp::Filter;

type DynError = Box<dyn std::error::Error>;

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
    log::info!("Listening at: {}", addr);

    warp::serve(routes).run(addr).await;
    Ok(())
}

mod filters {
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
}

mod handlers {
    use super::models::{self, State};
    use super::tasks;
    use std::convert::Infallible;
    use warp::http::StatusCode;

    pub async fn gitlab(
        msg: gitlab::webhooks::WebHook,
        _state: State,
    ) -> Result<impl warp::Reply, Infallible> {
        log::debug!("incoming gitlab web hook: {:?}", msg);
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
}

mod models {
    use crate::DynError;
    use chrono::{DateTime, Utc};
    use gitlab::ProjectId;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use url::Url;

    pub type State = Arc<Mutex<Data>>;

    pub struct Data {
        pub public_url: Url,
        pub webex_token: String,
        pub db: Db,
        pub last_notification_at: Option<DateTime<Utc>>,
    }

    #[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
    pub struct Email(pub String);

    impl From<String> for Email {
        fn from(s: String) -> Self {
            Self(s)
        }
    }

    #[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
    pub struct User(pub Email);

    #[derive(Debug, Default)]
    pub struct Db {
        pub projects: BTreeMap<ProjectId, Vec<User>>,
        pub users: BTreeMap<User, Vec<ProjectId>>,
    }

    pub fn state_from_env() -> Result<State, DynError> {
        Ok(Arc::new(Mutex::new(Data {
            public_url: Url::parse(&dotenv::var("PUBLIC_URL")?)?,
            webex_token: dotenv::var("WEBEX_TOKEN")?,
            db: Default::default(), // TODO: implement loading db
            last_notification_at: None,
        })))
    }

    pub mod webex {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct WebHook {
            pub data: Data,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[serde(rename_all = "camelCase")]
        pub struct Data {
            pub created: String,
            pub id: String,
            pub person_email: String,
            pub person_id: String,
            pub room_id: String,
            pub room_type: String,
        }
    }
}

mod tasks {
    use crate::models::{Data, Db, State, User};
    use gitlab::ProjectId;
    use lazy_static::lazy_static;
    use url::Url;

    pub async fn answer(state: State, user: User, msg: webex::types::Message) {
        let text = msg.text.as_ref().map(|s| s.as_str());
        let cmd = Command::from_text(text.unwrap_or_default());
        log::debug!("command: {:?}", cmd);

        let reply = match cmd {
            Command::Welcome => welcome(&state.lock().await.public_url).to_string(),
            Command::Enable(project) => enable(&mut state.lock().await.db, user, project),
            Command::Disable(project) => disable(&mut state.lock().await.db, user, project),
            Command::List => list(&state.lock().await.db, &user),
            Command::Status => status(&*state.lock().await),
        };
        let msg_out = webex::types::MessageOut {
            markdown: Some(reply),
            text: None,
            ..webex::types::MessageOut::from_msg(&msg)
        };

        let client = {
            let state = state.lock().await;
            webex::Webex::new(&state.webex_token)
        };

        log::debug!("reply: {:?}", msg_out);
        if let Err(e) = client.send_message(&msg_out).await {
            log::error!("failed to reply due to: {}", e);
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Command {
        List,
        Enable(ProjectId),
        Disable(ProjectId),
        Status,
        Welcome,
    }

    impl Command {
        fn from_text(s: &str) -> Self {
            use regex::Regex;
            lazy_static! {
                static ref PROJECT_REGEX: Regex =
                    Regex::new(r"(?i)^/(enable|disable)\s+(\d+)$").unwrap();
            }

            match &s.trim().to_lowercase()[..] {
                "/list" => Self::List,
                "/status" => Self::Status,
                _ => PROJECT_REGEX
                    .captures(&s.trim()[..])
                    .and_then(|cap| cap.get(1).and_then(|m1| cap.get(2).map(|m2| (m1, m2))))
                    .and_then(|(m1, m2)| {
                        m2.as_str().parse().ok().map(|id| {
                            if m1.as_str() == "enable" {
                                Command::Enable(ProjectId::new(id))
                            } else {
                                Command::Disable(ProjectId::new(id))
                            }
                        })
                    })
                    .unwrap_or(Command::Welcome),
            }
        }
    }

    fn welcome(public_url: &Url) -> String {
        format!(
            r#"Commands:

```
/list           List enabled GitLab repositories
/enable <url>   Enable notification for GitLab repository. Note: This repo needs to have a
                registered GitLab web hook to the URL of this bot: {url}.
/disable <url>  Disable notifications for GitLab repository.
/status         Status of the bot.
```
"#,
            url = public_url
        )
    }

    fn list(db: &Db, user: &User) -> String {
        let user_projects = db.users.get(user).map(|v| &v[..]).unwrap_or_default();
        let items: Vec<String> = user_projects
            .iter()
            .map(|id| format!("* {}", id.value()))
            .collect();
        items.join("\n")
    }

    fn enable(db: &mut Db, user: User, project: ProjectId) -> String {
        let user_projects = db.users.entry(user.clone()).or_default();
        if let Some(_) = user_projects.iter().find(|&&id| id == project) {
            format!("project {} is already enabled", project.value())
        } else {
            user_projects.push(project);
            db.projects.entry(project).or_default().push(user);
            // TODO: debug check for duplicate entries of user
            format!("enabled project {}", project.value())
        }
    }

    fn disable(db: &mut Db, user: User, project: ProjectId) -> String {
        let user_projects = db.users.entry(user.clone()).or_default();
        if let Some(idx) = user_projects.iter().position(|&id| id == project) {
            user_projects.swap_remove(idx);
            let project_users = db.projects.entry(project).or_default();
            if let Some(idx) = project_users.iter().position(|u| u == &user) {
                project_users.swap_remove(idx);
            } else {
                log::warn!(
                    "invalid db: user {:?} not found in project {}",
                    user,
                    project
                );
            }
            format!("project {} disabled", project.value())
        } else {
            format!("project {} is not enabled", project.value())
        }
    }

    fn status(state: &Data) -> String {
        format!(
            r#"
* Notifying: {} users
* Last notification: {}
"#,
            state.db.users.len(),
            state
                .last_notification_at
                .map(|dt| dt.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_command_from_text() {
            assert_eq!(Command::from_text("/list"), Command::List);
            assert_eq!(Command::from_text("/status"), Command::Status);
            assert_eq!(
                Command::from_text("/enable 42"),
                Command::Enable(ProjectId::new(42))
            );
            assert_eq!(
                Command::from_text("/disable 42"),
                Command::Disable(ProjectId::new(42))
            );
            assert_eq!(Command::from_text("/enable abc"), Command::Welcome);
            assert_eq!(Command::from_text("/disable abc"), Command::Welcome);
            assert_eq!(Command::from_text("lorem"), Command::Welcome);
        }
    }
}
