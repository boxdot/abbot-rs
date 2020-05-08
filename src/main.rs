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
    log::info!("listening at: {}", addr);

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
        msg: serde_json::Value,
        state: State,
    ) -> Result<impl warp::Reply, Infallible> {
        log::debug!("incoming gitlab web hook: {:?}", msg);

        let msg: gitlab::webhooks::WebHook = match serde_json::from_value(msg) {
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
}

mod models {
    use crate::DynError;
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;
    use std::fmt;
    use std::fs;
    use std::path::{Path, PathBuf};
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

    #[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Email(pub String);

    impl From<String> for Email {
        fn from(s: String) -> Self {
            Self(s)
        }
    }

    #[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
    pub struct User(pub Email);

    impl From<User> for String {
        fn from(user: User) -> Self {
            (user.0).0
        }
    }

    #[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ProjectId(pub u64);

    impl From<gitlab::ProjectId> for ProjectId {
        fn from(id: gitlab::ProjectId) -> Self {
            Self(id.value())
        }
    }

    impl fmt::Display for ProjectId {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    #[derive(Debug, Default, Serialize, Deserialize)]
    pub struct Db {
        #[serde(skip)]
        path: PathBuf,
        pub projects: BTreeMap<ProjectId, Vec<User>>,
        pub users: BTreeMap<User, Vec<ProjectId>>,
    }

    impl Db {
        pub fn path_from_env() -> PathBuf {
            let path = dotenv::var("DB").unwrap_or_else(|_| "abbot-db.json".to_string());
            path.into()
        }

        pub fn path(&self) -> &Path {
            &self.path
        }

        pub fn load(path: impl AsRef<Path>) -> Result<Self, DynError> {
            let f = fs::File::open(path)?;
            let db = serde_json::from_reader(f)?;
            Ok(db)
        }

        pub fn save(&self, path: impl AsRef<Path>) -> Result<(), DynError> {
            let f = fs::File::create(path)?;
            serde_json::to_writer(f, self)?;
            Ok(())
        }
    }

    pub fn state_from_env() -> Result<State, DynError> {
        let db_path = Db::path_from_env();
        let db = match Db::load(&db_path) {
            Ok(db) => {
                log::info!(
                    "loaded db with {} user(s), {} project(s) from: {}",
                    db.users.len(),
                    db.projects.len(),
                    db_path.display()
                );
                db
            }
            Err(e) => {
                log::warn!("could not load db from {}: {}", db_path.display(), e);

                let db = Db::default();
                db.save(&db_path)?;

                log::info!("initialized a new empty db at: {}", db_path.display());
                db
            }
        };

        Ok(Arc::new(Mutex::new(Data {
            public_url: Url::parse(&dotenv::var("PUBLIC_URL")?)?,
            webex_token: dotenv::var("WEBEX_TOKEN")?,
            db,
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
    use crate::models::{Data, Db, ProjectId, State, User};
    use lazy_static::lazy_static;
    use url::Url;

    pub async fn answer(state: State, user: User, msg: webex::types::Message) {
        let text = msg.text.as_ref().map(|s| s.as_str());
        let cmd = Command::from_text(text.unwrap_or_default());

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
                                Command::Enable(ProjectId(id))
                            } else {
                                Command::Disable(ProjectId(id))
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
            .map(|id| format!("* {}", id.0))
            .collect();
        let res = items.join("\n");
        if res.is_empty() {
            "n/a".to_string()
        } else {
            res
        }
    }

    fn enable(db: &mut Db, user: User, project: ProjectId) -> String {
        let user_projects = db.users.entry(user.clone()).or_default();
        if let Some(_) = user_projects.iter().find(|&&id| id == project) {
            format!("project {} is already enabled", project.0)
        } else {
            // TODO: debug check for duplicate entries of user
            user_projects.push(project);
            db.projects.entry(project).or_default().push(user);
            if let Err(e) = db.save(db.path()) {
                log::error!("failed to save db: {}", e);
                std::process::exit(1);
            }
            format!("enabled project {}", project.0)
        }
    }

    fn disable(db: &mut Db, user: User, project: ProjectId) -> String {
        let user_projects = db.users.entry(user.clone()).or_default();
        if let Some(idx) = user_projects.iter().position(|&id| id == project) {
            user_projects.swap_remove(idx);
            if user_projects.is_empty() {
                db.users.remove(&user);
            }

            let project_users = db.projects.entry(project).or_default();
            if let Some(idx) = project_users.iter().position(|u| u == &user) {
                project_users.swap_remove(idx);
                if project_users.is_empty() {
                    db.projects.remove(&project);
                }
            } else {
                log::warn!(
                    "invalid db: user {:?} not found in project {}",
                    user,
                    project
                );
            }

            if let Err(e) = db.save(db.path()) {
                log::error!("failed to save db: {}", e);
                std::process::exit(1);
            }

            format!("project {} disabled", project)
        } else {
            format!("project {} is not enabled", project)
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

    pub async fn notify(state: State, msg: gitlab::webhooks::WebHook) {
        use gitlab::webhooks::WebHook::*;
        let project_id: ProjectId = match &msg {
            Push(hook) => hook.project_id,
            // Issue(hook) => hook.project.project_id,
            // MergeRequest(hook) => hook.project_id,
            Note(hook) => hook.project_id,
            Build(hook) => hook.project_id,
            // WikiPage(hook) => hook.project_id,
            _ => todo!("handle all hooks"),
        }
        .into();

        let state = state.lock().await;

        let client = webex::Webex::new(&state.webex_token);

        if let Some(project_users) = state.db.projects.get(&project_id) {
            for user in project_users {
                let msg_out = webex::types::MessageOut {
                    to_person_email: Some(user.clone().into()),
                    markdown: Some(format!("{:?}", msg)),
                    ..Default::default()
                };

                let user = user.clone();
                let client = client.clone();
                tokio::spawn(async move {
                    if let Err(e) = client.send_message(&msg_out).await {
                        log::error!("failed to notify user {:?} due to: {}", user, e);
                    }
                });
            }
        }
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
                Command::Enable(ProjectId(42))
            );
            assert_eq!(
                Command::from_text("/disable 42"),
                Command::Disable(ProjectId(42))
            );
            assert_eq!(Command::from_text("/enable abc"), Command::Welcome);
            assert_eq!(Command::from_text("/disable abc"), Command::Welcome);
            assert_eq!(Command::from_text("lorem"), Command::Welcome);
        }
    }
}
