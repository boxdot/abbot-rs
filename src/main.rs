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

    // TODO: use salted shasum hashed email instead of clear text
    #[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
    pub struct User(pub Email);

    impl From<User> for String {
        fn from(user: User) -> Self {
            (user.0).0
        }
    }

    #[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ProjectId(pub u64);

    impl From<::gitlab::ProjectId> for ProjectId {
        fn from(id: ::gitlab::ProjectId) -> Self {
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

        pub fn load(path: PathBuf) -> Result<Self, DynError> {
            let f = fs::File::open(&path)?;
            let db = serde_json::from_reader(f)?;
            Ok(Self { path, ..db })
        }

        pub fn save(&self, path: impl AsRef<Path>) -> Result<(), DynError> {
            let f = fs::File::create(path)?;
            serde_json::to_writer(f, self)?;
            Ok(())
        }
    }

    pub fn state_from_env() -> Result<State, DynError> {
        let db_path = Db::path_from_env();
        let db = match Db::load(db_path.clone()) {
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

    pub mod gitlab {
        use gitlab::webhooks::HookDate;
        use gitlab::webhooks::UserHookAttrs;
        use gitlab::JobId;
        use gitlab::ObjectId;
        use gitlab::PipelineId;
        use gitlab::Runner;
        use serde::Deserialize;

        #[derive(Debug, Clone, Deserialize)]
        #[serde(untagged, rename_all = "snake_case")]
        pub enum WebHookExt {
            /// web hooks supported by standard edition (implement by `gitlab` crate)
            Standard(gitlab::webhooks::WebHook),
            Pipeline(Box<PipelineHook>),
        }

        #[derive(Debug, Clone, Deserialize)]
        #[serde(tag = "object_kind")]
        pub enum WebHook {
            Pipeline(PipelineHook),
        }

        // TODO: Contribute upstream
        #[derive(Debug, Clone, Deserialize)]
        pub struct PipelineHook {
            pub builds: Vec<BuildAttrs>,
            pub object_attributes: PipelineHookAttrs,
            pub object_kind: String,
            pub project: PipelineProjectHookAttrs,
            pub user: UserHookAttrs,
        }

        /// Project information exposed in pipeline hooks.
        #[derive(Debug, Clone, Deserialize)]
        pub struct PipelineProjectHookAttrs {
            /// The display name of the project.
            pub name: String,
            /// The description of the project.
            pub description: Option<String>,
            /// The URL for the project's homepage.
            pub web_url: String,
            /// The URL to the project avatar.
            pub avatar_url: Option<String>,
            /// The URL to clone the repository over SSH.
            pub git_ssh_url: String,
            /// The URL to clone the repository over HTTPS.
            pub git_http_url: String,
            /// The namespace the project lives in.
            pub namespace: String,
            /// Integral value for the project's visibility.
            pub visibility_level: u64,
            /// The path to the project's repository with its namespace.
            pub path_with_namespace: String,
            /// The default branch for the project.
            pub default_branch: Option<String>,
        }

        /// An uploaded artifact from a job.
        #[derive(Deserialize, Debug, Clone)]
        pub struct JobArtifactFile {
            /// The name of the artifact.
            pub filename: Option<String>,
            /// The size (in bytes) of the artifact.
            pub size: Option<usize>,
        }

        #[derive(Deserialize, Debug, Clone)]
        pub struct PipelineHookAttrs {
            ///
            pub before_sha: ObjectId,
            /// Date pipeline created
            pub created_at: HookDate,
            /// Status of Pipeline
            pub detailed_status: StatusState,
            /// Duration of pipeline (in seconds)
            pub duration: Option<u64>,
            /// Time pipeline finished.
            pub finished_at: Option<HookDate>,
            /// Id of pipeline
            pub id: PipelineId,
            /// References for pipeline, branch or tag.
            #[serde(rename = "ref")]
            pub ref_: String,
            pub sha: ObjectId,
            /// All stages of pipeline
            pub stages: Vec<String>,
            /// Status of pipeline
            pub status: StatusState,
            pub tag: bool,
            /// Variables used to during pipeline
            pub variables: Vec<String>,
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
        #[serde(rename_all = "snake_case")]
        /// States for commit statuses.
        pub enum StatusState {
            /// The check was created.
            Created,
            /// The check is queued.
            Pending,
            /// The check is currently running.
            Running,
            /// The check passed.
            Passed,
            /// The check succeeded.
            Success,
            /// The check failed.
            Failed,
            /// The check was canceled.
            Canceled,
            /// The check was skipped.
            Skipped,
            /// The check is waiting for manual action.
            Manual,
        }

        #[derive(Deserialize, Debug, Clone)]
        pub struct BuildAttrs {
            pub artifacts_file: JobArtifactFile,
            /// When the hook was created.
            pub created_at: HookDate,
            /// When the hook was finished
            pub finished_at: Option<HookDate>,
            /// When the hook was finished
            pub started_at: Option<HookDate>,
            /// The ID of the build.
            pub id: JobId,
            /// Manual job.
            pub manual: bool,
            /// Job name
            pub name: String,
            /// Runner
            pub runner: Option<Runner>,
            /// Build stage name
            pub stage: String,
            /// Status of the build
            pub status: StatusState,
            /// The user which triggered the hook.
            pub user: UserHookAttrs,
            /// How build was triggered
            pub when: String,
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn test_webhook_pipeline_extension() {
                const JSON: &'static str = r#"
                    {
                        "builds": [
                            {
                                "allow_failure": false,
                                "artifacts_file": {
                                    "filename": null,
                                    "size": null
                                },
                                "created_at": "2020-05-08 20:54:44 UTC",
                                "finished_at": "2020-05-08 20:54:58 UTC",
                                "id": 2915010,
                                "manual": false,
                                "name": "build",
                                "runner": {
                                    "active": true,
                                    "description": "some_runner",
                                    "id": 3078,
                                    "is_shared": true
                                },
                                "stage": "build",
                                "started_at": "2020-05-08 20:54:46 UTC",
                                "status": "failed",
                                "user": {
                                    "avatar_url": "https://gitlab.org/uploads/-/system/user/avatar/19/avatar.png",
                                    "email": "kafka@schloss.com",
                                    "name": "Franz Kafka",
                                    "username": "kafka"
                                },
                                "when": "on_success"
                            },
                            {
                                "allow_failure": false,
                                "artifacts_file": {
                                    "filename": null,
                                    "size": null
                                },
                                "created_at": "2020-05-08 20:39:53 UTC",
                                "finished_at": "2020-05-08 20:40:06 UTC",
                                "id": 2914926,
                                "manual": false,
                                "name": "build",
                                "runner": {
                                    "active": true,
                                    "description": "aws-autoscaler-main-1a-epgitlabp-us-east-1",
                                    "id": 3036,
                                    "is_shared": true
                                },
                                "stage": "build",
                                "started_at": "2020-05-08 20:39:54 UTC",
                                "status": "failed",
                                "user": {
                                    "avatar_url": "https://gitlab.org/uploads/-/system/user/avatar/19/avatar.png",
                                    "email": "kafka@schloss.com",
                                    "name": "Franz Kafka",
                                    "username": "kafka"
                                },
                                "when": "on_success"
                            }
                        ],
                        "commit": {
                            "author": {
                                "email": "kafka@schloss.com",
                                "name": "Franz Kafka"
                            },
                            "id": "b2374cdca84c06dc86d4f60a58553df40a1873d1",
                            "message": "Add CI\n",
                            "timestamp": "2020-05-08T22:39:46+02:00",
                            "title": "Add CI",
                            "url": "https://gitlab.org/user/testing/-/commit/b2374cdca84c06dc86d4f60a58553df40a1873d1"
                        },
                        "merge_request": null,
                        "object_attributes": {
                            "before_sha": "30de015c871d435622ad849be36e2a9b2490c76d",
                            "created_at": "2020-05-08 20:39:53 UTC",
                            "detailed_status": "failed",
                            "duration": 12,
                            "finished_at": "2020-05-08 20:54:58 UTC",
                            "id": 634680,
                            "ref": "ci",
                            "sha": "b2374cdca84c06dc86d4f60a58553df40a1873d1",
                            "source": "push",
                            "stages": [
                                "build"
                            ],
                            "status": "failed",
                            "tag": false,
                            "variables": []
                        },
                        "object_kind": "pipeline",
                        "project": {
                            "avatar_url": null,
                            "ci_config_path": "",
                            "default_branch": "master",
                            "description": "Project for testing gitlab webhooks",
                            "git_http_url": "https://gitlab.org/user/testing.git",
                            "git_ssh_url": "ssh://git@gitlab.org:3389/user/testing.git",
                            "id": 6665,
                            "name": "Testing",
                            "namespace": "User",
                            "path_with_namespace": "user/testing",
                            "visibility_level": 10,
                            "web_url": "https://gitlab.org/user/testing"
                        },
                        "user": {
                            "avatar_url": "https://gitlab.org/uploads/-/system/user/avatar/19/avatar.png",
                            "email": "kafka@schloss.com",
                            "name": "Franz Kafka",
                            "username": "kafka"
                        }
                    }"#;

                let _pipeline: PipelineHook = serde_json::from_str(JSON).unwrap();

                let webhook: WebHookExt = serde_json::from_str(JSON).unwrap();
                assert!(matches!(webhook, WebHookExt::Pipeline(_)));
            }
        }
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
    use crate::models::{self, Data, Db, ProjectId, State, User};
    use lazy_static::lazy_static;
    use url::Url;

    pub async fn answer(state: State, user: User, msg: webex::types::Message) {
        let text = msg.text.as_deref();
        let cmd = Command::from_text(text.unwrap_or_default());

        let reply = match cmd {
            Command::Welcome => welcome(&state.lock().await.public_url),
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
        if user_projects.iter().any(|&id| id == project) {
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

    pub async fn notify(state: State, msg: models::gitlab::WebHookExt) {
        use gitlab::webhooks::WebHook::*;
        let project_id: ProjectId = match &msg {
            // Push(hook) => hook.project_id,
            // Issue(hook) => hook.project.project_id,
            models::gitlab::WebHookExt::Standard(MergeRequest(hook)) => {
                hook.object_attributes.target_project_id
            }
            // Note(hook) => hook.project_id,
            // Build(hook) => hook.project_id,
            // WikiPage(hook) => hook.project_id,
            _ => {
                log::debug!("dropping unhandled gitlab hook: {:?}", msg);
                return;
            }
        }
        .into();

        let state = state.lock().await;

        let client = webex::Webex::new(&state.webex_token);

        if let Some(notificaton) = format_gitlab_notification(&msg) {
            if let Some(project_users) = state.db.projects.get(&project_id) {
                for user in project_users {
                    let msg_out = webex::types::MessageOut {
                        to_person_email: Some(user.clone().into()),
                        markdown: Some(notificaton.clone()),
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
    }

    fn format_gitlab_notification(msg: &models::gitlab::WebHookExt) -> Option<String> {
        let merge_request = match msg {
            models::gitlab::WebHookExt::Standard(gitlab::webhooks::WebHook::MergeRequest(
                merge_request,
            )) => merge_request,
            _ => return None,
        };

        let title = if let Some(url) = &merge_request.object_attributes.url {
            format!(
                "[{title}]({url})",
                title = merge_request.object_attributes.title,
                url = url
            )
        } else {
            merge_request.object_attributes.title.clone()
        };

        let description = if let Some(description) = &merge_request.object_attributes.description {
            format!("\n\n{}", description)
        } else {
            "".to_string()
        };

        use gitlab::webhooks::MergeRequestAction;
        let verb = match merge_request.object_attributes.action? {
            MergeRequestAction::Open => {
                return Some(format!(
                    "New merge request {title} in [{project}]({project_url}){description}",
                    title = title,
                    project = merge_request.project.name,
                    project_url = merge_request.project.web_url,
                    description = description
                ))
            }
            // we don't hand updates since we don't know what changed
            MergeRequestAction::Update => return None,
            MergeRequestAction::Close => "closed",
            MergeRequestAction::Reopen => "reopened",
            MergeRequestAction::Merge => "merged",
        };

        Some(format!(
            "Merge request {title} in [{project}]({project_url}) {verb}",
            title = title,
            project = merge_request.project.name,
            project_url = merge_request.project.web_url,
            verb = verb
        ))
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
