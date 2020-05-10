pub mod gitlab;
pub mod webex;

use crate::DynError;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use url::Url;

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
