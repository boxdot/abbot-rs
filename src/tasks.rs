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
