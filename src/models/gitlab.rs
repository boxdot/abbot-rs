
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
