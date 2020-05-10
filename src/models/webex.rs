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
