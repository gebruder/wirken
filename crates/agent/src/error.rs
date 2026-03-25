use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("llm error: {0}")]
    Llm(String),

    #[error("tool error: {0}")]
    Tool(String),

    #[error("tool not found: {0}")]
    ToolNotFound(String),

    #[error("skill load error: {0}")]
    SkillLoad(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("conversation error: {0}")]
    Conversation(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("http error: {0}")]
    Http(String),
}
