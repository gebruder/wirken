use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("hash chain broken at row {id}: expected {expected}, found {found}")]
    HashChainBroken {
        id: i64,
        expected: String,
        found: String,
    },

    #[error("audit writer channel closed")]
    ChannelClosed,

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("schema drift at session {session_id} seq {seq}: {reason}")]
    SchemaDrift {
        session_id: String,
        seq: u64,
        reason: String,
    },

    #[error("SIEM configuration error: {0}")]
    SiemConfig(String),
}
