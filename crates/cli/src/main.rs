use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(name = "wirken", version, about = "Secure personal AI agent gateway")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Interactive setup wizard — configure AI provider, channels, and start the gateway
    Setup,

    /// Manage messaging channels
    #[command(subcommand)]
    Channel(ChannelCommands),

    /// Query and verify the audit log
    #[command(subcommand)]
    Audit(AuditCommands),

    /// Manage active sessions
    #[command(subcommand)]
    Sessions(SessionCommands),

    /// Manage permissions
    #[command(subcommand)]
    Permissions(PermissionCommands),

    /// Manage stored credentials
    #[command(subcommand)]
    Credentials(CredentialCommands),

    /// Send a message to the agent directly
    Agent {
        /// The message to send
        #[arg(short, long)]
        message: String,
    },

    /// Run diagnostics
    Doctor,
}

#[derive(Subcommand)]
enum ChannelCommands {
    /// Add a new channel
    Add {
        /// Channel type (telegram, discord, slack)
        channel: String,
    },
    /// List configured channels
    List,
    /// Remove a channel
    Remove {
        /// Channel to remove
        channel: String,
    },
}

#[derive(Subcommand)]
enum AuditCommands {
    /// Show recent audit events
    Log {
        /// Filter by action type
        #[arg(long)]
        action: Option<String>,
        /// Filter by channel
        #[arg(long)]
        channel: Option<String>,
        /// Number of events to show
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
    },
    /// Verify audit log hash chain integrity
    Verify,
}

#[derive(Subcommand)]
enum SessionCommands {
    /// List active sessions
    List {
        /// Filter by channel
        #[arg(long)]
        channel: Option<String>,
    },
    /// Close a session
    Close {
        /// Session ID
        id: String,
    },
}

#[derive(Subcommand)]
enum PermissionCommands {
    /// List granted permissions
    List {
        /// Agent ID
        #[arg(long, default_value = "default")]
        agent: String,
    },
    /// Revoke a permission
    Revoke {
        /// Action key to revoke
        key: String,
        /// Agent ID
        #[arg(long, default_value = "default")]
        agent: String,
    },
}

#[derive(Subcommand)]
enum CredentialCommands {
    /// List stored credentials (metadata only — no secrets shown)
    List,
    /// Rotate a credential
    Rotate {
        /// Credential name
        name: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("wirken=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Setup => commands::setup::run().await,
        Commands::Channel(cmd) => match cmd {
            ChannelCommands::Add { channel } => commands::channel::add(&channel).await,
            ChannelCommands::List => commands::channel::list().await,
            ChannelCommands::Remove { channel } => commands::channel::remove(&channel).await,
        },
        Commands::Audit(cmd) => match cmd {
            AuditCommands::Log { action, channel, limit } => {
                commands::audit::log(action, channel, limit).await
            }
            AuditCommands::Verify => commands::audit::verify().await,
        },
        Commands::Sessions(cmd) => match cmd {
            SessionCommands::List { channel } => commands::session::list(channel).await,
            SessionCommands::Close { id } => commands::session::close(&id).await,
        },
        Commands::Permissions(cmd) => match cmd {
            PermissionCommands::List { agent } => commands::permission::list(&agent).await,
            PermissionCommands::Revoke { key, agent } => {
                commands::permission::revoke(&key, &agent).await
            }
        },
        Commands::Credentials(cmd) => match cmd {
            CredentialCommands::List => commands::credential::list().await,
            CredentialCommands::Rotate { name } => commands::credential::rotate(&name).await,
        },
        Commands::Agent { message } => commands::agent::send(&message).await,
        Commands::Doctor => commands::doctor::run().await,
    }
}
