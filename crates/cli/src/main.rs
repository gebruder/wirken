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
    Setup {
        /// Install Wirken as a system service (systemd on Linux, launchd on macOS)
        #[arg(long)]
        install_service: bool,
        /// Uninstall the Wirken system service
        #[arg(long)]
        uninstall_service: bool,
    },

    /// Start the gateway daemon
    Run {
        /// WebChat port
        #[arg(short, long)]
        port: Option<u16>,
    },

    /// Run an adapter process (called by the gateway daemon)
    #[command(hide = true)]
    Adapter {
        /// Channel to run
        channel: String,
    },

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

    /// Manage agents
    #[command(subcommand)]
    Agents(AgentCommands),

    /// Search, install, and manage skills
    #[command(subcommand)]
    Skills(SkillCommands),

    /// Send a message to an agent
    #[command(name = "ask")]
    Ask {
        /// The message to send
        #[arg(short, long)]
        message: String,
        /// Agent ID (default: "default")
        #[arg(long, default_value = "default")]
        agent: String,
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
enum AgentCommands {
    /// Add a new agent with its own model, workspace, and channel bindings
    Add,
    /// List all configured agents
    List,
    /// Remove an agent
    Remove {
        /// Agent ID
        id: String,
    },
    /// Bind a channel to an agent
    Bind {
        /// Agent ID
        agent: String,
        /// Channel to bind
        channel: String,
    },
}

#[derive(Subcommand)]
enum SkillCommands {
    /// Search the skill registry
    Search {
        /// Search query
        query: String,
    },
    /// Install a skill from the registry
    Install {
        /// Skill name
        name: String,
    },
    /// List installed skills
    List,
    /// Sign a skill directory with Ed25519
    Sign {
        /// Path to skill directory
        dir: String,
    },
    /// Verify a skill's signature
    Verify {
        /// Path to skill directory
        dir: String,
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
        Commands::Setup {
            install_service,
            uninstall_service,
        } => {
            if uninstall_service {
                return commands::service::uninstall_service();
            }
            commands::setup::run(install_service).await
        }
        Commands::Run { port } => commands::run::run(port).await,
        Commands::Adapter { channel } => commands::adapter::run(&channel).await,
        Commands::Channel(cmd) => match cmd {
            ChannelCommands::Add { channel } => commands::channel::add(&channel).await,
            ChannelCommands::List => commands::channel::list().await,
            ChannelCommands::Remove { channel } => commands::channel::remove(&channel).await,
        },
        Commands::Audit(cmd) => match cmd {
            AuditCommands::Log {
                action,
                channel,
                limit,
            } => commands::audit::log(action, channel, limit).await,
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
        Commands::Skills(cmd) => match cmd {
            SkillCommands::Search { query } => commands::skills::search(&query).await,
            SkillCommands::Install { name } => commands::skills::install(&name).await,
            SkillCommands::List => commands::skills::list().await,
            SkillCommands::Sign { dir } => commands::skills::sign(&dir).await,
            SkillCommands::Verify { dir } => commands::skills::verify(&dir).await,
        },
        Commands::Agents(cmd) => match cmd {
            AgentCommands::Add => commands::agents::add().await,
            AgentCommands::List => commands::agents::list().await,
            AgentCommands::Remove { id } => commands::agents::remove(&id).await,
            AgentCommands::Bind { agent, channel } => {
                commands::agents::bind(&agent, &channel).await
            }
        },
        Commands::Ask { message, agent } => commands::agent::send(&message, &agent).await,
        Commands::Doctor => commands::doctor::run().await,
    }
}
