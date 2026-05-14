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
        /// Organization config endpoint (pulls provider, SIEM, MCP, and policy from a central URL)
        #[arg(long)]
        org: Option<String>,
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

    /// Run the MCP proxy (called by the gateway daemon)
    #[command(name = "mcp-proxy", hide = true)]
    McpProxy,

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

    /// Manage MCP integrations (OAuth bootstrap, …)
    #[command(subcommand)]
    Mcp(McpCommands),

    /// Manage agents
    #[command(subcommand)]
    Agents(AgentCommands),

    /// Search, install, and manage skills
    #[command(subcommand)]
    Skills(SkillCommands),

    /// Install and inspect bundled presets
    #[command(subcommand)]
    Preset(PresetCommands),

    /// Manage personas (agent + preset bundles)
    ///
    /// A persona is an AgentConfig row optionally pointing at a Preset.
    /// For lower-level access:
    ///
    ///   wirken agents: raw AgentConfig CRUD
    ///   wirken preset: skill-bundle management
    ///
    /// Use `wirken persona` for the operator-facing workflow; the
    /// lower-level commands cover advanced cases.
    #[command(subcommand)]
    Persona(PersonaCommands),

    /// Run the Zirkel orchestrator (cron or manual)
    #[command(subcommand)]
    Zirkel(ZirkelCommands),

    /// Manage scheduled cron jobs
    #[command(subcommand)]
    Cron(CronCommands),

    /// Lyrik security-assessment skill commands
    #[command(subcommand)]
    Lyrik(LyrikCommands),

    /// Send a message to an agent (also called a persona)
    #[command(name = "ask")]
    Ask {
        /// The message to send
        #[arg(short, long)]
        message: String,
        /// Agent / persona name. The two flags are interchangeable;
        /// every persona is an AgentConfig row keyed by its name, so
        /// `--agent alice` and `--persona alice` both resolve the
        /// same row. (default: "default")
        #[arg(long, visible_alias = "persona", default_value = "default")]
        agent: String,
    },

    /// Run diagnostics
    Doctor,
}

#[derive(Subcommand)]
enum LyrikCommands {
    /// Drive Lyrik phases against a target directory.
    Run {
        /// Path to the target directory containing `.lyrik/config.json`.
        #[arg(long)]
        target: std::path::PathBuf,
        /// Run-id; supports nested form `<sample>/run-<N>`.
        #[arg(long)]
        run: String,
        /// Reproduction mode: copy this findings.json into the run-state
        /// directory instead of dispatching the Lyrik skill via the agent
        /// runtime. Required until the agent-dispatch wiring lands.
        #[arg(long)]
        use_fixture: Option<std::path::PathBuf>,
    },
    /// Emit a Lyrik report in the requested format.
    Report {
        /// Output format. Currently only `sarif` is supported.
        #[arg(long, default_value = "sarif")]
        format: String,
        /// Path to findings.json. Mutually exclusive with `--run`.
        #[arg(long)]
        findings: Option<std::path::PathBuf>,
        /// Run-id under `<cwd>/.lyrik/state/runs/<run-id>/`. Mutually exclusive with `--findings`.
        #[arg(long)]
        run: Option<String>,
        /// Output file path. Parent directory is created if missing.
        #[arg(long)]
        output: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
enum ChannelCommands {
    /// Add a new channel
    Add {
        /// Channel type (telegram, discord, slack, whatsapp, etc.)
        channel: String,
        /// Access/bot token. Reads WIRKEN_<CHANNEL>_TOKEN env var if not supplied.
        #[arg(long)]
        token: Option<String>,
        /// WhatsApp: Cloud API phone number ID (15-16 digit numeric).
        /// Reads WIRKEN_WHATSAPP_PHONE_NUMBER_ID if not supplied.
        #[arg(long)]
        phone_number_id: Option<String>,
        /// WhatsApp: webhook verify token Meta calls with ?hub.verify_token=.
        /// Reads WIRKEN_WHATSAPP_VERIFY_TOKEN if not supplied.
        #[arg(long)]
        verify_token: Option<String>,
        /// WhatsApp: Meta app secret (32-char lowercase hex) for HMAC signature.
        /// Reads WIRKEN_WHATSAPP_APP_SECRET if not supplied.
        #[arg(long)]
        app_secret: Option<String>,
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
        /// Filter by actor
        #[arg(long)]
        actor: Option<String>,
        /// Filter by session id (full canonical form)
        #[arg(long)]
        session: Option<String>,
        /// Filter to events at or after this timestamp (RFC 3339)
        #[arg(long)]
        since: Option<String>,
        /// Filter to events at or before this timestamp (RFC 3339)
        #[arg(long)]
        until: Option<String>,
        /// Number of events to show
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
        /// Output format: human (default) or json
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Verify audit log hash chain integrity
    Verify {
        /// Output format: human (default) or json
        #[arg(long, default_value = "human")]
        format: String,
        /// Hard-fail on any session that has zero signed ChainHead
        /// rows. Without this flag, transition-era sessions
        /// recorded before chain-head signing was wired in are
        /// reported in counts and the verify exits zero. Always
        /// hard-fail on an invalid signature regardless of this
        /// flag.
        #[arg(long)]
        require_signed: bool,
    },
    /// Verify session attestation signatures across every session
    VerifyAttestations,
}

#[derive(Subcommand)]
enum SessionCommands {
    /// List active sessions
    List {
        /// Filter by channel
        #[arg(long)]
        channel: Option<String>,
        /// Show child sessions spawned by this parent session ID
        #[arg(long)]
        parent: Option<String>,
    },
    /// Close a session
    Close {
        /// Session ID
        id: String,
    },
    /// Reproducibly verify a session log: chain integrity, LLM
    /// input hashes, and deterministic tool re-execution.
    Verify {
        /// Session ID (format: `agent_id/channel/conversation_id`,
        /// or bare `agent_id` for legacy slice-1 sessions).
        id: String,
        /// Strict mode: exit non-zero on any unverifiable event,
        /// not just divergences.
        #[arg(long)]
        strict: bool,
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
    /// Grant an approval for an action key. Without `--session`,
    /// writes a 30-day persisted approval to `permissions.db`.
    /// With `--session <id>`, writes a session-scoped approval that
    /// lives in-memory for the named agent session only and is
    /// cleared on session end; the grant is recorded in the
    /// session's audit chain as `PermissionApproved` and replayed
    /// from the log on next wake.
    Approve {
        /// Action key to approve (e.g., shell:ls, file:/path)
        key: String,
        /// Agent ID
        #[arg(long, default_value = "default")]
        agent: String,
        /// Scope the grant to a single agent session. Pass the
        /// full session id (`{agent}/{channel}/{conversation}`).
        /// Without this flag the approval is persisted for 30 days.
        #[arg(long)]
        session: Option<String>,
    },
    /// Revoke a permission
    Revoke {
        /// Action key to revoke
        key: String,
        /// Agent ID
        #[arg(long, default_value = "default")]
        agent: String,
    },
    /// Show permission denials that have no current approval
    ListPending {
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
    /// Allow a parent agent to spawn a child agent with capability ceilings
    AllowSubagent {
        /// Parent agent ID
        parent: String,
        /// Child agent ID
        child: String,
        /// Comma-separated list of tools the child may use (empty = no tools)
        #[arg(long, default_value = "")]
        tools: String,
        /// Maximum permission tier: tier1, tier2, tier3
        #[arg(long, default_value = "tier1")]
        max_tier: String,
        /// Maximum LLM rounds for the child
        #[arg(long, default_value = "5")]
        max_rounds: usize,
        /// Wall-clock timeout in seconds
        #[arg(long, default_value = "30")]
        max_runtime: u64,
    },
    /// Remove a child agent from a parent's allowed subagents
    DenySubagent {
        /// Parent agent ID
        parent: String,
        /// Child agent ID
        child: String,
    },
    /// Update a per-agent setting
    Set {
        /// Agent ID
        id: String,
        /// Override tool calling: true, false, or auto (provider default)
        #[arg(long)]
        tools_enabled: Option<String>,
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
        /// Treat self-signed bundles as a verification failure. The
        /// default verifies the bundle is internally consistent; in
        /// `--strict` mode an unsigned or only-self-signed bundle
        /// exits 1, requiring out-of-band trust anchoring.
        #[arg(long)]
        strict: bool,
    },
    /// Migrate operator skills to the current frontmatter shape.
    /// Renames the deprecated `openclaw` metadata key to `wirken` and
    /// inserts an empty `permissions:` stub when missing. Each
    /// modified file is backed up to `SKILL.md.pre-migrate-<utc>`
    /// before rewriting.
    Migrate {
        /// Path to scan. Defaults to `<data_dir>/skills/` (operator
        /// skill tree). Pass an explicit path to migrate elsewhere.
        path: Option<String>,
        /// Print what would change without writing or backing up.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum PersonaCommands {
    /// Create a new persona row in the agent config store.
    Create {
        /// Persona name (used as both the AgentConfig id and the display name).
        name: String,
        /// Optional preset bundle to attach. May reference a preset that
        /// is not yet installed; the persona keeps the reference and the
        /// persona view surfaces a dangling-reference error at lookup.
        #[arg(long)]
        preset: Option<String>,
        /// LLM provider (openai, anthropic, ollama, custom).
        #[arg(long, default_value = "openai")]
        provider: String,
        /// Model id.
        #[arg(long, default_value = "gpt-4o")]
        model: String,
        /// API base URL.
        #[arg(long, default_value = "https://api.openai.com/v1")]
        base_url: String,
        /// Vault credential name for the API key. Empty if the provider
        /// does not require one (e.g. local ollama).
        #[arg(long, default_value = "")]
        credential: String,
        /// Channels to bind to this persona. Repeat for multiple.
        #[arg(long)]
        channel: Vec<String>,
        /// Child personas this persona may spawn as subagents. Each entry
        /// is added with the default ceiling (no tools, tier1, 5 rounds,
        /// 30s); refine via `wirken agents allow-subagent`.
        #[arg(long)]
        allow_subagent: Vec<String>,
    },
    /// List configured personas.
    List,
    /// Show the resolved view (config + preset + skills) for one persona.
    Show {
        /// Persona name.
        name: String,
    },
    /// Edit fields on an existing persona. At least one field flag is
    /// required.
    Edit {
        /// Persona name.
        name: String,
        /// Replace the preset reference. Conflicts with --clear-preset.
        #[arg(long, conflicts_with = "clear_preset")]
        preset: Option<String>,
        /// Remove the preset reference entirely.
        #[arg(long, conflicts_with = "preset")]
        clear_preset: bool,
        /// New provider.
        #[arg(long)]
        provider: Option<String>,
        /// New model id.
        #[arg(long)]
        model: Option<String>,
        /// New API base URL.
        #[arg(long)]
        base_url: Option<String>,
        /// New vault credential name.
        #[arg(long)]
        credential: Option<String>,
        /// Replace the channel set. Repeat for multiple channels; pass
        /// the flag at least once to mark a replacement (empty channel
        /// sets are not editable via this flag; use `wirken agents` for
        /// that case).
        #[arg(long)]
        channel: Vec<String>,
        /// New display name.
        #[arg(long)]
        display_name: Option<String>,
    },
    /// Delete a persona row. Workspace and per-agent skill directories
    /// are left on disk; remove them manually if no longer needed.
    Delete {
        /// Persona name.
        name: String,
    },
}

#[derive(Subcommand)]
enum PresetCommands {
    /// List bundled presets that can be installed
    List,
    /// Install a bundled preset to ~/.wirken/presets/<name>/
    Install {
        /// Preset name (e.g. `zirkel`)
        name: String,
    },
    /// Wire a daily cron entry that runs the preset's orchestrator
    Schedule {
        /// Preset name
        name: String,
    },
    /// Remove the wirken-managed cron entry for the preset
    Unschedule {
        /// Preset name
        name: String,
    },
}

#[derive(Subcommand)]
enum ZirkelCommands {
    /// Run the Zirkel orchestrator once (cron or manual entry).
    /// In Scope B this is a stub that loads the installed preset and
    /// reports it's ready. Scope C wires the fetch pipeline.
    Run,
    /// Bind the daily digest to an outbound channel + conversation.
    /// `wirken zirkel run` reads the binding and pushes the digest
    /// after a successful run; `wirken run`'s agent for the bound
    /// agent_id picks up the keep/skip interceptor at startup.
    Bind {
        /// Channel to push digests to (e.g. `signal`, `slack`).
        /// Must match an adapter registered with `wirken channel add`.
        #[arg(long)]
        channel: String,
        /// Conversation id within that channel (Signal phone number,
        /// Slack channel id, etc.).
        #[arg(long)]
        conversation: String,
        /// Agent that owns the keep/skip interceptor for this binding.
        /// Defaults to `default`. Should match a configured agent_id.
        #[arg(long, default_value = "default")]
        agent: String,
        /// Replace an existing binding with a different target.
        /// Required when the agent is already bound elsewhere; same-
        /// target re-binds are always a no-op.
        #[arg(long)]
        force: bool,
    },
    /// Remove the digest binding for an agent.
    Unbind {
        #[arg(long, default_value = "default")]
        agent: String,
    },
    /// Print the current digest binding (or a "no binding" message).
    Status,
    /// Store an api.data.gov API key in the wirken vault for a
    /// zirkel-bound source. Prompts for the key, validates it
    /// against the source's API before storing (a typo'd key
    /// won't survive the round trip).
    AuthSet {
        /// Source name as it appears in `sources.toml` (e.g.
        /// `congress-gov`, `govinfo-gov`).
        #[arg(long)]
        source: String,
    },
    /// List zirkel-bound API keys currently in the vault (names
    /// only — values stay encrypted).
    AuthList,
}

#[derive(Subcommand)]
enum CronCommands {
    /// List scheduled cron jobs
    List {
        /// Filter by agent ID
        #[arg(long)]
        agent: Option<String>,
    },
    /// Create a new cron job
    Create {
        /// Cron schedule (e.g., "0 0 9 * * *" for 9am daily)
        schedule: String,
        /// Message to send to the agent
        message: String,
        /// Agent ID
        #[arg(long, default_value = "default")]
        agent: String,
        /// Description
        #[arg(long, default_value = "")]
        description: String,
    },
    /// Delete a cron job
    Delete {
        /// Job ID
        id: String,
    },
    /// Pause a cron job
    Pause {
        /// Job ID
        id: String,
    },
    /// Resume a paused cron job
    Resume {
        /// Job ID
        id: String,
    },
}

#[derive(Subcommand)]
enum CredentialCommands {
    /// List stored credentials (metadata only — no secrets shown)
    List,
    /// Add a new credential. Prompts for the value on stderr; the
    /// value is encrypted with the device key before being written
    /// to the vault.
    Add {
        /// Credential name (referenced by `vault:NAME` in mcp.json
        /// auth blocks and other config)
        name: String,
        /// Optional channel/category tag for `wirken credentials list`
        #[arg(long)]
        channel: Option<String>,
        /// Read the value from stdin instead of prompting. A single
        /// trailing newline is stripped. Useful for piping:
        /// `echo "$SECRET" | wirken credentials add NAME --stdin`.
        #[arg(long, conflicts_with = "value_file")]
        stdin: bool,
        /// Read the value from a file. A single trailing newline is
        /// stripped. Mutually exclusive with --stdin.
        #[arg(long, conflicts_with = "stdin")]
        value_file: Option<std::path::PathBuf>,
    },
    /// Rotate a credential
    Rotate {
        /// Credential name
        name: String,
    },
    /// Remove a credential by name. The encrypted row is deleted from
    /// the vault. Errors if no credential with that name exists.
    Remove {
        /// Credential name
        name: String,
    },
}

#[derive(Subcommand)]
enum McpCommands {
    /// Run the OAuth2 authorization code flow for an HTTP MCP
    /// server with `auth.type = "oauth2"`. Opens the user's browser
    /// to the provider's authorization URL, spins up a localhost
    /// callback listener, exchanges the code for tokens, and stores
    /// the tokens in the vault under the credential name from the
    /// server's auth block.
    ///
    /// Slice 2 supports providers: linear, notion, github, google.
    /// Operators must register their own OAuth app at the provider
    /// and supply WIRKEN_<PROVIDER>_CLIENT_ID (and CLIENT_SECRET if
    /// the provider is confidential) before running this command.
    Authorize {
        /// MCP server name from mcp.json
        server: String,
        /// Per-agent mcp.json (default: shared ~/.wirken/mcp.json)
        #[arg(long)]
        agent: Option<String>,
        /// Explicit scope selection (repeatable). The required floor
        /// is always included regardless. Skips the interactive
        /// picker. Mutually exclusive with --no-scopes and
        /// --all-scopes.
        #[arg(
            long,
            value_name = "ID",
            conflicts_with_all = ["no_scopes", "all_scopes"]
        )]
        scope: Vec<String>,
        /// Request only the required scope floor; skip the picker.
        /// Useful for scripted bootstraps that want the minimum.
        /// Mutually exclusive with --scope and --all-scopes.
        #[arg(long, conflicts_with_all = ["scope", "all_scopes"])]
        no_scopes: bool,
        /// Request every scope in the provider's catalog; skip the
        /// picker. Mutually exclusive with --scope and --no-scopes.
        #[arg(long, conflicts_with_all = ["scope", "no_scopes"])]
        all_scopes: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

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
            org,
        } => {
            if uninstall_service {
                return commands::service::uninstall_service();
            }
            commands::setup::run(install_service, org).await
        }
        Commands::Run { port } => commands::run::run(port).await,
        Commands::Adapter { channel } => commands::adapter::run(&channel).await,
        Commands::McpProxy => commands::mcp_proxy::run().await,
        Commands::Channel(cmd) => match cmd {
            ChannelCommands::Add {
                channel,
                token,
                phone_number_id,
                verify_token,
                app_secret,
            } => {
                commands::channel::add(
                    &channel,
                    commands::channel::AddFlags {
                        token,
                        phone_number_id,
                        verify_token,
                        app_secret,
                    },
                )
                .await
            }
            ChannelCommands::List => commands::channel::list().await,
            ChannelCommands::Remove { channel } => commands::channel::remove(&channel).await,
        },
        Commands::Audit(cmd) => match cmd {
            AuditCommands::Log {
                action,
                channel,
                actor,
                session,
                since,
                until,
                limit,
                format,
            } => {
                commands::audit::log(
                    action, channel, actor, session, since, until, limit, &format,
                )
                .await
            }
            AuditCommands::Verify {
                format,
                require_signed,
            } => commands::audit::verify(&format, require_signed).await,
            AuditCommands::VerifyAttestations => commands::audit::verify_attestations().await,
        },
        Commands::Sessions(cmd) => match cmd {
            SessionCommands::List { channel, parent } => {
                commands::session::list(channel, parent).await
            }
            SessionCommands::Close { id } => commands::session::close(&id).await,
            SessionCommands::Verify { id, strict } => commands::session::verify(&id, strict).await,
        },
        Commands::Permissions(cmd) => match cmd {
            PermissionCommands::List { agent } => commands::permission::list(&agent).await,
            PermissionCommands::Approve {
                key,
                agent,
                session,
            } => commands::permission::approve(&key, &agent, session.as_deref()).await,
            PermissionCommands::Revoke { key, agent } => {
                commands::permission::revoke(&key, &agent).await
            }
            PermissionCommands::ListPending { agent } => {
                commands::permission::list_pending(&agent).await
            }
        },
        Commands::Credentials(cmd) => match cmd {
            CredentialCommands::List => commands::credential::list().await,
            CredentialCommands::Add {
                name,
                channel,
                stdin,
                value_file,
            } => {
                commands::credential::add(
                    &name,
                    channel.as_deref(),
                    commands::credential::ValueSource::from_flags(stdin, value_file),
                )
                .await
            }
            CredentialCommands::Rotate { name } => commands::credential::rotate(&name).await,
            CredentialCommands::Remove { name } => commands::credential::remove(&name).await,
        },
        Commands::Mcp(cmd) => match cmd {
            McpCommands::Authorize {
                server,
                agent,
                scope,
                no_scopes,
                all_scopes,
            } => {
                commands::mcp::authorize(&server, agent.as_deref(), scope, no_scopes, all_scopes)
                    .await
            }
        },
        Commands::Skills(cmd) => match cmd {
            SkillCommands::Search { query } => commands::skills::search(&query).await,
            SkillCommands::Install { name } => commands::skills::install(&name).await,
            SkillCommands::List => commands::skills::list().await,
            SkillCommands::Sign { dir } => commands::skills::sign(&dir).await,
            SkillCommands::Verify { dir, strict } => commands::skills::verify(&dir, strict).await,
            SkillCommands::Migrate { path, dry_run } => {
                commands::skills::migrate(path.as_deref(), dry_run).await
            }
        },
        Commands::Preset(cmd) => match cmd {
            PresetCommands::List => commands::preset::list().await,
            PresetCommands::Install { name } => commands::preset::install(&name).await,
            PresetCommands::Schedule { name } => commands::preset::schedule(&name).await,
            PresetCommands::Unschedule { name } => commands::preset::unschedule(&name).await,
        },
        Commands::Persona(cmd) => match cmd {
            PersonaCommands::Create {
                name,
                preset,
                provider,
                model,
                base_url,
                credential,
                channel,
                allow_subagent,
            } => {
                commands::persona::create(
                    &name,
                    preset.as_deref(),
                    &provider,
                    &model,
                    &base_url,
                    &credential,
                    channel,
                    allow_subagent,
                )
                .await
            }
            PersonaCommands::List => commands::persona::list().await,
            PersonaCommands::Show { name } => commands::persona::show(&name).await,
            PersonaCommands::Edit {
                name,
                preset,
                clear_preset,
                provider,
                model,
                base_url,
                credential,
                channel,
                display_name,
            } => {
                commands::persona::edit(
                    &name,
                    preset.as_deref(),
                    clear_preset,
                    provider.as_deref(),
                    model.as_deref(),
                    base_url.as_deref(),
                    credential.as_deref(),
                    channel,
                    display_name.as_deref(),
                )
                .await
            }
            PersonaCommands::Delete { name } => commands::persona::delete(&name).await,
        },
        Commands::Zirkel(cmd) => match cmd {
            ZirkelCommands::Run => commands::zirkel::run().await,
            ZirkelCommands::Bind {
                channel,
                conversation,
                agent,
                force,
            } => commands::zirkel::bind(&agent, &channel, &conversation, force).await,
            ZirkelCommands::Unbind { agent } => commands::zirkel::unbind(&agent).await,
            ZirkelCommands::Status => commands::zirkel::status().await,
            ZirkelCommands::AuthSet { source } => commands::zirkel::auth_set(&source).await,
            ZirkelCommands::AuthList => commands::zirkel::auth_list().await,
        },
        Commands::Agents(cmd) => match cmd {
            AgentCommands::Add => commands::agents::add().await,
            AgentCommands::List => commands::agents::list().await,
            AgentCommands::Remove { id } => commands::agents::remove(&id).await,
            AgentCommands::Bind { agent, channel } => {
                commands::agents::bind(&agent, &channel).await
            }
            AgentCommands::AllowSubagent {
                parent,
                child,
                tools,
                max_tier,
                max_rounds,
                max_runtime,
            } => {
                commands::agents::allow_subagent(
                    &parent,
                    &child,
                    &tools,
                    &max_tier,
                    max_rounds,
                    max_runtime,
                )
                .await
            }
            AgentCommands::DenySubagent { parent, child } => {
                commands::agents::deny_subagent(&parent, &child).await
            }
            AgentCommands::Set { id, tools_enabled } => {
                commands::agents::set(&id, tools_enabled.as_deref()).await
            }
        },
        Commands::Cron(cmd) => match cmd {
            CronCommands::List { agent } => commands::cron::list(agent.as_deref()).await,
            CronCommands::Create {
                schedule,
                message,
                agent,
                description,
            } => commands::cron::create(&schedule, &message, &agent, &description).await,
            CronCommands::Delete { id } => commands::cron::delete(&id).await,
            CronCommands::Pause { id } => commands::cron::pause(&id).await,
            CronCommands::Resume { id } => commands::cron::resume(&id).await,
        },
        Commands::Ask { message, agent } => commands::agent::send(&message, &agent).await,
        Commands::Doctor => commands::doctor::run().await,
        Commands::Lyrik(cmd) => match cmd {
            LyrikCommands::Run {
                target,
                run,
                use_fixture,
            } => commands::lyrik::run(&target, &run, use_fixture.as_deref()).await,
            LyrikCommands::Report {
                format,
                findings,
                run,
                output,
            } => {
                commands::lyrik::report(&format, findings.as_deref(), run.as_deref(), &output).await
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("clap parse failed")
    }

    #[test]
    fn persona_create_parses_with_defaults() {
        let cli = parse(&["wirken", "persona", "create", "alice"]);
        match cli.command {
            Commands::Persona(PersonaCommands::Create {
                name,
                preset,
                provider,
                model,
                base_url,
                credential,
                channel,
                allow_subagent,
            }) => {
                assert_eq!(name, "alice");
                assert!(preset.is_none());
                assert_eq!(provider, "openai");
                assert_eq!(model, "gpt-4o");
                assert_eq!(base_url, "https://api.openai.com/v1");
                assert_eq!(credential, "");
                assert!(channel.is_empty());
                assert!(allow_subagent.is_empty());
            }
            _ => panic!("expected Persona::Create"),
        }
    }

    #[test]
    fn persona_create_parses_with_every_flag() {
        let cli = parse(&[
            "wirken",
            "persona",
            "create",
            "alice",
            "--preset",
            "researcher",
            "--provider",
            "anthropic",
            "--model",
            "claude-sonnet-4-20250514",
            "--base-url",
            "https://api.anthropic.com/v1",
            "--credential",
            "alice-anthropic-key",
            "--channel",
            "slack",
            "--channel",
            "teams",
            "--allow-subagent",
            "writer",
        ]);
        match cli.command {
            Commands::Persona(PersonaCommands::Create {
                name,
                preset,
                channel,
                allow_subagent,
                ..
            }) => {
                assert_eq!(name, "alice");
                assert_eq!(preset.as_deref(), Some("researcher"));
                assert_eq!(channel, vec!["slack", "teams"]);
                assert_eq!(allow_subagent, vec!["writer"]);
            }
            _ => panic!("expected Persona::Create"),
        }
    }

    #[test]
    fn persona_list_parses() {
        let cli = parse(&["wirken", "persona", "list"]);
        assert!(matches!(
            cli.command,
            Commands::Persona(PersonaCommands::List)
        ));
    }

    #[test]
    fn persona_show_parses() {
        let cli = parse(&["wirken", "persona", "show", "alice"]);
        match cli.command {
            Commands::Persona(PersonaCommands::Show { name }) => assert_eq!(name, "alice"),
            _ => panic!("expected Persona::Show"),
        }
    }

    #[test]
    fn persona_edit_with_preset_flag_parses() {
        let cli = parse(&[
            "wirken",
            "persona",
            "edit",
            "alice",
            "--preset",
            "researcher",
        ]);
        match cli.command {
            Commands::Persona(PersonaCommands::Edit {
                name,
                preset,
                clear_preset,
                ..
            }) => {
                assert_eq!(name, "alice");
                assert_eq!(preset.as_deref(), Some("researcher"));
                assert!(!clear_preset);
            }
            _ => panic!("expected Persona::Edit"),
        }
    }

    #[test]
    fn persona_edit_with_clear_preset_parses() {
        let cli = parse(&["wirken", "persona", "edit", "alice", "--clear-preset"]);
        match cli.command {
            Commands::Persona(PersonaCommands::Edit {
                preset,
                clear_preset,
                ..
            }) => {
                assert!(preset.is_none());
                assert!(clear_preset);
            }
            _ => panic!("expected Persona::Edit"),
        }
    }

    #[test]
    fn persona_edit_rejects_both_preset_and_clear_preset() {
        let result = Cli::try_parse_from([
            "wirken",
            "persona",
            "edit",
            "alice",
            "--preset",
            "researcher",
            "--clear-preset",
        ]);
        assert!(
            result.is_err(),
            "clap must reject --preset and --clear-preset together"
        );
    }

    #[test]
    fn persona_delete_parses() {
        let cli = parse(&["wirken", "persona", "delete", "alice"]);
        match cli.command {
            Commands::Persona(PersonaCommands::Delete { name }) => assert_eq!(name, "alice"),
            _ => panic!("expected Persona::Delete"),
        }
    }
}
