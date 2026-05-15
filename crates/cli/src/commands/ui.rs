//! User-facing wizard rendering helpers.
//!
//! Three patterns repeat across the setup wizard: numbered step
//! headers, indented body paragraphs, and the welcome/outro panels.
//! These helpers are the single source of truth for indent depth,
//! blank-line placement, and the outro's column alignment, so a
//! future wizard slice does not have to count spaces by hand.
//!
//! Indentation convention: every user-facing line is prefixed with
//! two spaces. The helpers handle that prefix so call sites stay
//! flush-left in source. The exception is the outro's Next-steps
//! command list, which uses a four-space indent (nested under the
//! `Next steps:` header) with a fixed column for descriptions.

/// Step header in the form `  Step N: Title` followed by one blank
/// line. Caller owns whatever leading whitespace separates this
/// step from the previous one.
pub fn step(n: u8, title: &str) {
    println!("  Step {n}: {title}");
    println!();
}

/// Body block: each line prefixed with the wizard's two-space
/// indent. Empty entries render as bare blank lines so paragraph
/// breaks read naturally without the indent prefix appearing on an
/// otherwise empty line. No leading or trailing blank is added; the
/// caller owns the surrounding whitespace.
pub fn body(lines: &[&str]) {
    for line in lines {
        if line.is_empty() {
            println!();
        } else {
            println!("  {line}");
        }
    }
}

/// First-run welcome panel: two paragraphs naming what wirken is
/// and previewing the six setup phases, with a trailing blank line
/// so the Continue prompt that follows in the caller sits flush
/// against the panel.
pub fn welcome() {
    body(&[
        "Wirken is the switchboard between your messaging channels and an",
        "AI agent you control. Credentials never reach the LLM. Every",
        "action is logged in a signed, hash-chained audit log.",
        "",
        "Setup walks through six steps: provider, channels, credentials,",
        "service, sandbox, audit. About a minute.",
    ]);
    println!();
}

/// Service-install footer state for the outro.
pub enum ServiceState<'a> {
    Running { manage_command: &'a str },
    NotRunning { start_command: &'a str },
}

/// Structured setup outro: summary, Next-steps command panel,
/// WebChat URL, service-state footer. Caller is responsible for the
/// single blank line that precedes "Setup complete!"; the outro
/// owns everything else through its trailing blank.
pub fn outro(provider: &str, channels: &[&str], webchat_url: &str, service: ServiceState<'_>) {
    println!("  Setup complete!");
    println!();
    println!("  Provider: {provider}");
    if channels.is_empty() {
        println!("  Channels: none (add later with `wirken channel add`)");
    } else {
        println!("  Channels: {}", channels.join(", "));
    }
    println!();
    println!("  Next steps:");
    println!("    wirken channel add <channel>      Add another messaging channel");
    println!("    wirken credentials add <name>     Add or rotate a key");
    println!("    wirken doctor                     Verify the install");
    println!("    wirken session list               See active conversations");
    println!();
    println!("  WebChat: {webchat_url}");
    println!();
    match service {
        ServiceState::Running { manage_command } => {
            println!("  Wirken is running as a service.");
            println!("  Manage with: {manage_command}");
        }
        ServiceState::NotRunning { start_command } => {
            println!("  Start wirken: {start_command}");
        }
    }
    println!();
}
