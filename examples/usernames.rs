//! Username lookup example.
//!
//! Resolves a username (hash lookup) or a `signal.me` username link to an ACI.
//!
//! Usage:
//!     cargo run --example usernames -- rubdos.95
//!     cargo run --example usernames -- https://signal.me/#eu/R_rHg5IQLE60Qad5l8rV-6x2TMcVnDYvOV-igYXJj6GK1NuNeE9LKI3V_VZ8IH2p
//!     cargo run --example usernames -- rubdos.95 "https://signal.me/#eu/..."

use std::sync::LazyLock;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use libsignal_service::configuration::SignalServers;
use libsignal_service::push_service::PushService;
use libsignal_service::websocket;
use usernames::Username;

/// A bare username: `<nickname>.<discriminator>`, e.g. `rubdos.95`.
static USERNAME: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^[A-Za-z_][A-Za-z0-9_]{2,31}\.[0-9]{2,9}$")
        .expect("valid regex")
});

/// A `signal.me` username link, full or payload form.
static LINK: LazyLock<regex::Regex> = LazyLock::new(|| {
    // Matches the bare URL-safe base64 payload too; it can't contain '#' or '/'.
    regex::Regex::new(r"signal\.me/?#eu/|^[A-Za-z0-9_-]{20,}$")
        .expect("valid regex")
});

#[derive(Parser, Debug)]
#[command(name = "usernames")]
#[command(about = "Resolve Signal usernames and username links to ACIs")]
#[command(version)]
struct Args {
    /// Use staging servers
    #[arg(long)]
    staging: bool,

    /// Verbose output
    #[arg(long)]
    verbose: bool,

    /// One or more queries. Each is either a username (`rubdos.95`) or a
    /// `https://signal.me/#eu/<base64url>` username link.
    queries: Vec<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.verbose {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(
                "libsignal_service=trace",
            ))
            .init();
    } else {
        tracing_subscriber::fmt().init();
    }

    let servers = if args.staging {
        SignalServers::Staging
    } else {
        SignalServers::Production
    };

    let mut push_service =
        PushService::new(servers, None, "usernames-example/1.0");
    let mut socket = push_service
        .ws::<websocket::Unidentified>(
            "/v1/websocket/",
            "/v1/keepalive",
            &[],
            None,
        )
        .await
        .context("Failed to create WebSocket")?;

    for query in args.queries {
        let username = if USERNAME.is_match(&query) {
            println!("\n=== username: {query} ===");
            Username::new(&query)
                .map_err(|e| anyhow!("invalid username '{query}': {e}"))?
        } else if LINK.is_match(&query) {
            println!("\n=== username link: {query} ===");
            match socket
                .look_up_username_link(&query)
                .await
                .context("username link lookup failed")?
            {
                Some(username) => {
                    println!("decrypted username: {username}");
                    username
                },
                None => {
                    println!("  (link not found)");
                    continue;
                },
            }
        } else {
            return Err(anyhow!("not a username or link: {query}"));
        };

        match socket
            .look_up_username(&username)
            .await
            .context("username hash lookup failed")?
        {
            Some(aci) => println!("  ACI: {}", aci.service_id_string()),
            None => println!("  (no account found)"),
        }
    }

    Ok(())
}
