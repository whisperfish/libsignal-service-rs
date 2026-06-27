//! Key Transparency verification example.
//!
//! Usage: cargo run --example key_transparency -- [--staging] --aci ...

use anyhow::{Context, Result};
use clap::Parser;
use libsignal_core::E164;
use libsignal_service::configuration::SignalServers;
use libsignal_service::key_transparency::{
    production_public_config, staging_public_config, ChatSearchParams,
    InMemoryKeyTransparencyStore,
};
use libsignal_service::protocol::PublicKey;
use libsignal_service::push_service::PushService;
use libsignal_service::websocket;
use serde_json::json;
use uuid::Uuid;
use zkgroup::profiles::ProfileKey;

#[derive(Parser, Debug)]
#[command(name = "key_transparency")]
#[command(
    about = "Verify identity keys against Signal's Key Transparency directory"
)]
#[command(version)]
struct Args {
    /// Use staging servers
    #[arg(long)]
    staging: bool,

    /// Target ACI to verify
    #[arg(long)]
    target_aci: Uuid,

    /// Target's identity key (32-byte Ed25519 public key, hex-encoded)
    #[arg(long)]
    target_identity: String,

    /// Target's profile key (32-byte, hex-encoded, optional)
    #[arg(long)]
    target_profile_key: Option<String>,

    /// Verbose output
    #[arg(long)]
    verbose: bool,
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
        tracing_subscriber::fmt::init();
    }

    // Create PushService and authenticated socket
    let servers = if args.staging {
        SignalServers::Staging
    } else {
        SignalServers::Production
    };

    let mut push_service = PushService::new(servers, None, "kt-example/1.0");
    let mut socket = push_service
        .ws::<websocket::Unidentified>(
            "/v1/websocket/",
            "/v1/keepalive",
            &[],
            None,
        )
        .await
        .context("Failed to create WebSocket")?;

    // Create KT store and client
    let store = InMemoryKeyTransparencyStore::new();
    let config = if args.staging {
        staging_public_config()
    } else {
        production_public_config()
    };
    let mut client = socket.key_transparency(config, &store);

    // Build profile key from hex string if provided
    let profile_key: Option<ProfileKey> = args
        .target_profile_key
        .as_ref()
        .map(|pk_hex| -> Result<ProfileKey> {
            let pk_bytes = hex::decode(pk_hex)?;
            let pk_array: [u8; 32] = pk_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Profile key must be 32 bytes"))?;
            Ok(ProfileKey::create(pk_array))
        })
        .transpose()?;

    // Deserialize the target's identity key. Accept either the raw 32-byte
    // Ed25519 key (prepend the Djb 0x05 prefix) or the full 33-byte serialized
    // form (already prefixed).
    let mut key_bytes = hex::decode(&args.target_identity)?;
    if key_bytes.len() == 32 {
        let mut v = Vec::with_capacity(33);
        v.push(0x05u8);
        v.extend_from_slice(&key_bytes);
        key_bytes = v;
    }
    let target_identity_key =
        PublicKey::deserialize(&key_bytes).expect("valid identity key bytes");

    // Build search params with flat, high-level types
    let params = ChatSearchParams::<E164> {
        target_aci: args.target_aci.into(),
        target_identity_key,
        target_e164: None,
        target_username: None,
        target_profile_key: profile_key,
        last_tree_head_size: None,
        distinguished_tree_head_size: None,
    };

    // Call search_and_verify
    let result = client
        .search_and_verify(params)
        .await
        .context("KT search and verify failed")?;

    // Once monitored, exercise the cheaper monitor path too: proves the ACI is
    // still correctly placed in a consistently-grown tree. In one session this
    // validates the full monitor wiring end-to-end.
    let mut monitor = None;
    if result.now_monitored {
        monitor = Some(
            client
                .monitor_and_verify(args.target_aci.into())
                .await
                .context("KT monitor and verify failed")?,
        );
    }

    // Emit a structured result. Identity keys are public, so echoing the
    // target key is fine; the profile key is not (it gates profile access).
    let json = json!({
        "status": "ok",
        "aci": args.target_aci.to_string(),
        "key_matches": result.key_matches,
        "now_monitored": result.now_monitored,
        "monitor": monitor.as_ref().map(|m| json!({
            "verified": m.verified,
        })),
    });
    println!("{}", serde_json::to_string_pretty(&json)?);

    Ok(())
}
