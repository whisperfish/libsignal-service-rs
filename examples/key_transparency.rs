//! Key Transparency verification example.
//!
//! Usage: cargo run --example key_transparency -- [--staging] --aci ...

use anyhow::{Context, Result};
use clap::Parser;
use libsignal_core::E164;
use libsignal_service::configuration::{ServiceCredentials, SignalServers};
use libsignal_service::key_transparency::{
    production_public_config, staging_public_config, ChatSearchParams,
    InMemoryKeyTransparencyStore,
};
use libsignal_service::protocol::PublicKey;
use libsignal_service::push_service::PushService;
use libsignal_service::websocket;
use serde_json::json;
use std::str::FromStr;
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

    /// Your ACI (for authentication)
    #[arg(long)]
    aci: Uuid,

    /// Your Signal access password (hex-encoded)
    #[arg(long)]
    password: String,

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
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // Create credentials with stubbed phone number
    let phonenumber: E164 = E164::from_str("+10000000000")?;

    let credentials = ServiceCredentials {
        phonenumber,
        aci: Some(args.aci),
        password: Some(args.password.clone()),
        device_id: None,
        pni: None,
    };

    // Create PushService and authenticated socket
    let servers = if args.staging {
        SignalServers::Staging
    } else {
        SignalServers::Production
    };

    let mut push_service =
        PushService::new(servers, Some(credentials.clone()), "kt-example/1.0");
    let mut socket = push_service
        .ws::<websocket::Identified>(
            "/v1/websocket/",
            "/v1/keepalive",
            &[],
            Some(credentials),
        )
        .await
        .context("Failed to create authenticated WebSocket")?;

    // Create KT store and client
    let store = InMemoryKeyTransparencyStore::new();
    let config = if args.staging {
        staging_public_config()
    } else {
        production_public_config()
    };
    let mut client = socket.key_transparency(config, &store);

    // Clone target_profile_key for later use in output
    let target_profile_key_for_output = args.target_profile_key.clone();

    // Build profile key from hex string if provided
    let profile_key: Option<ProfileKey> = args
        .target_profile_key
        .map(|pk_hex| -> Result<ProfileKey> {
            let pk_bytes = hex::decode(&pk_hex)?;
            let pk_array: [u8; 32] = pk_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Profile key must be 32 bytes"))?;
            Ok(ProfileKey::create(pk_array))
        })
        .transpose()?;

    // Deserialize the target's identity key from hex bytes
    let mut key_bytes = Vec::with_capacity(33);
    key_bytes.push(0x05u8); // Djb key type prefix (KeyType::Djb = 0x05)
    key_bytes.extend_from_slice(&hex::decode(&args.target_identity)?);
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

    if args.verbose {
        eprintln!("Verification successful");
    }

    // Build JSON output
    let json = json!({
        "status": "success",
        "result": format!("{:?}", result),
        "validated": result.key_matches,
        "target_aci": args.target_aci.to_string(),
        "target_identity": args.target_identity,
        "target_profile_key": target_profile_key_for_output,
    });
    println!("{}", serde_json::to_string_pretty(&json)?);

    Ok(())
}
