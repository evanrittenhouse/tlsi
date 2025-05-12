use anyhow::{anyhow, bail, Result};
use clap::Parser;
use config::Args;
use handshake::Session;
use regex::Regex;
use std::error::Error;
use tokio::net::lookup_host;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let Args {
        host,
        port,
        sni,
        transport,
        number_of_handshakes,
    } = Args::parse();
    let addr = resolve_host(&host, port).await?;
    println!("{addr:?}");

    let mut session = Session::new(host, port, sni, transport, number_of_handshakes);

    session.run(addr).await;

    println!("Result: {:?}", session.hist);

    // println!("🔍 Resolved {}:{} -> {}", args.host, args.port, addr);

    // // Replace with actual TLS code later
    // // let handshake_result = simulate_tls_handshake(&repr, Transport::Tcp, addr).await;

    // let hooks = Hooks {
    //     connection_hook: Some(Arc::new(Tls)),
    // };

    // let params = ConnectionParams::new_client(QuicSettings::default(), None, hooks);

    //     if handshake_result.success {
    //         println!("✅ TLS handshake to {} (SNI: {repr}) succeeded.", addr);
    //     } else {
    //         println!("❌ TLS handshake to {} (SNI: {repr}) failed.", addr);
    //     }

    Ok(())
}

async fn resolve_host(host: &str, port: u16) -> Result<std::net::SocketAddr> {
    let regex = Regex::new(r"^([a-zA-Z]*://)?(?<domain>)")?;
    let Some(caps) = regex.captures(host) else {
        bail!("no host provided!");
    };

    let domain = &caps["domain"];
    let mut addrs = lookup_host((domain, port)).await?;
    addrs
        .next()
        .ok_or_else(|| anyhow!("Could not resolve {}:{}", host, port))
}

/*
*     {
       "-connect", kRequiredArgument,
       "The hostname and port of the server to connect to, e.g. foo.com:443",
   },
   {
       "-cipher", kOptionalArgument,
       "An OpenSSL-style cipher suite string that configures the offered "
       "ciphers",
   },
   {
       "-curves", kOptionalArgument,
       "An OpenSSL-style ECDH curves list that configures the offered curves",
   },
   {
       "-sigalgs", kOptionalArgument,
       "An OpenSSL-style signature algorithms list that configures the "
       "signature algorithm preferences",
   },
   {
       "-max-version", kOptionalArgument,
       "The maximum acceptable protocol version",
   },
   {
       "-min-version", kOptionalArgument,
       "The minimum acceptable protocol version",
   },
   {
       "-server-name", kOptionalArgument, "The server name to advertise",
   },
   {
       "-ech-grease", kBooleanArgument, "Enable ECH GREASE",
   },
   {
       "-ech-config-list", kOptionalArgument,
       "Path to file containing serialized ECHConfigs",
   },
   {
       "-select-next-proto", kOptionalArgument,
       "An NPN protocol to select if the server supports NPN",
   },
   {
       "-alpn-protos", kOptionalArgument,
       "A comma-separated list of ALPN protocols to advertise",
   },
   {
       "-fallback-scsv", kBooleanArgument, "Enable FALLBACK_SCSV",
   },
   {
       "-ocsp-stapling", kBooleanArgument,
       "Advertise support for OCSP stabling",
   },
   {
       "-signed-certificate-timestamps", kBooleanArgument,
       "Advertise support for signed certificate timestamps",
   },
   {
       "-channel-id-key", kOptionalArgument,
       "The key to use for signing a channel ID",
   },
   {
       "-false-start", kBooleanArgument, "Enable False Start",
   },
   {
       "-session-in", kOptionalArgument,
       "A file containing a session to resume.",
   },
   {
       "-session-out", kOptionalArgument,
       "A file to write the negotiated session to.",
   },
   {
       "-key", kOptionalArgument,
       "PEM-encoded file containing the private key.",
   },
   {
       "-cert", kOptionalArgument,
       "PEM-encoded file containing the leaf certificate and optional "
       "certificate chain. This is taken from the -key argument if this "
       "argument is not provided.",
   },
   {
       "-starttls", kOptionalArgument,
       "A STARTTLS mini-protocol to run before the TLS handshake. Supported"
       " values: 'smtp'",
   },
   {
       "-grease", kBooleanArgument, "Enable GREASE",
   },
   {
       "-permute-extensions",
       kBooleanArgument,
       "Permute extensions in handshake messages",
   },
   {
       "-test-resumption", kBooleanArgument,
       "Connect to the server twice. The first connection is closed once a "
       "session is established. The second connection offers it.",
   },
   {
       "-root-certs", kOptionalArgument,
       "A filename containing one or more PEM root certificates. Implies that "
       "verification is required.",
   },
   {
       "-root-cert-dir", kOptionalArgument,
       "A directory containing one or more root certificate PEM files in "
       "OpenSSL's hashed-directory format. Implies that verification is "
       "required.",
   },
   {
       "-early-data", kOptionalArgument, "Enable early data. The argument to "
       "this flag is the early data to send or if it starts with '@', the "
       "file to read from for early data.",
   },
   {
       "-http-tunnel", kOptionalArgument,
       "An HTTP proxy server to tunnel the TCP connection through",
   },
   {
       "-renegotiate-freely", kBooleanArgument,
       "Allow renegotiations from the peer.",
   },
   {
       "-debug", kBooleanArgument,
       "Print debug information about the handshake",
   },

*/

mod config;
mod handshake;
