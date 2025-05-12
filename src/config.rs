use clap::Parser;

use crate::handshake::Transport;

/// CLI tool to test TLS handshakes via SNI and resolved address.
#[derive(Parser, Debug)]
#[command(name = "tlsi", about = "QUIC/TLS SNI handshake checker")]
pub struct Args {
    /// Host to connect to (used for DNS resolution).
    pub host: String,

    /// Port to connect to.
    pub port: u16,

    /// The SNI (Server Name Indication) to send during TLS handshake.
    #[arg(long)]
    pub sni: String,

    /// Transport to use.
    #[arg(long)]
    pub transport: Transport,

    /// Number of handshakes to run in a given session.
    #[arg(short, long)]
    pub number_of_handshakes: u64,
}
