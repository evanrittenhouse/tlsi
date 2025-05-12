use anyhow::{bail, Result};
use boring::ssl::{SslConnector, SslMethod};
use histogram::Histogram;
use quiche::{self, RecvInfo};
use ring::rand::*;
use std::{
    net::SocketAddr,
    str::FromStr,
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpStream, UdpSocket},
    task::JoinSet,
};
use tokio_boring::connect;

#[derive(Debug, Default)]
pub struct HandshakeResult {
    success: bool,
    duration: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
pub enum Transport {
    Tcp,
    Quic,
}

impl FromStr for Transport {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "quic" => Ok(Self::Quic),
            _ => bail!("unknown transport"),
        }
    }
}

pub struct Session {
    host: String,
    port: u16,
    sni: String,
    transport: Transport,

    num_handshakes: u64,
    pub hist: Histogram,
}

impl Session {
    pub fn new(
        host: String,
        port: u16,
        sni: String,
        transport: Transport,
        num_handshakes: u64,
    ) -> Self {
        Self {
            host,
            port,
            sni,
            transport,
            num_handshakes,
            hist: Histogram::new(
                8,
                // We want max duration of 5s (5000 milliseconds), so 2^13
                // is the closest power above that
                13,
            )
            .unwrap(),
        }
    }

    pub async fn run(&mut self, addr: SocketAddr) {
        let mut join_set: JoinSet<Result<HandshakeResult>> = JoinSet::new();

        for _ in 0..self.num_handshakes {
            join_set.spawn(Self::handshake_inner(
                self.transport,
                self.sni.clone(),
                addr,
            ));
        }

        let results = join_set.join_all().await;
        for result in results {
            let Ok(inner) = result else {
                continue;
            };

            let Some(duration) = inner.duration else {
                continue;
            };

            self.hist.increment(duration.as_millis() as u64);
        }
    }

    async fn handshake_inner(
        transport: Transport,
        sni: String,
        addr: SocketAddr,
    ) -> Result<HandshakeResult> {
        match transport {
            Transport::Tcp => {
                let stream = TcpStream::connect(addr).await?;

                let connector = SslConnector::builder(SslMethod::tls_client())?.build();
                let config = connector.configure()?;

                let then = Instant::now();
                match connect(config, &sni, stream).await {
                    Ok(_) => {
                        let now = Instant::now();

                        Ok(HandshakeResult {
                            success: true,
                            duration: Some(now - then),
                        })
                    }
                    Err(_) => Ok(HandshakeResult {
                        success: false,
                        duration: None,
                    }),
                }
            }
            Transport::Quic => {
                let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

                let socket = UdpSocket::bind("0.0.0.0:0").await?;
                socket.connect(addr.clone()).await?;
                let local_addr = socket.local_addr().unwrap();

                // Generate a random source connection ID for the connection.
                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                SystemRandom::new().fill(&mut scid[..]).unwrap();
                let scid = quiche::ConnectionId::from_ref(&scid);

                let mut conn =
                    quiche::connect(Some(&sni), &scid, local_addr, addr, &mut config).unwrap();
                let recv_info = RecvInfo {
                    from: addr,
                    to: local_addr,
                };

                let mut buf = vec![0; 65536];

                let mut send_to: Option<SocketAddr> = None;
                let then = Instant::now();
                let success = loop {
                    let mut total = 0;

                    'write: loop {
                        let (written, send_info) = match conn.send(&mut buf) {
                            Ok(v) => v,
                            Err(e) => {
                                println!("{e:?}");
                                break 'write;
                            }
                        };

                        total += written;
                        send_to = Some(send_info.to);
                    }

                    socket
                        .send_to(&buf[..total], &send_to.expect("no bytes written"))
                        .await
                        .unwrap();

                    socket.readable().await?;
                    match socket.try_recv(&mut buf) {
                        Ok(n) => {
                            let _ = conn.recv(&mut buf[..n], recv_info);
                            if conn.is_established() {
                                break true;
                            }
                        }
                        // Avoid bailing on false positives
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(_) => break false,
                    };
                };

                let now = Instant::now();
                Ok(HandshakeResult {
                    success,
                    duration: Some(now - then),
                })
            }
        }
    }
}
