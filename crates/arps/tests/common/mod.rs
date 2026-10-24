use arp_common::Pubkey;
use arp_common::crypto;
use arp_common::frame::Frame;
use arps::config::ServerConfig;
use arps::router::Router;
use arps::server::ServerState;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use rand::rng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

pub fn test_config(listen: SocketAddr) -> ServerConfig {
    ServerConfig {
        listen,
        metrics_addr: "127.0.0.1:0".parse().unwrap(),
        max_conns: 1000,
        max_conns_ip: 100,
        msg_rate: 120,
        bw_rate: 1_048_576,
        max_payload: 65_535,
        admit_timeout: 5,
        ping_interval: 30,
        idle_timeout: 120,
        pow_difficulty: 0,
        trusted_proxy_cidrs: vec![],
        redirect_url: None,
        pre_auth_limit: 1000,
    }
}
pub fn test_config_with_params(
    listen: SocketAddr,
    max_conns: usize,
    msg_rate: u32,
    admit_timeout: u64,
) -> ServerConfig {
    ServerConfig {
        listen,
        metrics_addr: "127.0.0.1:0".parse().unwrap(),
        max_conns,
        max_conns_ip: 100,
        msg_rate,
        bw_rate: 1_048_576,
        max_payload: 65_535,
        admit_timeout,
        ping_interval: 30,
        idle_timeout: 120,
        pow_difficulty: 0,
        trusted_proxy_cidrs: vec![],
        redirect_url: None,
        pre_auth_limit: 1000,
    }
}
pub struct TestClient {
    pub ws_tx: futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
    pub ws_rx: futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    pub pubkey: Pubkey,
}

impl TestClient {
    pub async fn connect(addr: &SocketAddr, keypair: &SigningKey) -> Self {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let url = format!("ws://{addr}");
        let mut req = url.into_client_request().unwrap();
        req.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            arp_common::types::PROTOCOL_VERSION.parse().unwrap(),
        );
        req.headers_mut()
            .insert("CF-Connecting-IP", "127.0.0.1".parse().unwrap());
        let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
        let (mut ws_tx, mut ws_rx) = ws.split();

        let challenge_msg = ws_rx.next().await.unwrap().unwrap();
        let Message::Binary(challenge_data) = challenge_msg else {
            panic!("expected binary challenge frame");
        };
        let frame = Frame::parse(&challenge_data).unwrap();
        let Frame::Challenge { challenge, .. } = frame else {
            panic!("expected challenge frame");
        };

        let timestamp = crypto::unix_now().expect("clock error");
        let signature = crypto::sign_admission(keypair, &challenge, timestamp);
        let pubkey: Pubkey = keypair.verifying_key().to_bytes();
        let response = Frame::response(&pubkey, timestamp, &signature);
        ws_tx
            .send(Message::Binary(response.serialize().into()))
            .await
            .unwrap();

        let admit_msg = ws_rx.next().await.unwrap().unwrap();
        let Message::Binary(admit_data) = admit_msg else {
            panic!("expected binary admission frame");
        };
        let admit = Frame::parse(&admit_data).unwrap();
        assert!(
            matches!(admit, Frame::Admitted),
            "expected Admitted, got {admit:?}"
        );

        Self {
            ws_tx,
            ws_rx,
            pubkey,
        }
    }

    pub async fn send_message(&mut self, dest: &Pubkey, payload: &[u8]) {
        let route = Frame::route(dest, payload);
        self.ws_tx
            .send(Message::Binary(route.serialize().into()))
            .await
            .unwrap();
    }

    pub async fn send_ping(&mut self, payload: &[u8]) {
        let ping = Frame::ping(payload);
        self.ws_tx
            .send(Message::Binary(ping.serialize().into()))
            .await
            .unwrap();
    }

    pub async fn recv_frame(&mut self) -> Frame {
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(5), self.ws_rx.next())
                .await
                .expect("timeout waiting for frame")
                .unwrap()
                .unwrap();
            match msg {
                Message::Binary(data) => return Frame::parse(&data).unwrap(),
                Message::Ping(_) | Message::Pong(_) => {}
                other => panic!("expected binary frame, got {other:?}"),
            }
        }
    }

    /// Receive the next Deliver frame, skipping any Status frames.
    /// Useful when DELIVERED acknowledgments are interleaved with deliveries.
    pub async fn recv_deliver(&mut self) -> Frame {
        loop {
            let frame = self.recv_frame().await;
            match &frame {
                Frame::Status { .. } => continue,
                _ => return frame,
            }
        }
    }

    pub async fn recv_frame_timeout(&mut self, timeout: Duration) -> Option<Frame> {
        let result = tokio::time::timeout(timeout, self.recv_frame()).await;
        result.ok()
    }
}

fn make_state(config: ServerConfig) -> Arc<ServerState> {
    let server_keypair = SigningKey::generate(&mut rng());
    let router = Router::new(config.max_conns);
    Arc::new(ServerState {
        router,
        server_keypair,
        config,
        ip_connections: dashmap::DashMap::new(),
        active_connections: std::sync::atomic::AtomicUsize::new(0),
        pre_auth_semaphore: tokio::sync::Semaphore::new(1000),
    })
}

pub async fn start_server() -> (SocketAddr, Arc<ServerState>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = make_state(test_config(addr));

    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(e) = arps::run(listener, state_clone).await {
            eprintln!("server error in test: {e}");
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    (addr, state)
}

pub async fn start_server_with_max_payload(max_payload: usize) -> (SocketAddr, Arc<ServerState>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut config = test_config(addr);
    config.max_payload = max_payload;
    let state = make_state(config);

    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(e) = arps::run(listener, state_clone).await {
            eprintln!("server error in test: {e}");
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    (addr, state)
}

#[allow(dead_code)]
pub async fn start_server_with_pow(pow_difficulty: u8) -> (SocketAddr, Arc<ServerState>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut config = test_config(addr);
    config.pow_difficulty = pow_difficulty;
    let state = make_state(config);

    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(e) = arps::run(listener, state_clone).await {
            eprintln!("server error in test: {e}");
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    (addr, state)
}

impl TestClient {
    /// Connect to a server with PoW enabled, solving the challenge.
    #[allow(dead_code)]
    pub async fn connect_with_pow(addr: &SocketAddr, keypair: &SigningKey) -> Self {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let url = format!("ws://{addr}");
        let mut req = url.into_client_request().unwrap();
        req.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            arp_common::types::PROTOCOL_VERSION.parse().unwrap(),
        );
        req.headers_mut()
            .insert("CF-Connecting-IP", "127.0.0.1".parse().unwrap());
        let (ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
        let (mut ws_tx, mut ws_rx) = ws.split();

        let challenge_msg = ws_rx.next().await.unwrap().unwrap();
        let Message::Binary(challenge_data) = challenge_msg else {
            panic!("expected binary challenge frame");
        };
        let frame = Frame::parse(&challenge_data).unwrap();
        let Frame::Challenge {
            challenge,
            difficulty,
            ..
        } = frame
        else {
            panic!("expected challenge frame");
        };

        let timestamp = crypto::unix_now().expect("clock error");
        let signature = crypto::sign_admission(keypair, &challenge, timestamp);
        let pubkey: Pubkey = keypair.verifying_key().to_bytes();

        let response = if difficulty > 0 {
            let nonce = crypto::pow_solve(&challenge, &pubkey, timestamp, difficulty)
                .expect("PoW solve failed");
            Frame::response_with_pow(&pubkey, timestamp, &signature, nonce)
        } else {
            Frame::response(&pubkey, timestamp, &signature)
        };
        ws_tx
            .send(Message::Binary(response.serialize().into()))
            .await
            .unwrap();

        let admit_msg = ws_rx.next().await.unwrap().unwrap();
        let Message::Binary(admit_data) = admit_msg else {
            panic!("expected binary admission frame");
        };
        let admit = Frame::parse(&admit_data).unwrap();
        assert!(
            matches!(admit, Frame::Admitted),
            "expected Admitted, got {admit:?}"
        );

        Self {
            ws_tx,
            ws_rx,
            pubkey,
        }
    }
}
