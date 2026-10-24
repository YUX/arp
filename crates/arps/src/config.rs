use clap::Parser;
use ipnet::IpNet;
use std::net::SocketAddr;
use std::path::PathBuf;

/// CLI arguments for the relay server.
#[derive(Parser, Debug, Clone)]
#[command(name = "arps")]
#[command(about = "ARP relay server")]
#[command(version)]
pub struct Args {
    /// Socket address to listen on.
    #[arg(long, default_value = "0.0.0.0:8080", env = "ARPS_LISTEN")]
    pub listen: SocketAddr,
    /// Socket address for the metrics endpoint.
    #[arg(long, default_value = "127.0.0.1:9090", env = "ARPS_METRICS")]
    pub metrics_addr: SocketAddr,
    /// Maximum total concurrent connections.
    #[arg(long, default_value = "100000", env = "ARPS_MAX_CONNS")]
    pub max_conns: usize,
    /// Maximum concurrent connections per IP address.
    #[arg(long, default_value = "10", env = "ARPS_MAX_CONNS_IP")]
    pub max_conns_ip: usize,
    /// Maximum messages per minute per connection.
    #[arg(long, default_value = "120", env = "ARPS_MSG_RATE")]
    pub msg_rate: u32,
    /// Maximum bytes per minute per connection.
    #[arg(long, default_value = "1048576", env = "ARPS_BW_RATE")]
    pub bw_rate: u64,
    /// Maximum WebSocket payload size in bytes.
    #[arg(long, default_value = "65535", env = "ARPS_MAX_PAYLOAD")]
    pub max_payload: usize,
    /// Path to the server Ed25519 keypair file.
    #[arg(long, env = "ARPS_KEYPAIR")]
    pub keypair: Option<PathBuf>,
    /// Admission handshake timeout in seconds.
    #[arg(long, default_value = "5", env = "ARPS_ADMIT_TIMEOUT")]
    pub admit_timeout: u64,
    /// Interval between WebSocket pings in seconds.
    #[arg(long, default_value = "30", env = "ARPS_PING_INTERVAL")]
    pub ping_interval: u64,
    /// Connection idle timeout in seconds.
    #[arg(long, default_value = "120", env = "ARPS_IDLE_TIMEOUT")]
    pub idle_timeout: u64,
    /// Proof-of-work difficulty (leading zero bits). 0 = disabled.
    #[arg(long, default_value = "16", env = "ARPS_POW_DIFFICULTY")]
    pub pow_difficulty: u8,
    /// Trusted reverse-proxy CIDR ranges. Forwarded-IP headers (CF-Connecting-IP,
    /// X-Forwarded-For) are only honoured when the TCP peer address falls within
    /// one of these ranges. Without this, peer_addr is used directly.
    #[arg(long, value_delimiter = ',', env = "ARPS_TRUSTED_PROXY_CIDRS")]
    pub trusted_proxy_cidrs: Vec<IpNet>,
    /// Check for and apply updates instead of starting the server.
    #[arg(long)]
    pub update: bool,
    /// Only check if an update is available, don't download.
    #[arg(long)]
    pub check_update: bool,
    /// URL to redirect plain-HTTP visitors to. If unset, a neutral landing page is shown.
    #[arg(long, env = "ARPS_REDIRECT_URL")]
    pub redirect_url: Option<String>,
    /// Maximum pre-authentication connections (DoS protection).
    #[arg(long, default_value = "1000", env = "ARPS_PRE_AUTH_LIMIT")]
    pub pre_auth_limit: usize,
}

/// Runtime configuration derived from [`Args`].
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Socket address to listen on.
    pub listen: SocketAddr,
    /// Socket address for the metrics endpoint.
    pub metrics_addr: SocketAddr,
    /// Maximum total concurrent connections.
    pub max_conns: usize,
    /// Maximum concurrent connections per IP address.
    pub max_conns_ip: usize,
    /// Maximum messages per minute per connection.
    pub msg_rate: u32,
    /// Maximum bytes per minute per connection.
    pub bw_rate: u64,
    /// Maximum WebSocket payload size in bytes.
    pub max_payload: usize,
    /// Admission handshake timeout in seconds.
    pub admit_timeout: u64,
    /// Interval between WebSocket pings in seconds.
    pub ping_interval: u64,
    /// Connection idle timeout in seconds.
    pub idle_timeout: u64,
    /// Proof-of-work difficulty (leading zero bits). 0 = disabled.
    pub pow_difficulty: u8,
    /// Parsed trusted proxy CIDR ranges for forwarded-IP header extraction.
    pub trusted_proxy_cidrs: Vec<IpNet>,
    /// URL to redirect plain-HTTP visitors to. `None` = show a neutral landing page.
    pub redirect_url: Option<String>,
    /// Maximum pre-authentication connections (DoS protection).
    pub pre_auth_limit: usize,
}

impl ServerConfig {
    /// Validates the configuration values are within acceptable bounds.
    /// Returns Ok(()) if valid, Err with description otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use arps::config::ServerConfig;
    /// use std::net::SocketAddr;
    ///
    /// let config = ServerConfig {
    ///     listen: "0.0.0.0:8080".parse().unwrap(),
    ///     metrics_addr: "127.0.0.1:9090".parse().unwrap(),
    ///     max_conns: 100_000,
    ///     max_conns_ip: 10,
    ///     msg_rate: 120,
    ///     bw_rate: 1_048_576,
    ///     max_payload: 65_535,
    ///     admit_timeout: 5,
    ///     ping_interval: 30,
    ///     idle_timeout: 120,
    ///     pow_difficulty: 16,
    ///     trusted_proxy_cidrs: vec![],
    ///     redirect_url: None,
    ///     pre_auth_limit: 1000,
    /// };
    /// assert!(config.validate().is_ok());
    /// ```
    pub fn validate(&self) -> Result<(), String> {
        // Pre-auth connection limit
        if self.pre_auth_limit == 0 {
            return Err("pre_auth_limit must be greater than 0".to_string());
        }
        if self.pre_auth_limit > 100_000 {
            return Err("pre_auth_limit exceeds reasonable limit (100,000)".to_string());
        }

        // Max connections must be reasonable
        // Max connections must be reasonable
        if self.max_conns == 0 {
            return Err("max_conns must be greater than 0".to_string());
        }
        if self.max_conns > 1_000_000 {
            return Err("max_conns exceeds reasonable limit (1,000,000)".to_string());
        }

        // Per-IP connection limits
        if self.max_conns_ip == 0 {
            return Err("max_conns_ip must be greater than 0".to_string());
        }
        if self.max_conns_ip > self.max_conns {
            return Err("max_conns_ip cannot exceed max_conns".to_string());
        }

        // Rate limits
        if self.msg_rate == 0 {
            return Err("msg_rate must be greater than 0".to_string());
        }
        if self.msg_rate > 1000 {
            return Err("msg_rate exceeds sliding window capacity (1000 msg/min). \
                 The rate limiter tracks individual messages in a bounded window; \
                 values above 1000 are silently unenforced."
                .to_string());
        }

        if self.bw_rate == 0 {
            return Err("bw_rate must be greater than 0".to_string());
        }
        if self.bw_rate > 100_000_000_000 {
            return Err("bw_rate exceeds reasonable limit (100 GB/min)".to_string());
        }

        // Payload size - must not exceed frame parsing limits
        const MAX_ALLOWED_PAYLOAD: usize = 65_535;
        if self.max_payload == 0 {
            return Err("max_payload must be greater than 0".to_string());
        }
        if self.max_payload > MAX_ALLOWED_PAYLOAD {
            return Err(format!(
                "max_payload exceeds maximum allowed ({} bytes)",
                MAX_ALLOWED_PAYLOAD
            ));
        }

        // Timeouts
        if self.admit_timeout == 0 {
            return Err("admit_timeout must be greater than 0".to_string());
        }
        if self.admit_timeout > 300 {
            return Err("admit_timeout exceeds reasonable limit (300 seconds)".to_string());
        }

        if self.ping_interval == 0 {
            return Err("ping_interval must be greater than 0".to_string());
        }
        if self.ping_interval > 3600 {
            return Err("ping_interval exceeds reasonable limit (3600 seconds)".to_string());
        }

        if self.idle_timeout == 0 {
            return Err("idle_timeout must be greater than 0".to_string());
        }
        if self.idle_timeout > 86_400 {
            return Err(
                "idle_timeout exceeds reasonable limit (86400 seconds / 1 day)".to_string(),
            );
        }

        // PoW difficulty — capped at MAX_CLIENT_POW_DIFFICULTY (24) to prevent
        // admission timeouts; clients cap their PoW search at 2^24 iterations.
        if self.pow_difficulty > 24 {
            return Err(
                "pow_difficulty exceeds MAX_CLIENT_POW_DIFFICULTY (24 leading zero bits); \
                 clients cap PoW search at 2^24 iterations so higher values cause admission timeout"
                    .to_string(),
            );
        }

        // Redirect URL — must use http:// or https:// to prevent open-redirect abuse
        if let Some(ref url) = self.redirect_url
            && !url.starts_with("http://")
            && !url.starts_with("https://")
        {
            return Err("redirect_url must use http:// or https:// scheme".to_string());
        }
        Ok(())
    }
}

impl From<Args> for ServerConfig {
    fn from(args: Args) -> Self {
        Self {
            listen: args.listen,
            metrics_addr: args.metrics_addr,
            max_conns: args.max_conns,
            max_conns_ip: args.max_conns_ip,
            msg_rate: args.msg_rate,
            bw_rate: args.bw_rate,
            max_payload: args.max_payload,
            admit_timeout: args.admit_timeout,
            ping_interval: args.ping_interval,
            idle_timeout: args.idle_timeout,
            pow_difficulty: args.pow_difficulty,
            trusted_proxy_cidrs: args.trusted_proxy_cidrs,
            redirect_url: args.redirect_url,
            pre_auth_limit: args.pre_auth_limit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> ServerConfig {
        ServerConfig {
            listen: "127.0.0.1:8080".parse().unwrap(),
            metrics_addr: "127.0.0.1:9090".parse().unwrap(),
            max_conns: 1000,
            max_conns_ip: 10,
            msg_rate: 120,
            bw_rate: 1_048_576,
            max_payload: 65535,
            admit_timeout: 5,
            ping_interval: 30,
            idle_timeout: 120,
            pow_difficulty: 0,
            trusted_proxy_cidrs: vec![],
            redirect_url: None,
            pre_auth_limit: 1000,
        }
    }

    #[test]
    fn valid_config_passes() {
        assert!(valid_config().validate().is_ok());
    }

    #[test]
    fn max_conns_zero() {
        let mut c = valid_config();
        c.max_conns = 0;
        assert!(c.validate().unwrap_err().contains("max_conns"));
    }

    #[test]
    fn max_conns_too_large() {
        let mut c = valid_config();
        c.max_conns = 1_000_001;
        assert!(c.validate().unwrap_err().contains("max_conns"));
    }

    #[test]
    fn max_conns_ip_zero() {
        let mut c = valid_config();
        c.max_conns_ip = 0;
        assert!(c.validate().unwrap_err().contains("max_conns_ip"));
    }

    #[test]
    fn max_conns_ip_exceeds_max_conns() {
        let mut c = valid_config();
        c.max_conns_ip = c.max_conns + 1;
        assert!(c.validate().unwrap_err().contains("max_conns_ip"));
    }

    #[test]
    fn msg_rate_zero() {
        let mut c = valid_config();
        c.msg_rate = 0;
        assert!(c.validate().unwrap_err().contains("msg_rate"));
    }

    #[test]
    fn msg_rate_too_large() {
        let mut c = valid_config();
        c.msg_rate = 1_000_001;
        assert!(c.validate().unwrap_err().contains("msg_rate"));
    }

    #[test]
    fn bw_rate_zero() {
        let mut c = valid_config();
        c.bw_rate = 0;
        assert!(c.validate().unwrap_err().contains("bw_rate"));
    }

    #[test]
    fn bw_rate_too_large() {
        let mut c = valid_config();
        c.bw_rate = 100_000_000_001;
        assert!(c.validate().unwrap_err().contains("bw_rate"));
    }

    #[test]
    fn max_payload_zero() {
        let mut c = valid_config();
        c.max_payload = 0;
        assert!(c.validate().unwrap_err().contains("max_payload"));
    }

    #[test]
    fn max_payload_too_large() {
        let mut c = valid_config();
        c.max_payload = 65_536;
        assert!(c.validate().unwrap_err().contains("max_payload"));
    }

    #[test]
    fn admit_timeout_zero() {
        let mut c = valid_config();
        c.admit_timeout = 0;
        assert!(c.validate().unwrap_err().contains("admit_timeout"));
    }

    #[test]
    fn admit_timeout_too_large() {
        let mut c = valid_config();
        c.admit_timeout = 301;
        assert!(c.validate().unwrap_err().contains("admit_timeout"));
    }

    #[test]
    fn ping_interval_zero() {
        let mut c = valid_config();
        c.ping_interval = 0;
        assert!(c.validate().unwrap_err().contains("ping_interval"));
    }

    #[test]
    fn ping_interval_too_large() {
        let mut c = valid_config();
        c.ping_interval = 3601;
        assert!(c.validate().unwrap_err().contains("ping_interval"));
    }

    #[test]
    fn idle_timeout_zero() {
        let mut c = valid_config();
        c.idle_timeout = 0;
        assert!(c.validate().unwrap_err().contains("idle_timeout"));
    }

    #[test]
    fn idle_timeout_too_large() {
        let mut c = valid_config();
        c.idle_timeout = 86_401;
        assert!(c.validate().unwrap_err().contains("idle_timeout"));
    }

    #[test]
    fn boundary_values_valid() {
        // Test boundary values that should pass
        let mut c = valid_config();
        c.max_conns = 1;
        c.max_conns_ip = 1;
        c.msg_rate = 1;
        c.bw_rate = 1;
        c.max_payload = 1;
        c.admit_timeout = 1;
        c.ping_interval = 1;
        c.idle_timeout = 1;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn upper_boundary_values_valid() {
        let mut c = valid_config();
        c.max_conns = 1_000_000;
        c.max_conns_ip = 1_000_000;
        c.msg_rate = 1_000;
        c.bw_rate = 100_000_000_000;
        c.max_payload = 65_535;
        c.admit_timeout = 300;
        c.ping_interval = 3600;
        c.idle_timeout = 86_400;
        assert!(c.validate().is_ok());
    }
}
