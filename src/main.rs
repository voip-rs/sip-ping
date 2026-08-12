//! Ping a SIP server using OPTIONS requests.

use std::fmt;
use std::io::{Read, Write as _};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::process;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use tracing::{debug, info};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE: usize = 65536;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum Protocol {
    Udp,
    Tcp,
    Tls,
    Ws,
}

impl Protocol {
    fn default_port(self) -> u16 {
        match self {
            Self::Udp | Self::Tcp => 5060,
            Self::Tls => 5061,
            Self::Ws => 80,
        }
    }

    fn sip_transport(self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Tls => "TLS",
            Self::Ws => "WS",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::Ws => "ws",
        })
    }
}

/// Ping a SIP server using OPTIONS requests
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Target SIP server, host or host:port
    host: String,

    /// Transport protocol
    #[arg(short, long, value_enum, default_value_t = Protocol::Udp)]
    protocol: Protocol,

    /// Skip TLS certificate verification
    #[arg(short, long)]
    skip_verify: bool,

    /// Increase verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn init_tracing(verbose: u8) {
    use tracing_subscriber::EnvFilter;

    let level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level)),
        )
        .with_target(false)
        .without_time()
        .init();
}

fn random_alnum(len: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..len)
        .map(|_| CHARSET[fastrand::usize(..CHARSET.len())] as char)
        .collect()
}

fn ensure_port(host: &str, default_port: u16) -> String {
    if host.starts_with('[') {
        if host.contains("]:") {
            return host.to_string();
        }
        return format!("{host}:{default_port}");
    }
    if host.contains("::") {
        return format!("[{host}]:{default_port}");
    }
    if host.contains(':') {
        return host.to_string();
    }
    format!("{host}:{default_port}")
}

fn resolve(addr: &str) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<_> = addr
        .to_socket_addrs()
        .with_context(|| format!("resolving {addr}"))?
        .collect();
    if addrs.is_empty() {
        bail!("no addresses for {addr}");
    }
    Ok(addrs)
}

fn connect_tcp(addr: &str) -> Result<TcpStream> {
    let addrs = resolve(addr)?;
    let mut last_err = None;
    for sa in &addrs {
        info!("connecting to {sa}");
        match TcpStream::connect_timeout(sa, CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream.set_read_timeout(Some(READ_TIMEOUT))?;
                return Ok(stream);
            }
            Err(e) => {
                info!("connect failed: {e}");
                last_err = Some(e);
            }
        }
    }
    Err(last_err
        .unwrap_or_else(|| std::io::Error::other("no addresses"))
        .into())
}

fn build_sip_options(protocol: Protocol, local_addr: &str, host: &str) -> String {
    let call_id = random_alnum(20);
    let branch = random_alnum(12);
    let tag = random_alnum(8);
    let seq = fastrand::u16(1..);
    let transport = protocol.sip_transport();
    let transport_lower = transport.to_lowercase();

    match protocol {
        Protocol::Ws => {
            let via_host = format!("{}.invalid", random_alnum(12));
            format!(
                "OPTIONS sip:ping@invalid SIP/2.0\r\n\
                 Via: SIP/2.0/{transport} {via_host};branch=z9hG4bK{branch}\r\n\
                 Max-Forwards: 70\r\n\
                 From: <sip:sip-ping@anonymous.invalid>;tag={tag}\r\n\
                 To: <sip:ping@invalid>\r\n\
                 Call-ID: {call_id}\r\n\
                 CSeq: {seq} OPTIONS\r\n\
                 Content-Length: 0\r\n\
                 \r\n"
            )
        }
        _ => format!(
            "OPTIONS sip:ping@{host};transport={transport_lower} SIP/2.0\r\n\
             Via: SIP/2.0/{transport} {local_addr};branch=z9hG4bK{branch}\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:sip-ping@invalid>;tag={tag}\r\n\
             To: <sip:ping@{host};transport={transport_lower}>\r\n\
             Call-ID: {call_id}\r\n\
             CSeq: {seq} OPTIONS\r\n\
             Content-Length: 0\r\n\
             \r\n"
        ),
    }
}

fn read_sip_response(stream: &mut impl Read) -> Result<String> {
    let mut buf = vec![0u8; MAX_RESPONSE];
    let mut total = 0;
    loop {
        if total >= MAX_RESPONSE {
            bail!("response too large");
        }
        let n = stream
            .read(&mut buf[total..])
            .context("reading response")?;
        if n == 0 {
            break;
        }
        total += n;
        if buf[..total]
            .windows(4)
            .any(|w| w == b"\r\n\r\n")
        {
            break;
        }
    }
    if total == 0 {
        bail!("empty response");
    }
    Ok(String::from_utf8_lossy(&buf[..total]).into_owned())
}

fn status_line(response: &str) -> &str {
    response
        .lines()
        .next()
        .unwrap_or("")
        .trim()
}

fn ping_udp(addr: &str, host: &str) -> Result<(String, Duration)> {
    let socket = UdpSocket::bind("[::]:0")
        .or_else(|_| UdpSocket::bind("0.0.0.0:0"))
        .context("binding UDP socket")?;
    socket.set_read_timeout(Some(READ_TIMEOUT))?;
    socket
        .connect(addr)
        .context("connecting")?;

    let local = socket
        .local_addr()?
        .to_string();
    let request = build_sip_options(Protocol::Udp, &local, host);
    debug!("SIP request:\n{request}");

    let start = Instant::now();
    socket
        .send(request.as_bytes())
        .context("sending")?;

    let mut buf = vec![0u8; MAX_RESPONSE];
    let n = socket
        .recv(&mut buf)
        .context("receiving")?;
    let elapsed = start.elapsed();

    let response = String::from_utf8_lossy(&buf[..n]).into_owned();
    debug!("SIP response:\n{response}");
    Ok((response, elapsed))
}

fn ping_tcp(addr: &str, host: &str) -> Result<(String, Duration)> {
    let mut stream = connect_tcp(addr)?;
    let local = stream
        .local_addr()?
        .to_string();
    let request = build_sip_options(Protocol::Tcp, &local, host);
    debug!("SIP request:\n{request}");

    let start = Instant::now();
    stream
        .write_all(request.as_bytes())
        .context("sending")?;
    let response = read_sip_response(&mut stream)?;
    let elapsed = start.elapsed();

    debug!("SIP response:\n{response}");
    Ok((response, elapsed))
}

fn ping_tls(addr: &str, host: &str, skip_verify: bool) -> Result<(String, Duration)> {
    let tcp = connect_tcp(addr)?;
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(skip_verify)
        .build()
        .context("building TLS connector")?;

    let sni_host = if host.starts_with('[') {
        host.split(']')
            .next()
            .unwrap_or(host)
            .trim_start_matches('[')
    } else {
        host.split(':')
            .next()
            .unwrap_or(host)
    };
    let mut stream = connector
        .connect(sni_host, tcp)
        .context("TLS handshake")?;

    let local = stream
        .get_ref()
        .local_addr()?
        .to_string();
    let request = build_sip_options(Protocol::Tls, &local, host);
    debug!("SIP request:\n{request}");

    let start = Instant::now();
    stream
        .write_all(request.as_bytes())
        .context("sending")?;
    let response = read_sip_response(&mut stream)?;
    let elapsed = start.elapsed();

    debug!("SIP response:\n{response}");
    Ok((response, elapsed))
}

fn ping_ws(addr: &str, host: &str) -> Result<(String, Duration)> {
    use tungstenite::{ClientRequestBuilder, Message};

    let uri: tungstenite::http::Uri = format!("ws://{addr}")
        .parse()
        .context("parsing WS URI")?;
    let request = ClientRequestBuilder::new(uri).with_sub_protocol("sip");

    let (mut ws, _) = tungstenite::connect(request).context("WebSocket connect")?;

    let sip_request = build_sip_options(Protocol::Ws, "", host);
    debug!("SIP request:\n{sip_request}");

    let start = Instant::now();
    ws.send(Message::Text(sip_request))
        .context("sending")?;

    let response = loop {
        match ws
            .read()
            .context("reading WebSocket")?
        {
            Message::Text(text) => {
                break text.replace("\\r\\n", "\r\n");
            }
            Message::Close(_) => bail!("WebSocket closed"),
            _ => {}
        }
    };
    let elapsed = start.elapsed();

    debug!("SIP response:\n{response}");
    Ok((response, elapsed))
}

fn main() {
    let args = Args::parse();
    init_tracing(args.verbose);

    let addr = ensure_port(
        &args.host,
        args.protocol
            .default_port(),
    );
    info!(
        "pinging {addr} via {}",
        args.protocol
            .sip_transport()
    );

    let result = match args.protocol {
        Protocol::Udp => ping_udp(&addr, &args.host),
        Protocol::Tcp => ping_tcp(&addr, &args.host),
        Protocol::Tls => ping_tls(&addr, &args.host, args.skip_verify),
        Protocol::Ws => ping_ws(&addr, &args.host),
    };

    match result {
        Ok((response, elapsed)) => {
            let status = status_line(&response);
            let ms = elapsed.as_secs_f64() * 1000.0;
            println!("{}: {status} time={ms:.2}ms", args.host);
            if !status.starts_with("SIP/2.0 200 ") {
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("{}: {e:#}", args.host);
            process::exit(1);
        }
    }
}
