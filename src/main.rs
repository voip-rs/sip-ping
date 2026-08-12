//! Ping a SIP server using OPTIONS requests.

use std::fmt;
use std::io::{ErrorKind, Read, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::process;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use socket2::{Domain, Socket, Type};
use tracing::{debug, info};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Any,
    V4,
    V6,
}

impl Family {
    fn of(addr: &SocketAddr) -> Self {
        if addr.is_ipv4() {
            Self::V4
        } else {
            Self::V6
        }
    }

    fn accepts(self, addr: &SocketAddr) -> bool {
        self == Self::Any || self == Self::of(addr)
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Any => "IP",
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        })
    }
}

/// Local endpoint to bind before connecting.
struct Source {
    ip: Option<IpAddr>,
    port: u16,
}

impl Source {
    fn local_for(&self, remote: &SocketAddr) -> SocketAddr {
        let ip = self
            .ip
            .unwrap_or(match Family::of(remote) {
                Family::V4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                _ => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            });
        SocketAddr::new(ip, self.port)
    }
}

struct Target {
    /// Resolvable `host:port`, port defaulted from the transport.
    addr: String,
    /// Host exactly as given, used in the SIP URIs.
    host: String,
    family: Family,
    source: Source,
    timeout: Duration,
    skip_verify: bool,
}

/// Ping a SIP server using OPTIONS requests
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Target SIP server, host or host:port
    host: String,

    /// Transport protocol
    #[arg(short = 't', long, value_enum, default_value_t = Protocol::Udp)]
    protocol: Protocol,

    /// Source address to bind
    #[arg(short = 's', long, value_name = "ADDR")]
    source: Option<IpAddr>,

    /// Source port to bind
    #[arg(short = 'p', long, value_name = "PORT", default_value_t = 0)]
    source_port: u16,

    /// Connect and read timeout, in seconds
    #[arg(
        short = 'w',
        long,
        value_name = "SECS",
        default_value_t = 5,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    timeout: u64,

    /// Use IPv4 only
    #[arg(short = '4', conflicts_with = "ipv6")]
    ipv4: bool,

    /// Use IPv6 only
    #[arg(short = '6')]
    ipv6: bool,

    /// Skip TLS certificate verification
    #[arg(long)]
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

/// A bound source address pins the family; `-4`/`-6` may only agree with it.
fn address_family(ipv4: bool, ipv6: bool, source: Option<IpAddr>) -> Result<Family> {
    let requested = match (ipv4, ipv6) {
        (true, _) => Family::V4,
        (_, true) => Family::V6,
        _ => Family::Any,
    };
    let Some(ip) = source else {
        return Ok(requested);
    };
    let bound = if ip.is_ipv4() { Family::V4 } else { Family::V6 };
    if requested != Family::Any && requested != bound {
        bail!("source address {ip} is not {requested}");
    }
    Ok(bound)
}

fn resolve(addr: &str, family: Family) -> Result<Vec<SocketAddr>> {
    let all: Vec<_> = addr
        .to_socket_addrs()
        .with_context(|| format!("resolving {addr}"))?
        .collect();
    if all.is_empty() {
        bail!("no addresses for {addr}");
    }
    let matching: Vec<_> = all
        .into_iter()
        .filter(|sa| family.accepts(sa))
        .collect();
    if matching.is_empty() {
        bail!("no {family} addresses for {addr}");
    }
    Ok(matching)
}

fn first_reachable<T>(
    target: &Target,
    mut connect: impl FnMut(&SocketAddr) -> std::io::Result<T>,
) -> Result<T> {
    let addrs = resolve(&target.addr, target.family)?;
    let mut last_err = None;
    for sa in &addrs {
        info!("connecting to {sa}");
        match connect(sa) {
            Ok(connected) => return Ok(connected),
            Err(e) => {
                info!("connect failed: {e}");
                last_err = Some(e);
            }
        }
    }
    // `resolve` rejects an empty list, so the loop ran at least once.
    Err(anyhow!(last_err.expect("no address was tried")))
}

fn connect_udp(target: &Target) -> Result<UdpSocket> {
    let socket = first_reachable(target, |sa| {
        let local = target
            .source
            .local_for(sa);
        debug!("binding {local}");
        let socket = UdpSocket::bind(local)?;
        socket.connect(sa)?;
        Ok(socket)
    })
    .context("connecting")?;
    socket.set_read_timeout(Some(target.timeout))?;
    Ok(socket)
}

fn connect_tcp(target: &Target) -> Result<TcpStream> {
    let stream: TcpStream = first_reachable(target, |sa| {
        let local = target
            .source
            .local_for(sa);
        debug!("binding {local}");
        let socket = Socket::new(
            Domain::for_address(*sa),
            Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        socket.bind(&local.into())?;
        socket.connect_timeout(&(*sa).into(), target.timeout)?;
        Ok(socket.into())
    })
    .context("connecting")?;
    stream.set_read_timeout(Some(target.timeout))?;
    Ok(stream)
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

/// A read timeout reaches us as `WouldBlock` on a blocking socket, which reads
/// as `EAGAIN` and tells nobody what actually happened.
fn read_error(e: std::io::Error, timeout: Duration) -> anyhow::Error {
    match e.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => {
            anyhow!("no response within {}s", timeout.as_secs())
        }
        _ => anyhow!(e),
    }
}

fn read_sip_response(stream: &mut impl Read, timeout: Duration) -> Result<String> {
    let mut buf = vec![0u8; MAX_RESPONSE];
    let mut total = 0;
    loop {
        if total >= MAX_RESPONSE {
            bail!("response too large");
        }
        let n = stream
            .read(&mut buf[total..])
            .map_err(|e| read_error(e, timeout))
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

fn ping_udp(target: &Target) -> Result<(String, Duration)> {
    let socket = connect_udp(target)?;
    let local = socket
        .local_addr()?
        .to_string();
    let request = build_sip_options(Protocol::Udp, &local, &target.host);
    debug!("SIP request:\n{request}");

    let start = Instant::now();
    socket
        .send(request.as_bytes())
        .context("sending")?;

    let mut buf = vec![0u8; MAX_RESPONSE];
    let n = socket
        .recv(&mut buf)
        .map_err(|e| read_error(e, target.timeout))
        .context("receiving")?;
    let elapsed = start.elapsed();

    let response = String::from_utf8_lossy(&buf[..n]).into_owned();
    debug!("SIP response:\n{response}");
    Ok((response, elapsed))
}

fn ping_tcp(target: &Target) -> Result<(String, Duration)> {
    let mut stream = connect_tcp(target)?;
    let local = stream
        .local_addr()?
        .to_string();
    let request = build_sip_options(Protocol::Tcp, &local, &target.host);
    debug!("SIP request:\n{request}");

    let start = Instant::now();
    stream
        .write_all(request.as_bytes())
        .context("sending")?;
    let response = read_sip_response(&mut stream, target.timeout)?;
    let elapsed = start.elapsed();

    debug!("SIP response:\n{response}");
    Ok((response, elapsed))
}

fn ping_tls(target: &Target) -> Result<(String, Duration)> {
    let tcp = connect_tcp(target)?;
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(target.skip_verify)
        .build()
        .context("building TLS connector")?;

    let host = &target.host;
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
    let request = build_sip_options(Protocol::Tls, &local, &target.host);
    debug!("SIP request:\n{request}");

    let start = Instant::now();
    stream
        .write_all(request.as_bytes())
        .context("sending")?;
    let response = read_sip_response(&mut stream, target.timeout)?;
    let elapsed = start.elapsed();

    debug!("SIP response:\n{response}");
    Ok((response, elapsed))
}

/// A read timeout surfaces as `Interrupted` rather than an error, so the
/// handshake is resumed until it completes or the timeout is spent.
fn ws_handshake(
    request: tungstenite::ClientRequestBuilder,
    tcp: TcpStream,
    timeout: Duration,
) -> Result<tungstenite::WebSocket<TcpStream>> {
    use tungstenite::HandshakeError;

    let deadline = Instant::now() + timeout;
    let mut attempt = tungstenite::client::client(request, tcp);
    loop {
        match attempt {
            Ok((ws, _)) => return Ok(ws),
            Err(HandshakeError::Failure(e)) => return Err(anyhow!(e)),
            Err(HandshakeError::Interrupted(mid)) => {
                if Instant::now() >= deadline {
                    bail!("no response within {}s", timeout.as_secs());
                }
                attempt = mid.handshake();
            }
        }
    }
}

fn ping_ws(target: &Target) -> Result<(String, Duration)> {
    use tungstenite::{ClientRequestBuilder, Message};

    let tcp = connect_tcp(target)?;
    let uri: tungstenite::http::Uri = format!("ws://{}", target.addr)
        .parse()
        .context("parsing WS URI")?;
    let request = ClientRequestBuilder::new(uri).with_sub_protocol("sip");

    let mut ws = ws_handshake(request, tcp, target.timeout).context("WebSocket connect")?;

    let sip_request = build_sip_options(Protocol::Ws, "", &target.host);
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

fn run(args: &Args) -> Result<(String, Duration)> {
    let target = Target {
        addr: ensure_port(
            &args.host,
            args.protocol
                .default_port(),
        ),
        host: args
            .host
            .clone(),
        family: address_family(args.ipv4, args.ipv6, args.source)?,
        source: Source {
            ip: args.source,
            port: args.source_port,
        },
        timeout: Duration::from_secs(args.timeout),
        skip_verify: args.skip_verify,
    };
    info!(
        "pinging {} via {}",
        target.addr,
        args.protocol
            .sip_transport()
    );

    match args.protocol {
        Protocol::Udp => ping_udp(&target),
        Protocol::Tcp => ping_tcp(&target),
        Protocol::Tls => ping_tls(&target),
        Protocol::Ws => ping_ws(&target),
    }
}

fn main() {
    let args = Args::parse();
    init_tracing(args.verbose);

    match run(&args) {
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
