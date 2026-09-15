use igd::{search_gateway, PortMappingProtocol, SearchOptions};
use libc;
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, Type};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};
use std::thread;
use tungstenite::{accept, WebSocket};
//use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use enum_dispatch::enum_dispatch;
use env_logger::fmt::TimestampPrecision;
use hex;
use log::{debug, error, info, log_enabled, trace, warn, Level};
use memmap2::{Mmap, MmapMut, MmapOptions};
use mmap_bitvec::{BitVector, MmapBitVec};
use serde_with::hex::Hex;
use std::net::IpAddr;
//use nix::NixPath;
use blake3::hazmat::{merge_subtrees_non_root, merge_subtrees_root, HasherExt, Mode};
use blake3::Hasher as Blake3Hasher;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use serde_with::{base64::Base64, serde_as, InspectError, VecSkipError};
use sha2::{Digest, Sha256, Sha512};
use snow::Builder;
//use std::cmp;
use std::collections::{HashMap, HashSet};
//use std::collections::{VecDeque};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
//use std::convert::TryInto;
use std::env;
use std::os::unix::process::CommandExt;
//use std::fmt;
use std::f64;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
//use std::io::copy;
use nix::sys::select::{select, FdSet};
use rand::seq::IteratorRandom;
use rand::Rng;
use scanf::sscanf;
use std::io::IsTerminal;
use std::net::{SocketAddr, UdpSocket};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::time::{Duration, Instant};
use std::vec;
use std::{io, str};
//use base64::{engine::general_purpose, Engine as _};
//use nix::NixPath;
use schemars::{schema_for, JsonSchema};
use std::path::Path;
//use std::convert::TryInto;
//use std::fmt;
//use std::io::copy;

const NOISE_PARAMS: &str = "Noise_IK_25519_AESGCM_SHA256";
const SPECIAL_PUB: &str = "e13a614dff88de239a986bea20ca129c3dc77bb727fac18f2f092eed27cfb3fb";
const ACTIVE_PEER_DELAY_MS: u64 = 1500;

static SAVED_TERMIOS: std::sync::OnceLock<libc::termios> = std::sync::OnceLock::new();

fn restore_terminal() {
    if let Some(t) = SAVED_TERMIOS.get() {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, t);
        }
    }
}
const HELP_TEXT: &str = "
                        - /ping
                        - /get < sha256 or blake3/blake3_hash >
                        - /addpeer 1.2.3.4:5678
                        - /save  (because an on-exit handler looks hard, but it saves on a timer anynay so don't worry about it)
                        - /quit -- calls /save then exits
                        - /list
                        - /recommend hash
                        - /recommended
                        - /trending
                        - /pending
                        - /websockets
                        - /peers
                        - /msg [ip:port or 0xPubKey] msg
                        - /g [#group_name] msg  (group chat; omit #group_name to use last or default 'main')
                        - /version
                        - /publish path  (copy file to cjp2p/origin/ and print its URL)
                        - /share path  (serve file by SHA-256 and Blake3 hash from cjp2p/public/)
                        - /update  (auto-detects local build vs release binary)
                        - /help (this help)
                        - default action is /g #main
                ";

#[serde_as]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize)]
struct Ed25519Pub(#[serde_as(as = "Hex")] [u8; 32]);
impl Ed25519Pub {
    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    fn is_valid_edwards_point(&self) -> bool {
        use curve25519_dalek::edwards::CompressedEdwardsY;
        CompressedEdwardsY(self.0).decompress().is_some()
    }
}
impl<'de> serde::Deserialize<'de> for Ed25519Pub {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<Ed25519Pub>().map_err(serde::de::Error::custom)
    }
}
impl std::fmt::Display for Ed25519Pub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
impl std::fmt::Debug for Ed25519Pub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ed25519Pub({})", hex::encode(self.0))
    }
}
impl std::str::FromStr for Ed25519Pub {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "expected 32 bytes".to_string())?;
        let p = Self(arr);
        if !p.is_valid_edwards_point() {
            warn!("rejecting Ed25519Pub {} -- not a valid Edwards point", s);
            return Err(format!("invalid Edwards point: {}", s));
        }
        Ok(p)
    }
}
impl JsonSchema for Ed25519Pub {
    fn schema_name() -> String {
        "Ed25519Pub".to_owned()
    }
    fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            string: Some(Box::new(schemars::schema::StringValidation {
                pattern: Some("^[0-9a-f]{64}$".to_owned()),
                ..Default::default()
            })),
            ..Default::default()
        }
        .into()
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, Eq, PartialEq, Hash)]
enum Source {
    // <'a> {
    None, // W(&'a WebSocket<TcpStream>), // borrow checker, this really has to be the index, or taken out of peerstate, or maybe just pass the IP/port of the websocket instead of an index, make that the index
    S(SocketAddr),
}

macro_rules! BLOCK_SIZE {
    () => {
        // must be a multiple of 1024 or BLAKE3 stuff breaks
        0x1000 // 4k
    };
}

// when this gets to millions of peers, consider keeping less info about the slower ones
#[derive(Clone, Serialize, Deserialize, Debug)]
struct PeerInfo {
    delay: Duration,
    anti_ip_spoofing_cookie_they_expect: Option<String>,
    ed25519: Option<Ed25519Pub>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ed25519_eth_signed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ed25519_eth_signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    you_should_see_this: Option<YouShouldSeeThis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    i_just_saw_this: Option<IJustSawThis>,
}
impl PeerInfo {
    fn new() -> Self {
        return Self {
            delay: Duration::from_millis(200),
            anti_ip_spoofing_cookie_they_expect: None,
            ed25519: None,
            ed25519_eth_signed: None,
            ed25519_eth_signer: None,
            you_should_see_this: None,
            i_just_saw_this: None,
        };
    }
}
#[derive(Debug)]
struct OpenFile {
    file: File,
    eof: usize,
}
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct Keypair {
    public: Ed25519Pub,
    #[serde_as(as = "Hex")]
    private: [u8; 32],
}
impl Keypair {
    fn load_key() -> Self {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open("./cjp2p/state/key.v2.json");
        if file.as_ref().is_ok() && file.as_ref().unwrap().metadata().unwrap().len() > 0 {
            let f = file.as_ref().unwrap();
            return serde_json::from_reader(f).unwrap();
        }
        let seed: [u8; 32] = rand::rng().random();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let keypair = Self {
            public: Ed25519Pub(signing_key.verifying_key().to_bytes()),
            private: seed,
        };
        file.as_ref()
            .unwrap()
            .write_all(&serde_json::to_vec_pretty(&keypair).unwrap())
            .ok();
        return keypair;
    }

    fn x25519_private(&self) -> [u8; 32] {
        let hash = Sha512::digest(&self.private);
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&hash[..32]);
        scalar[0] &= 0xf8;
        scalar[31] &= 0xff;
        scalar[31] |= 0x40;
        scalar
    }

    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        ed25519_dalek::SigningKey::from_bytes(&self.private)
            .sign(msg)
            .to_bytes()
    }
}

struct PeerState {
    last_cookie: Option<String>,
    last_always_returned: Option<String>,
    last_always_returned_signed: bool,
    peer_map: HashMap<SocketAddr, PeerInfo>,
    peer_map_by_pub: HashMap<Ed25519Pub, Source>,
    peer_vec: Vec<SocketAddr>,
    suggested_peers: HashSet<SocketAddr>,
    recent_peer_timer: Instant,
    recent_peer_counter_max: usize,
    maintenance_period: u64,
    socket: UdpSocket,
    lcdp_port: u16,
    http_port: u16,
    boot: Instant,
    keypair: Keypair,
    open_file_cache: HashMap<String, OpenFile>,
    list_results: HashMap<String, (i32, u64)>,
    list_time: Instant,
    p: PersistentState,
    next_maintenance: Instant,
    next_save: Instant,
    last_upnp: std::time::SystemTime,
    recorded_chats: HashMap<String, Vec<String>>,
    all_chats: Vec<(String, String)>,
    displayed_group_chat_ids: HashSet<(String, i64)>,
    last_group: String,
    group_chat_outbox: Vec<GroupChatMessage>,
    group_chat_backoff_next: Option<Instant>,
    group_chat_backoff_delay_ms: f64,
    ws_vec: Vec<WebSocket<TcpStream>>,
    http_clients: Vec<TcpStream>,
    content_gateways: Vec<ContentGateway>,
    active_peer_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    active_peer_pubs: HashSet<Ed25519Pub>,
    //probe_peer_history: VecDeque<HashSet<SocketAddr>>,
}
#[derive(Serialize, Deserialize)]
struct PeersV10 {
    peer_map: Vec<(SocketAddr, PeerInfo)>,
    peer_map_by_pub: Vec<(Ed25519Pub, Source)>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PersistentState {
    you_should_see_this: Option<YouShouldSeeThis>,
    i_just_saw_this: Option<IJustSawThis>,
    #[serde(default)]
    my_ed25519_signed_by_web_wallet: Option<String>,
}
impl PersistentState {
    fn save(&self) {
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open("./cjp2p/state/persistent_state.v2.json")
            .unwrap()
            .write_all(&serde_json::to_vec_pretty(&self).unwrap())
            .unwrap();
    }
    fn load() -> Self {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open("./cjp2p/state/persistent_state.v2.json");
        if file.as_ref().is_ok() && file.as_ref().unwrap().metadata().unwrap().len() > 0 {
            return serde_json::from_reader(&file.unwrap()).unwrap();
        } else {
            return Self {
                you_should_see_this: None,
                i_just_saw_this: None,
                my_ed25519_signed_by_web_wallet: None,
            };
        }
    }
}
impl PeerState {
    fn new(lcdp_port: u16, http_port: u16) -> Self {
        fs::create_dir("./cjp2p").ok();
        fs::create_dir("./cjp2p/public").ok();
        fs::create_dir("./cjp2p/metadata").ok();
        fs::create_dir("./cjp2p/state").ok();
        fs::create_dir("./cjp2p/origin").ok();
        fs::create_dir("./cjp2p/log").ok();
        fs::create_dir("./cjp2p/metadata/latest").ok();
        fs::create_dir("./cjp2p/streams").ok();
        fs::create_dir("./cjp2p/public/blake3").ok();
        fs::create_dir("./cjp2p/public/blake3_tree_v2").ok();
        fs::create_dir("./cjp2p/incoming").ok();
        fs::create_dir("./cjp2p/incoming/blake3").ok();
        fs::create_dir("./cjp2p/incoming/blake3_tree_v2").ok();
        use std::net::Ipv6Addr;
        let (peer_map, peer_map_by_pub) = PeerState::load_peers();
        let mut ps = Self {
            last_cookie: None,
            last_always_returned: None,
            last_always_returned_signed: false,
            peer_map,
            peer_map_by_pub,
            peer_vec: vec![],
            suggested_peers: HashSet::new(),
            recent_peer_timer: Instant::now(),
            recent_peer_counter_max: 0,
            maintenance_period: if std::env::consts::OS == "android" {
                2
            } else {
                1
            },
            socket: (|| -> std::io::Result<UdpSocket> {
                let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
                #[cfg(any(target_os = "linux", target_os = "android"))]
                unsafe {
                    let val: libc::c_int = 0x0002; // IPV6_PREFER_SRC_PUBLIC
                    libc::setsockopt(
                        sock.as_raw_fd(),
                        libc::IPPROTO_IPV6,
                        libc::IPV6_ADDR_PREFERENCES,
                        &val as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&val) as libc::socklen_t,
                    );
                }
                let addr = SockAddr::from(std::net::SocketAddr::from((
                    Ipv6Addr::UNSPECIFIED,
                    lcdp_port,
                )));
                sock.bind(&addr)?;
                Ok(sock.into())
            })()
            .or_else(|_| UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, lcdp_port)))
            .unwrap(),
            lcdp_port,
            http_port,
            boot: Instant::now(),
            keypair: Keypair::load_key(),
            open_file_cache: HashMap::new(),
            list_results: HashMap::new(),
            list_time: Instant::now(),
            p: PersistentState::load(),
            next_maintenance: Instant::now() - Duration::from_secs(99999),
            next_save: Instant::now() + Duration::from_secs(150),
            last_upnp: std::time::SystemTime::now(),
            recorded_chats: HashMap::new(),
            all_chats: Vec::new(),
            displayed_group_chat_ids: HashSet::new(),
            last_group: "main".to_string(),
            group_chat_outbox: Vec::new(),
            group_chat_backoff_next: None,
            group_chat_backoff_delay_ms: 500.0,
            ws_vec: Vec::new(),
            http_clients: Vec::new(),
            content_gateways: Vec::new(),
            active_peer_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            active_peer_pubs: HashSet::new(),
            //probe_peer_history: VecDeque::new(),
        };
        let n = ps.active_peers_from_pub_map().len();
        ps.active_peer_count.store(n, std::sync::atomic::Ordering::Relaxed);
        if ps.maintenance_period > 1 {
            info!("slowing maintenance in half because android, checking if its plugged in is harder than it sounds");
        }

        for (k, v) in &ps.peer_map {
            if let Some(ed25519) = v.ed25519 {
                ps.peer_map_by_pub.insert(ed25519, Source::S(k.to_owned()));
            }
        }

        ps.socket.set_broadcast(true).ok();
        ps.socket.set_nonblocking(true).unwrap();
        SockRef::from(&ps.socket)
            .set_recv_buffer_size(0x100000)
            .ok();
        ps.socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        let ipv4 = Ipv4Addr::new(127, 0, 0, 1);
        let ipv6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0x1);
        let v4_in_v6 = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x1);

        debug!("{} is loopback? {} ", ipv4, ipv4.is_loopback());
        debug!("{} is loopback? {} ", ipv6, ipv6.is_loopback());
        debug!("{} is loopback? {} ", v4_in_v6, v4_in_v6.is_loopback()); //false, strange
        debug!("{} is loopback? {} ", v4_in_v6, v4_in_v6.to_ipv4().unwrap().is_loopback());
        for bootstrap in [
            "148.71.89.128:24254",
            "159.69.54.127:24254",
            "[2a01:4f8:c013:5bc5::1]:24254",
            "[2001:818:e876:f700:e008:c723:26f1:561f]:24254",
        ] {
            let mut pi = PeerInfo::new();
            pi.delay = Duration::from_millis(20);
            let sa: SocketAddr = bootstrap.parse().unwrap();
            if !ps.peer_map.contains_key(&sa) {
                ps.peer_map.insert(bootstrap.parse().unwrap(), pi);
            }
        }
        ps.upnp();
        ps.pcp_ipv6();
        ps.upnp_ipv6();
        return ps;
    }
    fn active_peers_from_pub_map(&self) -> Vec<(SocketAddr, Ed25519Pub, Duration)> {
        self.peer_map_by_pub
            .iter()
            .filter_map(|(pub_, src)| {
                if let Source::S(sa) = src {
                    let delay = self.peer_map.get(sa)?.delay;
                    if delay < Duration::from_millis(ACTIVE_PEER_DELAY_MS) {
                        return Some((*sa, *pub_, delay));
                    }
                }
                None
            })
            .collect()
    }
    fn hash_ip(&self, src: SocketAddr) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.keypair.private);
        hasher.update(src.ip().to_string());
        return format!("{:x}", hasher.finalize())[..8].to_string();
    }

    // check if the key is missing or incorrect (so true means unverified)
    fn check_key(&mut self, messages: &Vec<Message>, src: SocketAddr) -> bool {
        for message_in in messages {
            if let Message::AlwaysReturned(m) = message_in {
                self.last_always_returned=Some(m.cookie.clone());
                let correct_hash = self.hash_ip(src);
                if correct_hash == m.cookie && !self.peer_map.contains_key(&src) {
                    let mut pi = PeerInfo::new();
                    pi.delay = Duration::from_millis(120);
                    self.peer_map.insert(src, pi);
                    info!("new peer spotted {src}");
                }
                return correct_hash != m.cookie;
            }
        }
        return true;
    }
    fn please_always_return(&self, src: SocketAddr) -> Message {
        let correct_hash = self.hash_ip(src);
        return Message::PleaseAlwaysReturnThisMessage(PleaseAlwaysReturnThisMessage {
            cookie: correct_hash,
        });
    }

    fn always_returned(&self, sa: SocketAddr) -> Vec<Message> {
        trace!("always_returned for {sa}");
        if let Some(c) = self.last_cookie.clone() {
            return vec![Message::AlwaysReturned(AlwaysReturned{cookie:c })];
        }
        if let Some(p) = self.peer_map.get(&sa) {
            if let Some(c) = p.anti_ip_spoofing_cookie_they_expect.to_owned() {
                return vec![Message::AlwaysReturned(AlwaysReturned{cookie:c })];
            }
        }
        return vec![];
    }

    fn probe_interfaces(&mut self) -> () {
        let nowi = Instant::now();
        let to_probe: &mut HashSet<SocketAddr> = &mut HashSet::new();
        let addrs = nix::ifaddrs::getifaddrs().unwrap();
        log_if_slow(nowi, line!().to_string());
        for ifaddr in addrs {
            match ifaddr.broadcast {
                Some(address) => match address.as_sockaddr_in() {
                    Some(addr) => {
                        let mut sa = SocketAddr::from(*addr);
                        sa.set_port(24254);
                        trace!("broadcastingto {}",sa);
                        to_probe.insert(sa);
                        ()
                    }
                    None => (),
                },
                None => (),
            }
            log_if_slow(nowi, line!().to_string());
        }
        to_probe.insert("224.0.0.1:24254".parse().unwrap());
        to_probe.insert("[ff02::1]:24254".parse().unwrap());
        for sa in to_probe.iter() {
            let mut message_out = vec![Message::PleaseSendPeers(PleaseSendPeers {})];
            // for a netmask of 255.255.255.255 we might actually know the cookie
            message_out.append(&mut self.always_returned(*sa));
            let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
            trace!( "sending message {:?} to {sa}", String::from_utf8_lossy(&message_out_bytes));
            self.socket.send_to(&message_out_bytes, sa).ok();
            log_if_slow(nowi, line!().to_string());
        }
    }
    fn probe(&mut self) -> () {
        let nowi = Instant::now();
        /* extremely premature optimization
        let mut peers = vec![]; //        self.best_peers(10, 2);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // some possibly pointless attempt to time peer probes to match NAT/firewall states on both sides, i have no idea how much it helps or is needed, it's just an idea, it might even hurt depending on the peer due to forcing everyone on a ~4 minute timer vs just best peers preferred and more frequent
        // this was just a best_peers() call for a long time, which definately works
        // better in some scenarios.   its just an idea i coded up with results yet to be
        // determined
        for (p, pi) in &self.peer_map {
            let Some(ed25519) = pi.ed25519 else {
                continue;
            };
            let xor = u64::from_le_bytes(ed25519.as_bytes()[3..11].try_into().unwrap())
                ^ u64::from_le_bytes(self.keypair.public.as_bytes()[3..11].try_into().unwrap())
                ^ now;
            let m = ((self.peer_map_by_pub.len().next_power_of_two() >> 4) as u64)
                .saturating_sub(self.maintenance_period);
            debug!("PROBE xor mask {:x} of {}",m,self.peer_map_by_pub.len());
            if xor & m == 0 && ed25519 != self.keypair.public {
                peers.push((*p, pi.delay));
            }
        }

        debug!("PROBE xor peers found {}",peers.len());
        if log_enabled!(Level::Debug) {
            for p in &peers {
                if let Some(ed25519) = self.peer_map[&p.0].ed25519 {
                    debug!("PROBE xor peer found {ed25519}");
                }
            }
        }
        log_if_slow(nowi, line!().to_string());
        if peers.len() >= 5 {
            info!("PROBE too many xor peers {}, trimming",peers.len());
            peers.sort_unstable_by(|a, b| a.1.cmp(&b.1));
            let mut rng = rand::rng();
            let mut peers_trimmed = HashSet::new();

            for _ in 0..10 * 2 {
                let i =
                    ((rng.random_range(0.0..1.0) as f64).powi(2) * (peers.len() as f64)) as usize;
                if i >= peers.len() {
                    continue;
                }
                let p = peers[i];
                peers_trimmed.insert(p);
                if peers_trimmed.len() >= 5 {
                    break;
                };
            }
            peers = peers_trimmed.into_iter().collect();
        }
        debug!("PROBE probing {} xor peers {:?}",peers.len(),peers);
        let mut peers: HashSet<SocketAddr> = peers.into_iter().map(|(addr, _)| addr).collect();
        peers.extend(self.best_peers(10_usize.saturating_sub(peers.len()), 2));
        log_if_slow(nowi, line!().to_string());
        */
        let mut peers: HashSet<SocketAddr> = self
            .suggested_peers
            .iter()
            .choose_multiple(&mut rand::rng(), 10)
            .into_iter()
            .copied()
            .collect();
        for &sa in &peers {
            self.suggested_peers.remove(&sa);
        }
        // drop half so its not a big DDOS multiplier, since its very short to suggest a peer
        // "8.8.8.8:8",  13-21 chars and results in  85 sent
        // PleaseAlwaysReturnThisMessage should be shorter
        peers = peers
            .iter()
            .choose_multiple(&mut rand::rng(), 5)
            .into_iter()
            .copied()
            .collect();
        peers.extend(self.best_peers(10usize.saturating_sub(peers.len()), 2));
        if peers.len() != 10 {
            debug!("PROBE not 10 peers {}",peers.len());
        }
        log_if_slow(nowi, line!().to_string());
        /*
        debug!("PROBE total before history merge: {} peers {:?}", peers.len(), peers);

        self.probe_peer_history.push_back(peers.clone());
        if self.probe_peer_history.len() > 3 {
            peers.extend(self.probe_peer_history.pop_front().unwrap_or_default());
        }

        debug!("PROBE total after history merge: {} peers {:?}", peers.len(), peers);
        */
        for sa in peers {
            let mut message_out: Vec<Message> = Vec::new();
            if let Some(peer_info) = self.peer_map.get_mut(&sa) {
                peer_info.delay = peer_info
                    .delay
                    .saturating_add(peer_info.delay / 3 + Duration::from_millis(1));
                message_out.push(SignedMessage::new(self, serde_json::to_vec(&self.always_returned(sa)).unwrap()));
                message_out.push(MyPublicKey::new(self));
                message_out.push(Message::PleaseSendPeers(PleaseSendPeers {}));
                message_out.push(PleaseReturnThisMessage::new(self));
                message_out.append(&mut self.always_returned(sa));
            }
            // let people know im here
            // im not sure if anyone cares about all this info from completely random contacts
            message_out.push(self.please_always_return(sa));
            //    if let Some(v) = &self.p.i_just_saw_this {
            //        message_out.push(Message::IJustSawThis(v.clone()));
            //    }
            //    if let Some(v) = &self.p.you_should_see_this {
            //        message_out.push(Message::YouShouldSeeThis(v.clone()));
            //    }
            let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
            trace!( "PROBE probing {sa}");
            //            trace!( "PROBE sending message {:?} to {sa}", String::from_utf8_lossy(&message_out_bytes));
            match self.socket.send_to(&message_out_bytes, sa) {
                Ok(s) => trace!("sent {s}"),
                Err(e) => {
                    if e.raw_os_error() == Some(11) {
                        warn!("PROBE EWOULDBLOCK failed to send (your wifi/mobile connection is probably backing up) {0} {e}", message_out_bytes.len());
                    } else {
                        trace!("PROBE failed to send to {sa} {0} bytes: {e} ", message_out_bytes.len());
                    }
                }
            }
        }
        log_if_slow(nowi, line!().to_string());
    }

    fn sort(&mut self) -> () {
        let mut peers: Vec<_> = self
            .peer_map
            .iter()
            .map(|(k, v)| (k, v.delay.as_secs_f64()))
            .collect();
        peers.sort_unstable_by(|a, b| a.1.total_cmp(&b.1));
        self.peer_vec = peers.into_iter().map(|(addr, _)| *addr).collect();
    }

    fn load_peers() -> (HashMap<SocketAddr, PeerInfo>, HashMap<Ed25519Pub, Source>) {
        let file = OpenOptions::new()
            .read(true)
            .open("./cjp2p/state/peers.v10.json");
        let mut peer_map = HashMap::<SocketAddr, PeerInfo>::new();
        let mut peer_map_by_pub = HashMap::<Ed25519Pub, Source>::new();
        if file.as_ref().is_ok() && file.as_ref().unwrap().metadata().unwrap().len() > 0 {
            let v10: PeersV10 = serde_json::from_reader(&file.unwrap()).unwrap();
            peer_map.extend(v10.peer_map);
            peer_map_by_pub.extend(v10.peer_map_by_pub);
        }
        (peer_map, peer_map_by_pub)
    }
    fn save_peers(&self) -> () {
        debug!("saving peers");
        let mut peer_map: Vec<(SocketAddr, PeerInfo)> = Vec::new();
        let mut peer_map_by_pub: Vec<(Ed25519Pub, Source)> = Vec::new();
        for (pub_, src) in &self.peer_map_by_pub {
            if let Source::S(sa) = src {
                if let Some(pi) = self.peer_map.get(sa) {
                    peer_map.push((*sa, pi.clone()));
                    peer_map_by_pub.push((*pub_, *src));
                }
            }
        }
        let v10 = PeersV10 { peer_map, peer_map_by_pub };
        fs::create_dir_all("./cjp2p/state").ok();
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open("./cjp2p/state/peers.v10.json")
            .unwrap()
            .write_all(&serde_json::to_vec_pretty(&v10).unwrap())
            .ok();
    }

    fn best_peers(&self, mut how_many: usize, quality: i32) -> HashSet<SocketAddr> {
        let nowi = Instant::now();
        let mut rng = rand::rng();
        let result: &mut HashSet<SocketAddr> = &mut HashSet::new();
        log_if_slow(nowi, line!().to_string());
        if quality >= 3 {
            // this should be randomized, whenever there are enough peers that its not just all of them
            // anyway
            for i in self.peer_map_by_pub.values() {
                if how_many == 0 {
                    break;
                }
                if let Source::S(sa) = i {
                    result.insert(sa.clone());
                    how_many -= 1;
                }
            }
        }
        log_if_slow(nowi, line!().to_string());
        for _ in 0..how_many * 2 {
            let i = ((rng.random_range(0.0..1.0) as f64).powi(quality)
                * (self.peer_vec.len() as f64)) as usize;
            if i >= self.peer_vec.len() {
                continue;
            }
            let p = &self.peer_vec[i];
            if result.insert(*p) {
                how_many -= 1;
                if how_many == 0 {
                    break;
                }
            }
            trace!( "best peer(q:{quality}) {0} {1} {2}", i, p, self.peer_map[p].delay.as_secs_f64());
        }
        log_if_slow(nowi, line!().to_string());
        result.retain(|sa| {
            if self.peer_map.contains_key(sa) {
                true
            } else {
                error!("best_peers: {sa} in result but not in peer_map, removing, this shouldnt happen");
                false
            }
        });
        log_if_slow(nowi, line!().to_string());
        return result.clone();
    }
    fn handle_messages(
        &mut self,
        messages: Vec<Message>,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        stream_states: &mut HashMap<String, StreamState>,
        inbound_states: &mut HashMap<String, InboundState>,
        signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        let mut message_out = vec![];
        self.last_always_returned_signed = !*might_be_ip_spoofing && signer.is_some();
        for message_in_enum in messages {
            message_out.append(&mut message_in_enum.receive(
                self,
                &src,
                might_be_ip_spoofing,
                stream_states,
                inbound_states,
                signer,
            ));
        }
        return message_out;
    }
    fn serve_http_content(
        &mut self,
        stream_states: &mut HashMap<String, StreamState>,
        inbound_states: &mut HashMap<String, InboundState>,
        cg_index: usize,
    ) {
        let cg = &mut (self.content_gateways[cg_index]);
        if cg.http_done {
            warn!("is this code ever called? why?");
            return;
        }
        if let Some(l) = &cg.pending_latest {
            if cg.id.is_empty() || l.delay_for_newest_until.map_or(false, |t| !has_passed(t)) {
                return;
            }
            cg.pending_latest = None;
        }

        if let Ok(file) = OpenOptions::new()
            .read(true)
            .write(true)
            .open("./cjp2p/public/".to_owned() + &cg.id)
        {
            cg.serve_content_from_disk(&file);

            if cg.http_done {
                let cg_ = self.content_gateways.remove(cg_index);
                self.http_clients.push(cg_.http_socket);
            }
            return;
        }
        let id = cg.id.clone();

        if let Some(ss) = stream_states.get_mut(&id) {
            cg.serve_content_from_stream_state(ss);
            if cg.http_done {
                let cg_ = self.content_gateways.remove(cg_index);
                self.http_clients.push(cg_.http_socket);
            }
            return;
        }

        let i = match inbound_states.get_mut(&id) {
            Some(i) => i,
            _ => {
                if !is_local(&cg.http_socket) && !matches!( cg.initiator,Initiator::Latest ) {
                    let page = format!("HTTP/1.0 403 Forbidden\r\n\n");
                    cg.http_socket.write_all(page.as_bytes()).ok();
                    self.content_gateways.remove(cg_index);
                    return;
                }

                InboundState::new(&id, self, inbound_states);
                info!("http scheduling inbound file {:?}", id);
                inbound_states.get_mut(&id).unwrap()
            }
        };

        let cg = &mut (self.content_gateways[cg_index]);
        cg.serve_content_from_inbound_state(i);
        if cg.http_done {
            let cg_ = self.content_gateways.remove(cg_index);
            self.http_clients.push(cg_.http_socket);
        }
    }

    fn handle_websocket2(
        &mut self,
        index: usize,
        stream_states: &mut HashMap<String, StreamState>,
        inbound_states: &mut HashMap<String, InboundState>,
    ) {
        debug!("handling {} websockets",self.ws_vec.len());
        let Ok(buf) = self.ws_vec[index].read() else {
            info!("websocket disconnected with error");
            self.ws_vec.remove(index);
            return;
        };
        debug!("websocket sent: {}",buf);
        let message_in_bytes = buf.into_data();
        if message_in_bytes.len() == 0 {
            info!("websocket disconnected (EOF, empty read)");
            self.ws_vec.remove(index);
            return;
        }
        let messages: Messages = match serde_json::from_slice(&message_in_bytes) {
            Ok(r) => r,
            Err(e) => {
                debug!("could not deserialize incoming messages from websocket {e}  :  {}",
                    String::from_utf8_lossy(&message_in_bytes));
                return;
            }
        };
        let messages = messages.0;

        let message_out = self.handle_messages(
            messages,
            &Source::None,
            &mut false,
            stream_states,
            inbound_states,
            None,
        );
        if message_out.len() == 0 {
            return;
        }
        let message_out_string = serde_json::to_string(&message_out).unwrap();
        info!("sending reply message {:?} to websocket", message_out_string);
        let ws = &mut self.ws_vec[index];
        match ws.write(tungstenite::Message::Text(message_out_string.into())) {
            Ok(_) => {
                ws.flush().ok();
            }
            _ => {
                info!("websocket disconnected on write with error");
                self.ws_vec.remove(index);
            }
        }
    }
    fn upnp(&self) {
        let local_port: u16 = self.lcdp_port;
        let external_port: u16 = (((self.keypair.public.as_bytes()[0] as u16) << 8)
            + self.keypair.public.as_bytes()[1] as u16)
            | 0x401;
        let lease_duration: u32 = 3600; // 0 = permanent
        let protocol = PortMappingProtocol::UDP;
        let description = "cjp2p";
        thread::spawn(move || {
            if let Ok(gateway) = search_gateway(SearchOptions {
                ..Default::default()
            }) {
                debug!("UPNP Found gateway: {}", gateway.addr);
                let local_ip = get_local_ip_for_gateway(gateway.addr.ip().clone());
                let local_addr = SocketAddrV4::new(local_ip, local_port);
                debug!("UPNP Local addr: {local_addr}");
                match gateway.add_port(
                    protocol,
                    external_port,
                    local_addr,
                    lease_duration,
                    description,
                ) {
                    Ok(()) => {
                        debug!("UPNP external port requested base based on your public key: {}",external_port);
                        for index in 0..99 {
                            match gateway.get_generic_port_mapping_entry(index) {
                            Ok(entry) => {
                                if entry.external_port == external_port
                                    && entry.protocol == protocol
                                {
                                    debug!("UPNP Found mapping at index {index}");
                                    debug!("UPNP Real lease: {}s", entry.lease_duration);
                                    debug!("UPNP Internal: {}:{}", entry.internal_client, entry.internal_port);
                                    debug!("UPNP Desc: {}", entry.port_mapping_description);
                                    if entry.lease_duration != lease_duration {
                                        debug!("UPNP router Clamped from {lease_duration} to {}", entry.lease_duration);
                                    }
                                    break;
                                }
                            }
                            Err(
                                igd::GetGenericPortMappingEntryError::SpecifiedArrayIndexInvalid,
                            ) => {
                                warn!("UPNP Mapping not found. Router didn't create it or deleted it.");
                                break;
                            }
                            Err(e) => {
                                warn!("UPNP Error reading router index {index}: {:?}", e);
                                break;
                            }
                        }
                        }
                    }
                    Err(e) => {
                        warn!("UPNP add_port failed: {e}");
                    }
                }

                if let Ok(ip) = gateway.get_external_ip() {
                    debug!("UPNP Your gateway's IP: {ip}");
                }
            } else {
                debug!("UPNP no gateway found");
            }
        });
    }

    // Port Control Protocol (RFC 6887) MAP request for IPv6 firewall pinhole.
    fn pcp_ipv6(&self) {
        let local_port: u16 = self.lcdp_port;
        let external_port: u16 = (((self.keypair.public.as_bytes()[0] as u16) << 8)
            + self.keypair.public.as_bytes()[1] as u16)
            | 0x401;
        let lease_duration: u32 = 3600;
        thread::spawn(move || {
            let (gateway, oif) = match pcp_find_ipv6_gateway() {
                Some(v) => v,
                None => {
                    debug!("PCP no IPv6 default gateway found");
                    return;
                }
            };
            debug!("PCP IPv6 gateway: {} oif={}", gateway, oif);

            // RTA_OIF gives us the interface index directly -- used as scope_id for link-local.
            let scope_id: u32 = if gateway.is_unicast_link_local() {
                oif
            } else {
                0
            };
            let gw_sock = SocketAddr::V6(std::net::SocketAddrV6::new(gateway, 5351, 0, scope_id));

            // Discover which local IPv6 address routes toward the gateway.
            let local_ip: Ipv6Addr = {
                let s = match UdpSocket::bind("[::]:0") {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("PCP probe bind failed: {e}");
                        return;
                    }
                };
                if s.connect(gw_sock).is_err() {
                    warn!("PCP probe connect failed");
                    return;
                }
                match s.local_addr().map(|a| a.ip()) {
                    Ok(IpAddr::V6(v6)) => v6,
                    _ => {
                        warn!("PCP could not determine local IPv6 address");
                        return;
                    }
                }
            };
            debug!("PCP local IPv6: {}", local_ip);

            // Build PCP MAP request: 24-byte common header + 36-byte MAP opcode = 60 bytes.
            let nonce: [u8; 12] = rand::rng().random();
            let mut req = [0u8; 60];
            req[0] = 2; // PCP version
            req[1] = 1; // opcode: MAP
                        // bytes 2-3: reserved
            req[4..8].copy_from_slice(&lease_duration.to_be_bytes());
            req[8..24].copy_from_slice(&local_ip.octets());
            req[24..36].copy_from_slice(&nonce);
            req[36] = 17; // protocol: UDP
                          // bytes 37-39: reserved
            req[40..42].copy_from_slice(&local_port.to_be_bytes());
            req[42..44].copy_from_slice(&external_port.to_be_bytes());
            // bytes 44-59: suggested external IP = all zeros (any)

            let pcp_socket = match UdpSocket::bind("[::]:0") {
                Ok(s) => s,
                Err(e) => {
                    warn!("PCP bind failed: {e}");
                    return;
                }
            };
            pcp_socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .ok();
            if let Err(e) = pcp_socket.send_to(&req, gw_sock) {
                warn!("PCP send failed: {e}");
                return;
            }

            let mut resp = [0u8; 60];
            match pcp_socket.recv_from(&mut resp) {
                Ok((n, _)) => {
                    if n < 24 {
                        warn!("PCP response too short: {n} bytes");
                        return;
                    }
                    // Response byte 1 has R=1 bit set, opcode in low 7 bits -> 0x81 for MAP.
                    if resp[0] != 2 || resp[1] != 0x81 {
                        warn!("PCP unexpected response: ver={} op={:#x}", resp[0], resp[1]);
                        return;
                    }
                    let result = resp[3];
                    if result != 0 {
                        warn!("PCP MAP failed, result code: {result}");
                        return;
                    }
                    let lifetime = u32::from_be_bytes(resp[4..8].try_into().unwrap());
                    if n >= 60 {
                        let ext_port = u16::from_be_bytes(resp[42..44].try_into().unwrap());
                        let ext_ip_bytes: [u8; 16] = resp[44..60].try_into().unwrap();
                        let ext_ip = Ipv6Addr::from(ext_ip_bytes);
                        info!("PCP IPv6 mapping: external [{}]:{ext_port} lifetime {lifetime}s", ext_ip);
                    } else {
                        info!("PCP IPv6 mapping success, lifetime {lifetime}s");
                    }
                }
                Err(e) => {
                    if e.raw_os_error() == Some(11) {
                        debug!("PCP recv timeout (router may not support PCP): {e}");
                    } else {
                        info!("PCP recv error (router may not support PCP): {e}");
                    }
                }
            }
        });
    }

    // UPnP IGD2 WANIPv6FirewallControl pinhole -- IPv6 equivalent of UPnP port mapping.
    fn upnp_ipv6(&self) {
        let local_port: u16 = self.lcdp_port;
        let lease_duration: u32 = 3600;
        thread::spawn(move || {
            let control_url = match upnp_ipv6_find_service() {
                Some(u) => u,
                None => {
                    debug!("UPnP IPv6: no WANIPv6FirewallControl service found");
                    return;
                }
            };
            debug!("UPnP IPv6: control URL {control_url}");

            let local_ipv6 = match local_ipv6_source() {
                Some(ip) => ip,
                None => {
                    warn!("UPnP IPv6: could not determine local IPv6 address");
                    return;
                }
            };
            debug!("UPnP IPv6: local IPv6 {local_ipv6}");

            let soap_body = format!(
                concat!(
                    r#"<?xml version="1.0"?>"#,
                    r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">"#,
                    r#"<s:Body>"#,
                    r#"<u:AddPinhole xmlns:u="urn:schemas-upnp-org:service:WANIPv6FirewallControl:1">"#,
                    r#"<RemoteHost></RemoteHost><RemotePort>0</RemotePort>"#,
                    r#"<Protocol>17</Protocol>"#,
                    r#"<InternalPort>{}</InternalPort>"#,
                    r#"<InternalClient>{}</InternalClient>"#,
                    r#"<LeaseTime>{}</LeaseTime>"#,
                    r#"</u:AddPinhole></s:Body></s:Envelope>"#,
                ),
                local_port, local_ipv6, lease_duration
            );

            let svc = "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1";
            match upnp_soap_post(&control_url, &format!("{svc}#AddPinhole"), &soap_body) {
                Some(r) if r.contains("UniqueID") => {
                    info!("UPnP IPv6: AddPinhole success");
                }
                Some(r) if r.contains("errorCode") || r.contains("faultstring") => {
                    warn!("UPnP IPv6: AddPinhole error: {r}");
                }
                Some(_) => {
                    info!("UPnP IPv6: AddPinhole sent");
                }
                None => {
                    warn!("UPnP IPv6: AddPinhole HTTP request failed");
                }
            }
        });
    }

    pub fn x25519_to_ed25519(&self, their_x25519: [u8; 32]) -> Option<(Source, Ed25519Pub)> {
        let u = curve25519_dalek::MontgomeryPoint(their_x25519);

        // to_edwards(0) gives point with x sign bit = 0
        let ed_point_0 = u.to_edwards(0)?;
        let cand = Ed25519Pub(ed_point_0.compress().to_bytes());
        if let Some(src) = self.peer_map_by_pub.get(&cand) {
            return Some((*src, cand));
        }

        // to_edwards(1) gives point with x sign bit = 1
        let ed_point_1 = u.to_edwards(1)?;
        let cand = Ed25519Pub(ed_point_1.compress().to_bytes());

        if let Some(src) = self.peer_map_by_pub.get(&cand) {
            return Some((*src, cand));
        }

        return None;
    }
    fn unstall_getlatests(&self) {
        let nowi = Instant::now();
        let mut msg_out = vec![];
        log_if_slow(nowi, line!().to_string());
        for cg in &self.content_gateways {
            if let Some(pending_latest) = &cg.pending_latest {
                if cg.id.is_empty() {
                    msg_out.push(Message::GetLatest(GetLatest {
                        ed25519: pending_latest.pub_key,
                        name: pending_latest.name.clone(),
                    }));
                }
            }
        }
        log_if_slow(nowi, line!().to_string());
        if msg_out.len() > 0 {
            let peers = self.best_peers(250, 6);
            log_if_slow(nowi, line!().to_string());
            debug!("trying to GetLatest {:?} from {:?}",msg_out,peers);
            for sa in &peers {
                msg_out.append(&mut self.always_returned(*sa));
                match self
                    .socket
                    .send_to(&serde_json::to_vec(&msg_out).unwrap(), sa)
                {
                    Ok(s) => trace!("sent {s}"),
                    Err(e) => {
                        if e.raw_os_error() == Some(11) {
                            warn!("EWOULDBLOCK failed to send (your wifi/mobile connection is probably backing up) {0} {e}", msg_out.len());
                        } else {
                            trace!("failed to send to {sa} {0} bytes: {e} ", msg_out.len());
                        }
                    }
                }
                if self.always_returned(*sa).len() > 0 {
                    msg_out.pop();
                }
            }
        }
        log_if_slow(nowi, line!().to_string());
    }
}

#[derive(Debug, Serialize, Clone)]
struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    #[serde(skip)]
    body_prefix: Vec<u8>,
}

fn parse_header(stream: &mut TcpStream) -> Option<HttpRequest> {
    let mut buf = [0u8; 4096];
    let len = stream.read(&mut buf).ok()?;
    let data = &buf[..len];

    // Split at \r\n\r\n so binary POST bodies don't trip the ASCII check.
    let header_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(len);
    let header_bytes = &data[..header_end];
    if !header_bytes.is_ascii() {
        warn!("garbage on http port, closing");
        return None;
    }
    let body_prefix = data[header_end..].to_vec();

    let request_str = String::from_utf8_lossy(header_bytes);
    let mut lines = request_str.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();

    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(": ") {
            headers.insert(key.to_lowercase(), value.to_string());
        }
    }

    Some(HttpRequest {
        method,
        path,
        headers,
        body_prefix,
    })
}

fn free_disk_bytes() -> u64 {
    // macOS has no statvfs64; its statvfs already has 64-bit fields.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use libc::statvfs64 as statvfs;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    use libc::statvfs;
    unsafe {
        let mut stat: statvfs = std::mem::zeroed();
        if statvfs(b".\0".as_ptr() as *const libc::c_char, &mut stat) == 0 {
            (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64)
        } else {
            0
        }
    }
}

// Compute the blake3 chaining value for a block at the given byte offset.
// BLOCK_SIZE must be a power-of-2 multiple of blake3::CHUNK_LEN (1024), which 4096 is.
fn block_chaining_value(data: &[u8], byte_offset: u64) -> [u8; 32] {
    let mut h = Blake3Hasher::new();
    h.set_input_offset(byte_offset);
    h.update(data);
    h.finalize_non_root()
}

fn leaf_cv_in_tree_v2(mmap: &Mmap, block_num: usize) -> Option<[u8; 32]> {
    let n_leaves = n_leaves_from_tree_v2_eof(mmap.len())?;
    if block_num >= n_leaves {
        return None;
    }
    let leaf_start = mmap.len() - n_leaves * 32 + block_num * 32;
    Some(mmap[leaf_start..leaf_start + 32].try_into().unwrap())
}

// Tree file v2 format (64-byte header, then top-down levels, leaves last):
//   [4 bytes: magic b"B3T\x02"] [28 bytes: reserved] [32 bytes: root hash]
//   [intermediate levels highest-first, each level including passed-up odd entries]
//   [N x 32 bytes: leaf CVs at the end]
// N (leaf count) is not stored; derive it from content file size or eof.
fn tree_file_size(n_leaves: usize) -> usize {
    let mut total = 4 + n_leaves * 32;
    let mut n = n_leaves;
    while n > 2 {
        n = (n + 1) / 2;
        total += n * 32;
    }
    total
}

fn tree_file_size_v2(n_leaves: usize) -> usize {
    60 + tree_file_size(n_leaves)
}

// Fills in the 64-byte v2 header and all intermediate levels of a tree mmap whose leaf
// section (last n_leaves*32 bytes) has already been written by the caller.
// Writes magic, reserved zeroes, and (for n_leaves>=2) the computed root hash.
// For n_leaves==1 the root is blake3::hash(content) which the caller must write to [32..64].
// Returns the blake3 root hash for n_leaves >= 2; None for n_leaves == 1.
fn finalize_tree_mmap_v2(mmap: &mut MmapMut, n_leaves: usize) -> Option<blake3::Hash> {
    mmap[0..4].copy_from_slice(b"B3T\x02");
    mmap[4..32].fill(0);
    if n_leaves < 2 {
        return None;
    }
    let total = mmap.len();
    let mut level_sizes: Vec<usize> = vec![n_leaves];
    while *level_sizes.last().unwrap() > 2 {
        let n = *level_sizes.last().unwrap();
        level_sizes.push((n + 1) / 2);
    }
    let mut offsets: Vec<usize> = Vec::with_capacity(level_sizes.len());
    let mut from_end = 0;
    for &s in &level_sizes {
        from_end += s * 32;
        offsets.push(total - from_end);
    }
    for k in 0..level_sizes.len() - 1 {
        let src = offsets[k];
        let dst = offsets[k + 1];
        let n = level_sizes[k];
        for i in 0..n / 2 {
            let l: [u8; 32] = mmap[src + 2 * i * 32..src + (2 * i + 1) * 32]
                .try_into()
                .unwrap();
            let r: [u8; 32] = mmap[src + (2 * i + 1) * 32..src + (2 * i + 2) * 32]
                .try_into()
                .unwrap();
            mmap[dst + i * 32..dst + (i + 1) * 32].copy_from_slice(&merge_subtrees_non_root(
                &l,
                &r,
                Mode::Hash,
            ));
        }
        if n % 2 == 1 {
            let last: [u8; 32] = mmap[src + (n - 1) * 32..src + n * 32].try_into().unwrap();
            mmap[dst + (n / 2) * 32..dst + (n / 2 + 1) * 32].copy_from_slice(&last);
        }
    }
    let top = *offsets.last().unwrap();
    let a: [u8; 32] = mmap[top..top + 32].try_into().unwrap();
    let b: [u8; 32] = mmap[top + 32..top + 64].try_into().unwrap();
    let root = merge_subtrees_root(&a, &b, Mode::Hash);
    mmap[32..64].copy_from_slice(root.as_bytes());
    Some(root)
}

// Derive n_leaves from a v2 tree file's eof. Walks upward from approximation.
fn n_leaves_from_tree_v2_eof(eof: usize) -> Option<usize> {
    if eof < 128 {
        return None;
    }
    let target = eof - 60;
    let mut n = (target.saturating_sub(4)) / 64;
    if n < 2 {
        n = 2;
    }
    while tree_file_size(n) < target {
        n += 1;
    }
    while n > 0 && tree_file_size(n) > target {
        n -= 1;
    }
    if tree_file_size(n) == target {
        Some(n)
    } else {
        None
    }
}

// Recursive top-down consistency check for tree v2 files.
// Returns true if stored[level][idx] equals merge_non_root of its children.
// Adds suspect 4KB block indices to `bad` on inconsistency.
fn tree_check_subtree(
    data: &[u8],
    level_sizes: &[usize],
    offsets: &[usize],
    level: usize,
    idx: usize,
    bad: &mut HashSet<usize>,
) -> bool {
    if level == 0 {
        return true;
    }
    let li = 2 * idx;
    let ri = li + 1;
    if ri >= level_sizes[level - 1] {
        return tree_check_subtree(data, level_sizes, offsets, level - 1, li, bad);
    }
    let co = offsets[level - 1];
    let po = offsets[level];
    let l: [u8; 32] = data[co + li * 32..co + (li + 1) * 32].try_into().unwrap();
    let r: [u8; 32] = data[co + ri * 32..co + (ri + 1) * 32].try_into().unwrap();
    let p: [u8; 32] = data[po + idx * 32..po + (idx + 1) * 32].try_into().unwrap();
    let l_ok = tree_check_subtree(data, level_sizes, offsets, level - 1, li, bad);
    let r_ok = tree_check_subtree(data, level_sizes, offsets, level - 1, ri, bad);
    if merge_subtrees_non_root(&l, &r, Mode::Hash) == p {
        return true;
    }
    bad.insert((po + idx * 32) / BLOCK_SIZE!());
    if l_ok && r_ok {
        bad.insert((co + li * 32) / BLOCK_SIZE!());
        bad.insert((co + ri * 32) / BLOCK_SIZE!());
    }
    false
}

// Check the header hash and parent-child consistency of a tree v2 data slice.
// Returns the set of 4KB block indices suspected bad. Empty = all good, rename to public.
fn check_tree_v2_data(data: &[u8], expected_hash: &str, n_leaves: usize) -> Vec<usize> {
    if data.len() < 64 || &data[0..4] != b"B3T\x02" {
        warn!("check_tree_v2_data: bad magic {:02x}{:02x}{:02x}{:02x} len={}", data.get(0).copied().unwrap_or(0), data.get(1).copied().unwrap_or(0), data.get(2).copied().unwrap_or(0), data.get(3).copied().unwrap_or(0), data.len());
        return (0..(data.len() + BLOCK_SIZE!() - 1) / BLOCK_SIZE!()).collect();
    }
    let expected: blake3::Hash = match expected_hash.parse() {
        Ok(h) => h,
        Err(_) => return vec![],
    };
    let mut bad: HashSet<usize> = HashSet::new();
    let header_hash_bad = data[32..64] != *expected.as_bytes();
    if header_hash_bad {
        warn!("check_tree_v2_data: root hash mismatch in block0 header: stored={} expected={} n_leaves={} len={}", hex::encode(&data[32..64]), expected_hash, n_leaves, data.len());
        bad.insert(0);
    }
    if n_leaves < 2 {
        return bad.into_iter().collect();
    }
    let total = data.len();
    let mut level_sizes = vec![n_leaves];
    while *level_sizes.last().unwrap() > 2 {
        let last = *level_sizes.last().unwrap();
        level_sizes.push((last + 1) / 2);
    }
    let mut offsets = Vec::with_capacity(level_sizes.len());
    let mut from_end = 0usize;
    for &s in &level_sizes {
        from_end += s * 32;
        offsets.push(total - from_end);
    }
    let l = level_sizes.len();
    let pre_tree_bad_count = bad.len();
    tree_check_subtree(data, &level_sizes, &offsets, l - 1, 0, &mut bad);
    tree_check_subtree(data, &level_sizes, &offsets, l - 1, 1, &mut bad);
    if bad.len() > pre_tree_bad_count {
        let mut bad_sorted: Vec<usize> = bad.iter().copied().collect();
        bad_sorted.sort();
        let block0_from_tree = !header_hash_bad && bad_sorted.contains(&0);
        warn!("check_tree_v2_data: tree structure fail n_leaves={} len={} bad_blocks={:?} block0_from_tree={}", n_leaves, data.len(), bad_sorted, block0_from_tree);
        // Top-level hashes are at bytes 64..128 (always block 0). When only leaf/mid blocks
        // are bad, block 0 is a propagated side effect, not genuinely corrupt.
        if block0_from_tree {
            let non_zero_bad: Vec<usize> = bad_sorted.iter().copied().filter(|&b| b != 0).collect();
            warn!("check_tree_v2_data: block0 added by tree propagation, actual suspect blocks: {:?}", non_zero_bad);
        }
    }
    bad.into_iter().collect()
}

// Build the tree file from a source mmap in one pass.
// If sha256 is Some, updates it with every chunk in the same pass.
// Returns the blake3 hex ID, or None on I/O error.
fn build_tree_from_mmap(
    src: &Mmap,
    file_size: usize,
    mut sha256: Option<&mut Sha256>,
) -> Option<String> {
    let n_leaves = (file_size + BLOCK_SIZE!() - 1) / BLOCK_SIZE!();
    let tree_tmp = format!("./cjp2p/public/.tmp_tree_{:016x}", rand::rng().random::<u64>());
    let tf = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&tree_tmp)
        .ok()?;
    let tsize = tree_file_size_v2(n_leaves);
    tf.set_len(tsize as u64).ok()?;
    let mut tmm = unsafe { MmapMut::map_mut(&tf) }.ok()?;
    let leaf_base = tsize - n_leaves * 32;
    let mut offset: u64 = 0;
    for (i, chunk) in src.chunks(BLOCK_SIZE!()).enumerate() {
        if let Some(ref mut h) = sha256 {
            h.update(chunk);
        }
        let cv = block_chaining_value(chunk, offset);
        tmm[leaf_base + i * 32..leaf_base + (i + 1) * 32].copy_from_slice(&cv);
        offset += chunk.len() as u64;
    }
    let blake3_id = if n_leaves == 1 {
        finalize_tree_mmap_v2(&mut tmm, 1);
        let h = blake3::hash(&src[..file_size]);
        tmm[32..64].copy_from_slice(h.as_bytes());
        format!("{}", h)
    } else {
        format!("{}", finalize_tree_mmap_v2(&mut tmm, n_leaves).unwrap())
    };
    drop(tmm);
    drop(tf);
    let tree_path = format!("./cjp2p/public/blake3_tree_v2/{}", blake3_id);
    if Path::new(&tree_path).exists() {
        fs::remove_file(&tree_tmp).ok();
    } else {
        fs::rename(&tree_tmp, &tree_path).ok();
    }
    Some(blake3_id)
}

fn create_tree_for_file(file_path: &str) -> Option<String> {
    let file = File::open(file_path).ok()?;
    let file_size = file.metadata().ok()?.len() as usize;
    if file_size == 0 {
        return None;
    }
    let src = unsafe { Mmap::map(&file) }.ok()?;
    build_tree_from_mmap(&src, file_size, None)
}

// After a sha256 download completes, write its tree and link the blake3 path.
// Hard link is tried first; symlink as fallback; if both fail (e.g. cross-fs on
// Android) the tree still lands so a future blake3 InboundState can use it.
fn upgrade_to_blake3(public_path: &str) {
    if let Some(blake3_id) = create_tree_for_file(public_path) {
        let blake3_path = format!("./cjp2p/public/blake3/{}", blake3_id);
        if !Path::new(&blake3_path).exists() {
            fs::remove_file(&blake3_path).ok();
            if fs::hard_link(public_path, &blake3_path).is_err() {
                let name = Path::new(public_path)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy();
                std::os::unix::fs::symlink(format!("../{}", name), &blake3_path).ok();
            }
        }
        info!("upgraded {} to blake3/{}", public_path, blake3_id);
        println!("blake3: {}", blake3_id);
    }
}

fn add_sha256_link(path: &str) {
    let sha256 = match (|| -> Option<String> {
        let mut file = fs::File::open(path).ok()?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let n = file.read(&mut buf).ok()?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Some(format!("{:x}", hasher.finalize()))
    })() {
        Some(h) => h,
        None => {
            error!("add_sha256_link: failed to hash {}", path);
            return;
        }
    };
    let sha256_dest = format!("./cjp2p/public/{}", sha256);
    if !Path::new(&sha256_dest).exists() {
        fs::remove_file(&sha256_dest).ok();
        if fs::hard_link(path, &sha256_dest).is_err() {
            std::os::unix::fs::symlink(
                path.strip_prefix("./cjp2p/public/").unwrap_or(path),
                &sha256_dest,
            )
            .ok();
        }
    }
    info!("linked {} to {}", path, sha256_dest);
    println!("sha256: {}", sha256);
}

fn handle_upload(mut stream: TcpStream, req: HttpRequest) {
    let content_length: usize = req
        .headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    stream.set_nonblocking(false).ok();
    thread::spawn(move || {
        let temp_name = format!(".tmp_{:016x}", rand::rng().random::<u64>());
        let temp_path = format!("./cjp2p/public/{}", temp_name);
        let mut file = match File::create(&temp_path) {
            Ok(f) => f,
            Err(e) => {
                let body = format!("{{\"error\":\"{e}\"}}");
                let _ = stream.write_all(
                    format!("HTTP/1.0 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body).as_bytes()
                );
                return;
            }
        };
        if content_length == 0 {
            stream
                .write_all(b"HTTP/1.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .ok();
            return;
        }
        let n_leaves = (content_length + BLOCK_SIZE!() - 1) / BLOCK_SIZE!();
        let tree_tmp = format!("./cjp2p/public/.tmp_tree_{:016x}", rand::rng().random::<u64>());
        let tf = match OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&tree_tmp)
        {
            Ok(f) => f,
            Err(e) => {
                let body = format!("{{\"error\":\"{e}\"}}");
                let _ = stream.write_all(
                    format!("HTTP/1.0 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body).as_bytes()
                );
                return;
            }
        };
        let tsize = tree_file_size_v2(n_leaves);
        tf.set_len(tsize as u64).ok();
        let mut tree_mmap = unsafe { MmapMut::map_mut(&tf) }.unwrap();
        let leaf_base = tsize - n_leaves * 32;
        let mut sha256_hasher = Sha256::new();
        let mut blake3_hasher = if n_leaves == 1 {
            Some(Blake3Hasher::new())
        } else {
            None
        };
        let prefix_len = req.body_prefix.len();
        let mut written = prefix_len;
        let mut block_offset: u64 = 0;
        let mut leaf_count = 0usize;
        {
            let mut on_leaf = |cv: [u8; 32]| {
                tree_mmap[leaf_base + leaf_count * 32..leaf_base + (leaf_count + 1) * 32]
                    .copy_from_slice(&cv);
                leaf_count += 1;
            };
            let mut block = [0u8; BLOCK_SIZE!()];
            block[..prefix_len].copy_from_slice(&req.body_prefix);
            let mut fill = prefix_len;
            if prefix_len > 0 {
                file.write_all(&req.body_prefix).ok();
                sha256_hasher.update(&req.body_prefix);
                if let Some(ref mut h) = blake3_hasher {
                    h.update(&req.body_prefix);
                }
            }
            loop {
                while fill < BLOCK_SIZE!() && written < content_length {
                    let want = (BLOCK_SIZE!() - fill).min(content_length - written);
                    match stream.read(&mut block[fill..fill + want]) {
                        Ok(0) | Err(_) => {
                            written = content_length;
                            break;
                        }
                        Ok(n) => {
                            file.write_all(&block[fill..fill + n]).ok();
                            sha256_hasher.update(&block[fill..fill + n]);
                            if let Some(ref mut h) = blake3_hasher {
                                h.update(&block[fill..fill + n]);
                            }
                            fill += n;
                            written += n;
                        }
                    }
                }
                if fill == 0 {
                    break;
                }
                on_leaf(block_chaining_value(&block[..fill], block_offset));
                block_offset += fill as u64;
                fill = 0;
                if written >= content_length {
                    break;
                }
            }
        } // on_leaf dropped here, releasing &mut tree_mmap and &mut leaf_count
        drop(file);
        let sha256 = format!("{:x}", sha256_hasher.finalize());
        let blake3 = if leaf_count == 1 {
            finalize_tree_mmap_v2(&mut tree_mmap, 1);
            let h = blake3_hasher.unwrap().finalize();
            tree_mmap[32..64].copy_from_slice(h.as_bytes());
            format!("{}", h)
        } else {
            format!("{}", finalize_tree_mmap_v2(&mut tree_mmap, leaf_count).unwrap())
        };
        drop(tree_mmap);
        drop(tf);
        let blake3_dest = format!("./cjp2p/public/blake3/{}", blake3);
        if let Err(e) = fs::rename(&temp_path, &blake3_dest) {
            let body = format!("{{\"error\":\"{e}\"}}");
            let _ = stream.write_all(
                format!("HTTP/1.0 500 Internal Server Error\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}", body.len(), body).as_bytes()
            );
            fs::remove_file(&tree_tmp).ok();
            return;
        }
        let sha256_dest = format!("./cjp2p/public/{}", sha256);
        if fs::hard_link(&blake3_dest, &sha256_dest).is_err() {
            std::os::unix::fs::symlink(format!("blake3/{}", blake3), &sha256_dest).ok();
        }
        let tree_path = format!("./cjp2p/public/blake3_tree_v2/{}", blake3);
        if Path::new(&tree_path).exists() {
            fs::remove_file(&tree_tmp).ok();
        } else {
            fs::rename(&tree_tmp, &tree_path).ok();
        }
        println!("upload: {} bytes -> blake3:{} sha256:{}", written, blake3, sha256);
        let body = format!("{{\"sha256\":\"{sha256}\",\"blake3\":\"{blake3}\"}}");
        let _ = stream.write_all(
            format!("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}", body.len(), body).as_bytes()
        );
    });
}
fn handle_publish_origin(mut stream: TcpStream, req: HttpRequest) {
    let raw_filename = req.headers.get("x-filename").cloned().unwrap_or_default();
    let filename = urlencoding::decode(&raw_filename)
        .unwrap_or_default()
        .to_string();
    if filename.is_empty() {
        stream
            .write_all(b"HTTP/1.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .ok();
        return;
    }
    let content_length: usize = req
        .headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    println!("publish_origin: start filename={:?} content_length={} body_prefix={}",
        filename, content_length, req.body_prefix.len());
    stream.set_nonblocking(false).ok();
    thread::spawn(move || {
        let temp_name = format!(".tmp_{:016x}", rand::rng().random::<u64>());
        fs::create_dir_all("./cjp2p/origin").ok();
        let temp_path = format!("./cjp2p/origin/{}", temp_name);
        let dest_path = format!("./cjp2p/origin/{}", filename);
        if let Some(parent) = Path::new(&dest_path).parent() {
            fs::create_dir_all(parent).ok();
        }
        let mut file = match File::create(&temp_path) {
            Ok(f) => f,
            Err(e) => {
                println!("publish_origin: File::create failed: {e}");
                let body = format!("{{\"error\":\"{e}\"}}");
                let _ = stream.write_all(
                    format!("HTTP/1.0 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body).as_bytes()
                );
                return;
            }
        };
        let mut written = 0usize;
        if !req.body_prefix.is_empty() {
            file.write_all(&req.body_prefix).ok();
            written += req.body_prefix.len();
        }
        let mut buf = [0u8; 65536];
        let mut stop_reason = "complete";
        while written < content_length {
            let to_read = (content_length - written).min(buf.len());
            match stream.read(&mut buf[..to_read]) {
                Ok(0) => {
                    stop_reason = "eof";
                    break;
                }
                Ok(n) => {
                    if file.write_all(&buf[..n]).is_err() {
                        stop_reason = "write_err";
                        break;
                    }
                    written += n;
                }
                Err(e) => {
                    println!("publish_origin: read error after {}B: {e}", written);
                    stop_reason = "read_err";
                    break;
                }
            }
        }
        println!("publish_origin: read done written={} content_length={} stop={}", written, content_length, stop_reason);
        drop(file);
        if let Err(e) = fs::rename(&temp_path, &dest_path) {
            fs::remove_file(&temp_path).ok();
            println!("publish_origin: rename failed: {e}");
            let body = format!("{{\"error\":\"{e}\"}}");
            let _ = stream.write_all(
                format!("HTTP/1.0 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body).as_bytes()
            );
            return;
        }
        let escaped = filename.replace('"', "\\\"");
        let body = format!("{{\"filename\":\"{escaped}\"}}");
        let resp = format!("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
        match stream.write_all(resp.as_bytes()) {
            Ok(_) => println!("publish_origin: ok -> cjp2p/origin/{}", filename),
            Err(e) => println!("publish_origin: response write failed: {e} (file was written ok)"),
        }
    });
}
fn get_local_ip_for_gateway(gateway_ip: Ipv4Addr) -> Ipv4Addr {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind failed");
    socket.connect((gateway_ip, 1900)).expect("connect failed");
    socket
        .local_addr()
        .expect("local_addr failed")
        .ip()
        .to_string()
        .parse()
        .expect("parse failed")
}

// Find the IPv6 default gateway and its interface index via netlink RTM_GETROUTE.
// This uses the kernel's routing socket API, which works on Linux and Android alike.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn pcp_find_ipv6_gateway() -> Option<(Ipv6Addr, u32)> {
    use nix::sys::socket::{
        bind, recvfrom, sendto, socket, AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockType,
    };

    const RTM_GETROUTE: u16 = 26;
    const RTM_NEWROUTE: u16 = 24;
    const NLM_F_REQUEST: u16 = 0x01;
    // NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH
    const NLM_F_DUMP: u16 = 0x300;
    const NLMSG_DONE: u16 = 3;
    const AF_INET6: u8 = 10;
    // rtattr types for routes
    const RTA_OIF: u16 = 4;
    const RTA_GATEWAY: u16 = 5;

    let sock = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        None, // NETLINK_ROUTE = 0
    )
    .ok()?;

    bind(sock.as_raw_fd(), &NetlinkAddr::new(0, 0)).ok()?;

    // nlmsghdr (16 bytes) + rtmsg (12 bytes) = 28 bytes
    let mut req = [0u8; 28];
    req[0..4].copy_from_slice(&28u32.to_ne_bytes()); // nlmsg_len
    req[4..6].copy_from_slice(&RTM_GETROUTE.to_ne_bytes()); // nlmsg_type
    req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes()); // nlmsg_flags
    req[8..12].copy_from_slice(&1u32.to_ne_bytes()); // nlmsg_seq
                                                     // nlmsg_pid = 0 (kernel)
    req[16] = AF_INET6; // rtm_family; rest of rtmsg = 0

    sendto(
        sock.as_raw_fd(),
        &req,
        &NetlinkAddr::new(0, 0),
        MsgFlags::empty(),
    )
    .ok()?;

    let mut best_gw: Option<Ipv6Addr> = None;
    let mut best_oif: u32 = 0;

    'recv: loop {
        let mut buf = vec![0u8; 8192];
        let (n, _) = recvfrom::<NetlinkAddr>(sock.as_raw_fd(), &mut buf).ok()?;

        let mut pos = 0usize;
        while pos + 16 <= n {
            let nlmsg_len = u32::from_ne_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
            let nlmsg_type = u16::from_ne_bytes(buf[pos + 4..pos + 6].try_into().unwrap());

            if nlmsg_type == NLMSG_DONE {
                break 'recv;
            }
            if nlmsg_len < 16 || pos + nlmsg_len > n {
                break;
            }

            if nlmsg_type == RTM_NEWROUTE && nlmsg_len >= 28 {
                let rtm_family = buf[pos + 16];
                let rtm_dst_len = buf[pos + 17]; // 0 = default route

                if rtm_family == AF_INET6 && rtm_dst_len == 0 {
                    let mut ap = pos + 28; // rtattrs start after nlmsghdr+rtmsg
                    let end = pos + nlmsg_len;
                    let mut gw: Option<Ipv6Addr> = None;
                    let mut oif: u32 = 0;

                    while ap + 4 <= end {
                        let rta_len =
                            u16::from_ne_bytes(buf[ap..ap + 2].try_into().unwrap()) as usize;
                        let rta_type = u16::from_ne_bytes(buf[ap + 2..ap + 4].try_into().unwrap());
                        if rta_len < 4 || ap + rta_len > end {
                            break;
                        }
                        let data = &buf[ap + 4..ap + rta_len];
                        if rta_type == RTA_GATEWAY && data.len() == 16 {
                            let arr: [u8; 16] = data.try_into().unwrap();
                            gw = Some(Ipv6Addr::from(arr));
                        } else if rta_type == RTA_OIF && data.len() == 4 {
                            oif = u32::from_ne_bytes(data.try_into().unwrap());
                        }
                        ap += (rta_len + 3) & !3; // align to 4 bytes
                    }

                    if let Some(g) = gw {
                        best_gw = Some(g);
                        best_oif = oif;
                    }
                }
            }

            pos += (nlmsg_len + 3) & !3;
        }
    }

    best_gw.map(|gw| (gw, best_oif))
}

// No netlink off Linux, so PCP skips IPv6 gateway discovery.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn pcp_find_ipv6_gateway() -> Option<(Ipv6Addr, u32)> {
    None
}

// The local IPv6 address the kernel would use to reach the wider network. Connecting a UDP
// socket picks the source address for that route without sending anything, which needs no
// netlink, so this works the same off Linux.
fn local_ipv6_source() -> Option<Ipv6Addr> {
    let s = UdpSocket::bind("[::]:0").ok()?;
    s.connect("[2001:4860:4860::8888]:53").ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V6(v6) => Some(v6),
        _ => None,
    }
}

// SSDP M-SEARCH for WANIPv6FirewallControl, then parse the device description to get the
// control URL. Returns the full absolute HTTP URL for the control endpoint.
fn upnp_ipv6_find_service() -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();

    let msearch = concat!(
        "M-SEARCH * HTTP/1.1\r\n",
        "HOST: 239.255.255.250:1900\r\n",
        "MAN: \"ssdp:discover\"\r\n",
        "MX: 3\r\n",
        "ST: urn:schemas-upnp-org:service:WANIPv6FirewallControl:1\r\n",
        "\r\n"
    );
    sock.send_to(msearch.as_bytes(), "239.255.255.250:1900")
        .ok()?;

    let mut buf = [0u8; 2048];
    let (n, _) = sock.recv_from(&mut buf).ok()?;
    let resp = std::str::from_utf8(&buf[..n]).unwrap_or("");

    // Extract LOCATION header value (case-insensitive), preserving the full URL.
    let location = resp
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("location:"))?
        .splitn(2, ' ')
        .nth(1)
        .map(|s| s.trim().to_string())?;
    debug!("UPnP IPv6: device description at {location}");

    let xml = upnp_http_get(&location)?;

    // Find the WANIPv6FirewallControl service block and extract its controlURL.
    let svc_idx = xml.find("WANIPv6FirewallControl:1")?;
    let after = &xml[svc_idx..];
    let cs = after.find("<controlURL>")? + "<controlURL>".len();
    let ce = after[cs..].find("</controlURL>")?;
    let ctrl_path = after[cs..cs + ce].trim();

    // Build absolute URL from the description base URL.
    let base = {
        let rest = location.strip_prefix("http://")?;
        let slash = rest.find('/').unwrap_or(rest.len());
        format!("http://{}", &rest[..slash])
    };

    let control_url = if ctrl_path.starts_with("http://") {
        ctrl_path.to_string()
    } else if ctrl_path.starts_with('/') {
        format!("{base}{ctrl_path}")
    } else {
        format!("{base}/{ctrl_path}")
    };

    Some(control_url)
}

fn upnp_http_get(url: &str) -> Option<String> {
    let rest = url.strip_prefix("http://")?;
    let (host_port, path_rest) = rest.split_once('/').unwrap_or((rest, ""));
    let path = format!("/{path_rest}");
    let mut stream = TcpStream::connect(host_port).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp).ok()?;
    resp.find("\r\n\r\n").map(|i| resp[i + 4..].to_string())
}

fn upnp_soap_post(url: &str, action: &str, body: &str) -> Option<String> {
    let rest = url.strip_prefix("http://")?;
    let (host_port, path_rest) = rest.split_once('/').unwrap_or((rest, ""));
    let path = format!("/{path_rest}");
    let mut stream = TcpStream::connect(host_port).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let req = format!(
        "POST {path} HTTP/1.0\r\nHost: {host_port}\r\nContent-Type: text/xml\r\nSOAPAction: \"{action}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp).ok()?;
    resp.find("\r\n\r\n").map(|i| resp[i + 4..].to_string())
}

fn parse_args() -> (u16, u16, Vec<String>) {
    let mut lcdp_port: u16 = 24254;
    let mut http_port: u16 = 24255;
    let raw_args: Vec<String> = env::args().skip(1).collect();
    let mut file_args: Vec<String> = Vec::new();
    let mut i = 0;
    while i < raw_args.len() {
        match raw_args[i].as_str() {
            "--help" | "-h" => {
                println!("Usage: cjp2p [OPTIONS] [FILES...]");
                println!();
                println!("Options:");
                println!("  --lcdp-port PORT   UDP port for p2p traffic (default: 24254)");
                println!("  --http-port PORT  HTTP port for web console (default: 24255)");
                println!("  --help            Show this help message");
                println!();
                println!("Files: hash IDs to download");
                std::process::exit(0);
            }
            "--lcdp-port" => {
                i += 1;
                lcdp_port = raw_args
                    .get(i)
                    .expect("--lcdp-port requires a value")
                    .parse()
                    .expect("--lcdp-port must be a valid port number");
            }
            "--http-port" => {
                i += 1;
                http_port = raw_args
                    .get(i)
                    .expect("--http-port requires a value")
                    .parse()
                    .expect("--http-port must be a valid port number");
            }
            _ => {
                file_args.push(raw_args[i].clone());
            }
        }
        i += 1;
    }
    (lcdp_port, http_port, file_args)
}

pub fn run() -> Result<(), std::io::Error> {
    env_logger::builder()
        .format_timestamp(Some(TimestampPrecision::Millis))
        .init();
    println!("logging level: {}", log::max_level());
    let (lcdp_port, http_port, file_args) = parse_args();
    run_engine(lcdp_port, http_port, file_args)
}

/// Called from the Tauri crate's JNI entry point on Android.
/// Sets cwd, initialises logging, then starts the engine.
pub fn run_from_android(data_dir: &str, lcdp_port: u16, http_port: u16) {
    if !data_dir.is_empty() {
        std::env::set_current_dir(data_dir).ok();
    }
    env_logger::builder()
        .format_timestamp(Some(TimestampPrecision::Millis))
        .try_init()
        .ok();
    let _ = run_engine(lcdp_port, http_port, vec![]);
}

fn run_engine(
    lcdp_port: u16,
    http_port: u16,
    file_args: Vec<String>,
) -> Result<(), std::io::Error> {
    let mut ps: PeerState = PeerState::new(lcdp_port, http_port);
    let bind_addr = if Path::new(".allow_remote_http").exists() {
        format!("0.0.0.0:{http_port}")
    } else {
        format!("127.0.0.1:{http_port}")
    };
    let web_server = TcpListener::bind(&bind_addr).unwrap();
    SockRef::from(&web_server)
        .set_send_buffer_size(0x400000)
        .ok();
    let sndbuf = SockRef::from(&web_server).send_buffer_size().unwrap();
    if sndbuf < 0x40000 {
        warn!("sndbuf  = {:?}",sndbuf);
    }
    println!("your ed25519 public key, stored in cjp2p/state/key.v2.json, is:  0x{}", ps.keypair.public);
    println!("BUILD_VERSION {}", env!("BUILD_VERSION"));
    println!("OS {}", std::env::consts::OS);
    println!("web console at        http://127.0.0.1:{http_port}/");
    println!("{HELP_TEXT}");
    announce_version_change(&mut ps);
    let pub_hex = ps.keypair.public.to_string();
    let mut inbound_states: HashMap<String, InboundState> = HashMap::new();
    let mut stream_states: HashMap<String, StreamState> = HashMap::new();
    for v in file_args {
        let path = Path::new(&v);
        if path.is_dir() {
            let dir_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .expect("directory argument has no usable name");
            let link = format!("./cjp2p/origin/{}", dir_name);
            let abs = fs::canonicalize(path).expect("could not resolve directory path");
            if Path::new(&link).exists() {
                println!("symlink already exists: {}", link);
            } else {
                std::os::unix::fs::symlink(&abs, &link)
                    .expect("failed to create symlink in cjp2p/origin/");
                println!("symlinked {} -> {}", link, abs.display());
            }
            println!(
                "serve files from this directory at:  http://127.0.0.1:{http_port}/latest/0x{pub_hex}/{dir_name}/<filename>"
            );
        } else {
            info!("queing inbound file {:?}", v);
            InboundState::new(&v, &mut ps, &mut inbound_states);
        }
    }

    let stdin = std::io::stdin();
    let mut stdin_open = true;
    let tty_state: Option<(OwnedFd, std::sync::mpsc::Receiver<Option<String>>)> =
        if stdin.is_terminal() {
            unsafe {
                let mut t: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(libc::STDIN_FILENO, &mut t) == 0 {
                    SAVED_TERMIOS.set(t).ok();
                }
            }
            let mut pipe_fds = [-1i32; 2];
            if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } == 0 {
                let pipe_read = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
                let pipe_write_raw = pipe_fds[1];
                let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
                let rl_peer_count_thread = std::sync::Arc::clone(&ps.active_peer_count);
                let rl_pub_prefix: String = pub_hex.chars().take(5).collect();
                let rl_git_hash: &str = option_env!("GIT_HASH").unwrap_or("nogit");
                std::thread::spawn(move || {
                    let mut rl = match rustyline::DefaultEditor::new() {
                        Ok(e) => e,
                        Err(_) => {
                            unsafe {
                                libc::close(pipe_write_raw);
                            }
                            return;
                        }
                    };
                    loop {
                        let n = rl_peer_count_thread.load(std::sync::atomic::Ordering::Relaxed);
                        let prompt = format!("[pub:{} ver:{} peers:{}] ", rl_pub_prefix, rl_git_hash, n);
                        match rl.readline(&prompt) {
                            Ok(line) => {
                                let _ = rl.add_history_entry(&line);
                                let _ = tx.send(Some(line));
                                unsafe {
                                    libc::write(
                                        pipe_write_raw,
                                        b"x".as_ptr() as *const libc::c_void,
                                        1,
                                    );
                                }
                            }
                            Err(rustyline::error::ReadlineError::Interrupted) => {
                                restore_terminal();
                                unsafe {
                                    libc::raise(libc::SIGINT);
                                }
                            }
                            Err(_) => {
                                let _ = tx.send(None);
                                unsafe {
                                    libc::write(
                                        pipe_write_raw,
                                        b"x".as_ptr() as *const libc::c_void,
                                        1,
                                    );
                                }
                                break;
                            }
                        }
                    }
                    unsafe {
                        libc::close(pipe_write_raw);
                    }
                });
                Some((pipe_read, rx))
            } else {
                None
            }
        } else {
            None
        };
    'main: loop {
        let mut read_fds = FdSet::new();
        let mut write_fds = FdSet::new();
        maintenance(&mut stream_states, &mut inbound_states, &mut ps);
        read_fds.insert(ps.socket.as_fd());
        read_fds.insert(web_server.as_fd());
        if stdin_open {
            match &tty_state {
                Some((pipe_read, _)) => read_fds.insert(pipe_read.as_fd()),
                None => read_fds.insert(stdin.as_fd()),
            }
        }

        for cg in &ps.content_gateways {
            let fd = cg.http_socket.as_fd();
            if cg.waiting_for_browser {
                write_fds.insert(fd);
            }
        }
        for hc in &ps.http_clients {
            read_fds.insert(hc.as_fd());
        }
        for ws in &ps.ws_vec {
            read_fds.insert(ws.get_ref().as_fd());
        }
        let tv_1 = &mut (nix::sys::time::TimeVal::new(0, 313187));
        if select(None, &mut read_fds, &mut write_fds, None, tv_1).is_err() {
            continue 'main;
        }
        ps.last_cookie = None;
        ps.last_always_returned = None;

        for (index, cg) in ps.content_gateways.iter().enumerate() {
            if write_fds.contains(cg.http_socket.as_fd()) {
                debug!("handling cg {} {} {} ",cg.http_done,cg.waiting_for_browser,cg.sent_header);
                ps.serve_http_content(&mut stream_states, &mut inbound_states, index);
                continue 'main;
            }
        }

        // Kick /latest/ gateways whose 300ms grace window has closed.
        for (index, cg) in ps.content_gateways.iter().enumerate() {
            if let Some(l) = &cg.pending_latest {
                if !cg.id.is_empty() && l.delay_for_newest_until.map_or(true, |t| has_passed(t)) {
                    ps.serve_http_content(&mut stream_states, &mut inbound_states, index);
                    continue 'main;
                }
            }
        }

        for (k, ws) in ps.ws_vec.iter().enumerate() {
            if read_fds.contains(ws.get_ref().as_fd()) {
                debug!("handling ws vec");
                ps.handle_websocket2(k, &mut stream_states, &mut inbound_states);
                continue 'main;
            }
        }

        {
            let stdin_triggered = match &tty_state {
                Some((pipe_read, _)) => read_fds.contains(pipe_read.as_fd()),
                None => read_fds.contains(stdin.as_fd()),
            };
            if stdin_triggered {
                debug!("handling stdin");
                let keep_open = if let Some((pipe_read, rx)) = &tty_state {
                    let mut buf = [0u8; 1];
                    unsafe {
                        libc::read(
                            pipe_read.as_raw_fd(),
                            buf.as_mut_ptr() as *mut libc::c_void,
                            1,
                        );
                    }
                    match rx.try_recv() {
                        Ok(Some(line)) => {
                            handle_line(&line, &mut ps, &mut stream_states, &mut inbound_states);
                            true
                        }
                        Ok(None) => false,
                        Err(std::sync::mpsc::TryRecvError::Empty) => true,
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => false,
                    }
                } else {
                    handle_stdin(&mut ps, &mut stream_states, &mut inbound_states)
                };
                if !keep_open {
                    stdin_open = false;
                }
                continue 'main;
            }
        }
        if read_fds.contains(web_server.as_fd()) {
            debug!("handling new http");
            if let Ok((stream, _)) = web_server.accept() {
                stream.set_nonblocking(true).unwrap();
                ps.http_clients.push(stream);
            }
            continue 'main;
        }
        for (k, hc) in ps.http_clients.iter().enumerate() {
            if read_fds.contains(hc.as_fd()) {
                debug!("handling http");
                handle_web_request(k, &mut stream_states, &mut inbound_states, &mut ps);
                continue 'main;
            }
        }
        if read_fds.contains(ps.socket.as_fd()) {
            trace!("handling network");
            handle_network(&mut ps, &mut stream_states, &mut inbound_states);
        }
    }
}

fn print_group_chat_msg(pub_key_hex: &str, msg: &GroupChatMessage) {
    let ts = chrono::DateTime::from_timestamp_millis(msg.timestamp)
        .map(|dt: chrono::DateTime<chrono::Utc>| dt.to_rfc3339())
        .unwrap_or_else(|| format!("{}", msg.timestamp));
    let mut pub_str = String::new();
    for c in pub_key_hex.chars().take(5) {
        let nibble = u8::from_str_radix(&c.to_string(), 16).unwrap_or(0);
        let color = 30u8 + (nibble & 7);
        if nibble & 8 != 0 {
            pub_str.push_str(&format!("\x1b[7;{color}m{c}"));
        } else {
            pub_str.push_str(&format!("\x1b[m\x1b[{color}m{c}"));
        }
    }
    pub_str.push_str("\x1b[m");
    println!("[{ts}] {pub_str}... #{}: \x1b[7m{}\x07\x1b[m",
        msg.group_name, msg.text);
}

fn handle_stdin(
    ps: &mut PeerState,
    stream_states: &mut HashMap<String, StreamState>,
    inbound_states: &mut HashMap<String, InboundState>,
) -> bool {
    let mut line = String::new();
    let n = io::stdin().read_line(&mut line).unwrap_or(0);
    if n == 0 {
        return false;
    }
    let line = line.trim_end_matches('\n');
    if line.is_empty() {
        return true;
    }
    handle_line(line, ps, stream_states, inbound_states);
    true
}

fn handle_line(
    line: &str,
    ps: &mut PeerState,
    stream_states: &mut HashMap<String, StreamState>,
    inbound_states: &mut HashMap<String, InboundState>,
) {
    if line.is_empty() {
        return;
    }
    let mut line = line.to_string();
    let mut arg: String = "".to_string();
    let mut arg2: String = "".to_string();
    if sscanf!(line.as_str(), "/get {}",arg).is_ok() {
        println!("QUEING FILE {arg}");
        InboundState::new(&arg, ps, inbound_states);
    } else if line == "/quit" {
        ps.save_peers();
        ps.p.save();
        restore_terminal();
        std::process::exit(0);
    } else if sscanf!(line.as_str(), "/test {} {}",arg,arg2).is_ok() {
        println!("this command is undocummmented because it will hang the node, your internet connection, and probably piss off your ISP.  Hetzner sent me an abuse email demaning an explaination almost immediately after I tried it there. DO NOT USE THIS!!  (Though Hetzner did not lose any traffic, unlike my cheap home router)");
        // the issue is that, i have found, many cheap home "routers" top out at 1Mbps when talking to various IPs due to some sort of "Connection" tracking, even if you are the DMZ, or even if you use ipv6 to avoid NAT.
        // it's structural censorship, or "protocol discrimination"
        let rate: u64 = arg2.parse().unwrap();
        ps.socket.set_nonblocking(false).unwrap();
        if arg == "4" {
            std::process::Command::new("ping")
                .arg("-c50")
                .arg("-i.2")
                .arg("8.8.8.8")
                .spawn()
                .ok();
        } else {
            std::process::Command::new("ping6")
                .arg("-c50")
                .arg("-i.2")
                .arg("2001:4860:4860::8888")
                .spawn()
                .ok();
        };
        'outer: for c in 0..255u64 {
            for d in 0..255u64 {
                let s = if arg == "4" {
                    // 100.64/10 reserved for CGNAT so wont piss off anyone but your ISP at most, not ideal really, port 6881 is bitttorent
                    SocketAddr::from(([100, 100, c as u8, d as u8], 6881))
                } else {
                    // 2001:db8::${i} 2001:db8::/31 supposedly black hole route
                    SocketAddr::from((
                        [0x2001, 0xdb8, 0, ((c as u16) << 8) + (d as u16), 0, 0, 0, 1],
                        6881,
                    ))
                };
                ps.socket.send_to(&[], s).ok();
                if ((c << 8) + d) % (rate / 500) == 0 {
                    std::thread::sleep(Duration::from_millis(2));
                    let sent = (c << 8) + d;
                    print!("sent {}\r",sent);
                    if sent > rate * 4 {
                        break 'outer;
                    }
                }
            }
        }
        ps.socket.set_nonblocking(true).unwrap();
    } else if line == "/save" {
        ps.save_peers();
        ps.p.save();
    } else if sscanf!(line.as_str(), "/addpeer {}",arg).is_ok() {
        let mut pi = PeerInfo::new();
        pi.delay = Duration::ZERO;
        ps.peer_map.insert(arg.parse().unwrap(), pi);
    } else if line.starts_with("/msg ") {
        let rest = line[5..].trim_start();
        if let Some((addr, msg)) = rest.split_once(char::is_whitespace) {
            let msg = msg.trim_start();
            if addr.starts_with("0x") {
                if let Ok(pub_key) = addr[2..].parse::<Ed25519Pub>() {
                    chat_to_pub(ps, pub_key, &msg.to_string());
                }
            } else if let Ok(dst) = addr.parse() {
                let mut message_out = ChatMessage::new(&ps, msg.to_string());
                message_out.append(&mut ps.always_returned(dst));
                if let Some(pi) = &ps.peer_map.get(&dst) {
                    if let Some(their_pub) = &pi.ed25519 {
                        message_out = vec![
                                EncryptedMessages::new(ps,their_pub, serde_json::to_vec(&message_out).unwrap()),
                                //FastEncryptedMessages::new(ps,their_pub, serde_json::to_vec(&message_out).unwrap()),
                                ];
                    }
                }
                let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
                trace!( "sending message {:?} to {addr}", String::from_utf8_lossy(&message_out_bytes));
                ps.socket.send_to(&message_out_bytes, addr).ok();
            }
        }
    } else if line == "/peers" {
        println!("========== active peer/ports");
        for v in ps.peer_vec.iter().rev() {
            let Some(peer) = ps.peer_map.get(v) else {
                error!("/peers: {v} in peer_vec but not in peer_map, skipping, this shouldnt happen");
                continue;
            };
            let d = peer.delay;
            if d < Duration::from_secs(1) {
                println!("{:21?} {}",
                            d,
                            v);
            }
        }
        println!("{} total peers", ps.peer_map_by_pub.len());
        let mut unique_ips = HashSet::new();
        for (k, _) in &ps.peer_map {
            unique_ips.insert(k.ip());
        }
        let mut apbp = ps.active_peers_from_pub_map();
        apbp.sort_by_key(|(_, _, d)| std::cmp::Reverse(*d));
        thread::spawn(move || {
            println!("========== all IPs");
            for k in &unique_ips {
                println!("{:21} {}",k,if let Ok(hn)= dns_lookup::lookup_addr(&k) { hn } else { k.to_string()});
            }
            println!("{} total unique IP peers.  ",unique_ips.len());
            println!("========== active peers by pub key");
            for (sa, pub_, delay) in &apbp {
                println!("{:21?} {:21} 0x{}", delay, sa.to_string(), pub_);
            }
            println!("{} active by pub", apbp.len());
        });
    } else if line == "/websockets" {
        println!("{} websocket(s) connected", ps.ws_vec.len());
    } else if sscanf!(line.as_str(), "/recommend {}",arg).is_ok() {
        ps.p.you_should_see_this = Some(YouShouldSeeThis {
            id: arg.to_owned(),
            length: File::open("./cjp2p/public/".to_owned() + &arg)
                .unwrap()
                .metadata()
                .unwrap()
                .len(),
        });
    } else if line == "/pending" {
        println!("{} pending",inbound_states.len());
        for (_, i) in inbound_states.iter_mut() {
            println!("pending download {} {}/{}",i.id,i.bytes_complete,i.eof);
        }
        for (_, i) in stream_states.iter_mut() {
            println!("streaming {} {}",i.id,i.data_file_len);
        }
        for cg in &ps.content_gateways {
            println!("content_gateway {}",cg.id);
        }
    } else if line == "/trending" {
        let mut trending: HashMap<String, (i32, u64)> = HashMap::new();
        for (_, v) in &ps.peer_map {
            if let Some(p) = &v.i_just_saw_this {
                match trending.get_mut(&p.id) {
                    Some(h) => h.0 += 1,
                    None => {
                        trending.insert(p.id.to_owned(), (1, p.length));
                        ()
                    }
                }
            }
        }
        let mut sorted_list_results: Vec<_> = trending.iter().collect();
        sorted_list_results.sort_by_key(|&(_, b)| b.0);
        for (k, v) in &sorted_list_results {
            println!("{} {} {}",v.0,k,v.1);
        }
    } else if line == "/recommended" {
        let mut highly_recommended_content: HashMap<String, (i32, u64)> = HashMap::new();
        for (_, v) in &ps.peer_map {
            if let Some(p) = &v.you_should_see_this {
                match highly_recommended_content.get_mut(&p.id) {
                    Some(h) => h.0 += 1,
                    None => {
                        highly_recommended_content.insert(p.id.to_owned(), (1, p.length));
                        ()
                    }
                }
            }
        }
        let mut sorted_list_results: Vec<_> = highly_recommended_content.iter().collect();
        sorted_list_results.sort_by_key(|&(_, b)| b.0);
        for (k, v) in &sorted_list_results {
            println!("{} {} {}",v.0,k,v.1);
        }
    } else if line == "/list" {
        ps.list_results = HashMap::new();
        ps.list_time = Instant::now();
        println!("searching");
        for sa in &ps.peer_vec {
            let mut message_out = ps.always_returned(*sa);
            for v in PleaseListContent::new(&ps) {
                message_out.push(v);
            }
            let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
            trace!( "sending message {:?} to {sa}", String::from_utf8_lossy(&message_out_bytes));
            ps.socket.send_to(&message_out_bytes, sa).ok();
        }
    } else if line == "/update" {
        let exe = env::current_exe().unwrap();
        let args: Vec<String> = env::args().collect();
        let bundle_url =
            format!("http://127.0.0.1:{}/latest/{SPECIAL_PUB}/cjp2p.bundle",ps.http_port);
        thread::spawn(move || {
            info!("exe: {}",exe.to_string_lossy());
            if !exe.to_string_lossy().contains("/target/") {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                let meta = match std::fs::metadata(&exe) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("/update: stat failed: {e}");
                        return;
                    }
                };
                if meta.uid() == 0 && unsafe { libc::getuid() } != 0 {
                    eprintln!("/update: binary is owned by root but running as a regular user -- re-run as root to update");
                    return;
                }
                let os = std::env::consts::OS;
                let arch = std::env::consts::ARCH;
                let bin_name = format!("cjp2p-{os}-{arch}");
                let url = format!("https://github.com/kermit4/cjp2p-rust/releases/latest/download/{bin_name}");
                let tmp = exe.with_extension("tmp");
                eprintln!("/update: downloading {url}");
                let status = std::process::Command::new("wget")
                    .args(["-q", "-O", tmp.to_str().unwrap(), url.as_str()])
                    .status()
                    .expect("wget failed");
                if !status.success() {
                    eprintln!("/update: wget failed");
                    let _ = std::fs::remove_file(&tmp);
                    return;
                }
                let mut perms = std::fs::metadata(&tmp).unwrap().permissions();
                perms.set_mode(0o755);
                let _ = std::fs::set_permissions(&tmp, perms);
                let bak = exe.with_extension("bak");
                if let Err(e) = std::fs::rename(&exe, &bak) {
                    eprintln!("/update: failed to back up old binary: {e}");
                    let _ = std::fs::remove_file(&tmp);
                    return;
                }
                if let Err(e) = std::fs::rename(&tmp, &exe) {
                    eprintln!("/update: failed to move new binary into place: {e}");
                    let _ = std::fs::rename(&bak, &exe);
                    return;
                }
                eprintln!("/update: updated, restarting");
                restore_terminal();
                let _ = std::process::Command::new(&exe).args(&args[1..]).exec();
            } else {
                let status = std::process::Command::new("wget")
                    .args(["-q", "-O", "bundle", bundle_url.as_str()])
                    .status()
                    .expect("wget failed");
                if !status.success() {
                    eprintln!("wget cjp2p.bundle failed: {}", status);
                    return;
                }
                let status = std::process::Command::new("git")
                    .args(["pull", "bundle", "master"])
                    .status()
                    .expect("git pull failed");
                if !status.success() {
                    eprintln!("git pull bundle master failed: {}", status);
                    return;
                }
                let status = std::process::Command::new("make")
                    .status()
                    .expect("make failed");
                if !status.success() {
                    eprintln!("make failed: {}", status);
                    return;
                }
                restore_terminal();
                let _ = std::process::Command::new(&exe).args(&args[1..]).exec();
            }
        });
    } else if line == "/help" {
        println!("{HELP_TEXT}");
    } else if sscanf!(line.as_str(), "/publish {}", arg).is_ok() {
        let src = std::path::Path::new(&arg);
        let file_name = match src.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_owned(),
            None => {
                println!("publish: can't determine filename from {arg}");
                return;
            }
        };
        let dest = format!("./cjp2p/origin/{}", file_name);
        let tmp = format!("./cjp2p/origin/.tmp.{}", file_name);
        let tmp_path = std::path::Path::new(&tmp);
        if fs::hard_link(src, tmp_path).is_ok() {
            println!("publish: hard linked");
        } else if std::os::unix::fs::symlink(
            fs::canonicalize(src).unwrap_or_else(|_| src.to_path_buf()),
            tmp_path,
        )
        .is_ok()
        {
            println!("publish: symlinked");
        } else if fs::copy(src, tmp_path).is_ok() {
            println!("publish: copied");
        } else {
            println!("publish: all methods failed for {arg}");
            return;
        }
        if let Err(e) = fs::rename(tmp_path, &dest) {
            let _ = fs::remove_file(tmp_path);
            println!("publish: rename failed: {e}");
            return;
        }
        println!("http://localhost:{}/latest/0x{}/{}", ps.http_port, ps.keypair.public, file_name);
    } else if sscanf!(line.as_str(), "/share {}", arg).is_ok() {
        let path = arg.clone();
        let http_port = ps.http_port;
        thread::spawn(move || {
            let src_file = match File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    println!("share: {path}: {e}");
                    return;
                }
            };
            let file_size = match src_file.metadata() {
                Ok(m) => m.len() as usize,
                Err(e) => {
                    println!("share: metadata: {e}");
                    return;
                }
            };
            if file_size == 0 {
                println!("share: empty file");
                return;
            }
            println!("hashing: {path} {file_size}");
            let src = match unsafe { Mmap::map(&src_file) } {
                Ok(m) => m,
                Err(e) => {
                    println!("share: mmap: {e}");
                    return;
                }
            };
            let mut sha256_hasher = Sha256::new();
            let blake3 = match build_tree_from_mmap(&src, file_size, Some(&mut sha256_hasher)) {
                Some(id) => id,
                None => {
                    error!("share: build_tree failed");
                    return;
                }
            };
            let sha256 = format!("{:x}", sha256_hasher.finalize());
            let blake3_dest = format!("./cjp2p/public/blake3/{}", blake3);
            if !Path::new(&blake3_dest).exists() {
                fs::remove_file(&blake3_dest).ok();
                let abs =
                    fs::canonicalize(&path).unwrap_or_else(|_| std::path::PathBuf::from(&path));
                if fs::hard_link(&path, &blake3_dest).is_err() {
                    std::os::unix::fs::symlink(&abs, &blake3_dest).ok();
                }
            }
            let sha256_dest = format!("./cjp2p/public/{}", sha256);
            if !Path::new(&sha256_dest).exists() {
                fs::remove_file(&sha256_dest).ok();
                if fs::hard_link(&blake3_dest, &sha256_dest).is_err() {
                    std::os::unix::fs::symlink(format!("blake3/{}", blake3), &sha256_dest).ok();
                }
            }
            println!("{path} is shared at http://localhost:{http_port}/blake3/{blake3}");
            println!("  sha256: http://localhost:{http_port}/{sha256}");
        });
    } else if line.starts_with("/ping") || line.starts_with("/version") {
        let peers = ps.best_peers(100, 5);
        info!("spamming  {} peers",peers.len());
        for sa in peers {
            let mut message_out = ChatMessage::new(&ps, line.clone());
            message_out.append(&mut ps.always_returned(sa));
            // no point in encrypting spam
            let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
            trace!( "sending message {:?} to {sa}", String::from_utf8_lossy(&message_out_bytes));
            ps.socket.send_to(&message_out_bytes, sa).ok();
        }
    } else {
        let mut group_name = ps.last_group.clone();
        let _ = sscanf!(line.as_str(), "/g #{} {}", group_name, line).is_ok()
            || sscanf!(line.as_str(), "/g {}", line).is_ok();
        ps.last_group = group_name.clone();
        GroupChatMessage::send(ps, group_name, line);
    }
}
fn status_json(ps: &PeerState, mut stream: TcpStream) {
    let public_key = format!("0x{}", ps.keypair.public);
    let total_peers = ps.peer_map.len();

    let active_peers: Vec<serde_json::Value> = ps.active_peers_from_pub_map()
        .into_iter()
        .map(|(sa, pub_, delay)| json!({
            "addr": sa.to_string(),
            "pub": format!("0x{}", pub_),
            "delay_ms": delay.as_millis(),
        }))
        .collect();

    let mut seen_ips: HashSet<IpAddr> = HashSet::new();
    let unique_ips: usize = ps
        .peer_map
        .keys()
        .filter(|k| seen_ips.insert(k.ip()))
        .count();

    let fast_peer_count = ps
        .peer_vec
        .iter()
        .filter(|v| match ps.peer_map.get(*v) {
            Some(p) => p.delay < Duration::from_millis(ACTIVE_PEER_DELAY_MS),
            None => {
                error!("status_json: {v} in peer_vec but not in peer_map, skipping, this shouldnt happen");
                false
            }
        })
        .count();

    stream.set_nonblocking(false).ok();
    thread::spawn(move || {
        let free_bytes = free_disk_bytes();
        let body = json!({
            "version": env!("BUILD_VERSION"),
            "public_key": public_key,
            "total_peers": total_peers,
            "unique_ips": unique_ips,
            "active_peer_count": active_peers.len(),
            "fast_peer_count": fast_peer_count,
            "active_peers": active_peers,
            "free_disk_bytes": free_bytes,
        });
        let body_str = body.to_string();
        let response = format!(
            "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
            body_str.len(), body_str
        );
        stream.write_all(response.as_bytes()).ok();
    });
}

// GET /content.json (loopback-gated) -- machine-readable listing of this node's own
// shared content, the one thing the homepage HTML exposes but no JSON API did.
// public/: one entry per blob, sha256<->blake3 paired by underlying inode
// (public/<sha256> is hard/sym-linked to public/blake3/<blake3>, see handle_upload;
// fs::metadata follows the link so both resolve to the same (dev,ino)).
// origin/: published updatable files (served at /latest/0x<pub>/<name>) plus a
// `directories` array for /share-symlinked dirs (served at /latest/0x<pub>/<dir>/<file>).
fn content_json(ps: &PeerState, mut stream: TcpStream) {
    use std::os::unix::fs::MetadataExt;
    let pub_hex = ps.keypair.public.to_string();
    stream.set_nonblocking(false).ok();
    thread::spawn(move || {
        let is_hex64 = |s: &str| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit());
        let unix_secs = |t: std::time::SystemTime| {
            t.duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        };
        let rfc3339 =
            |t: std::time::SystemTime| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339();

        // ---- public/: pair sha256 <-> blake3 by underlying inode ----
        let mut by_inode: HashMap<(u64, u64), serde_json::Value> = HashMap::new();
        for (dir, is_blake3) in [("./cjp2p/public/blake3", true), ("./cjp2p/public", false)] {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().into_string().unwrap_or_default();
                    if !is_hex64(&name) {
                        continue;
                    }
                    let Ok(meta) = fs::metadata(entry.path()) else {
                        continue;
                    }; // follows symlink
                    if meta.is_dir() {
                        continue;
                    }
                    let modified = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                    let e = by_inode.entry((meta.dev(), meta.ino())).or_insert_with(|| {
                        json!({
                            "sha256": serde_json::Value::Null,
                            "blake3": serde_json::Value::Null,
                            "size": meta.len(),
                            "mtime": rfc3339(modified),
                            "mtime_unix": unix_secs(modified),
                            "tree": false,
                        })
                    });
                    if is_blake3 {
                        e["blake3"] = json!(name);
                        e["tree"] = json!(Path::new(&format!(
                            "./cjp2p/public/blake3_tree_v2/{}",
                            name
                        ))
                        .exists());
                    } else {
                        e["sha256"] = json!(name);
                    }
                }
            }
        }
        let mut public: Vec<serde_json::Value> = by_inode.into_values().collect();
        public.sort_by(|a, b| {
            b["mtime_unix"]
                .as_u64()
                .unwrap_or(0)
                .cmp(&a["mtime_unix"].as_u64().unwrap_or(0))
        });

        // ---- origin/: published files + /share-symlinked directories ----
        let mut origin: Vec<serde_json::Value> = Vec::new();
        let mut directories: Vec<serde_json::Value> = Vec::new();
        if let Ok(entries) = fs::read_dir("./cjp2p/origin") {
            for entry in entries.flatten() {
                let name = entry.file_name().into_string().unwrap_or_default();
                if name.starts_with('.') {
                    continue; // .tmp_*, dotfiles
                }
                let Ok(meta) = fs::metadata(entry.path()) else {
                    continue;
                }; // follows symlink
                let enc = urlencoding::encode(&name);
                if meta.is_dir() {
                    directories.push(json!({
                        "name": name,
                        "url": format!("/latest/0x{}/{}/", pub_hex, enc),
                    }));
                } else {
                    let modified = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                    origin.push(json!({
                        "name": name,
                        "url": format!("/latest/0x{}/{}", pub_hex, enc),
                        "size": meta.len(),
                        "mtime": rfc3339(modified),
                        "mtime_unix": unix_secs(modified),
                    }));
                }
            }
        }
        origin.sort_by(|a, b| {
            b["mtime_unix"]
                .as_u64()
                .unwrap_or(0)
                .cmp(&a["mtime_unix"].as_u64().unwrap_or(0))
        });

        let body = json!({
            "public_key": format!("0x{}", pub_hex),
            "origin": origin,
            "directories": directories,
            "public": public,
        });
        let body_str = body.to_string();
        let response = format!(
            "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
            body_str.len(), body_str
        );
        stream.write_all(response.as_bytes()).ok();
    });
}

fn status_page(
    inbound_states: &HashMap<String, InboundState>,
    ps: &PeerState,
    mut stream: TcpStream,
) {
    let public_key_hex = ps.keypair.public.to_string();
    let current_dir = std::env::current_dir().unwrap().display().to_string();

    let mut highly_recommended_content: HashMap<String, (i32, u64)> = HashMap::new();
    for (_, v) in &ps.peer_map {
        if let Some(p) = &v.you_should_see_this {
            match highly_recommended_content.get_mut(&p.id) {
                Some(h) => h.0 += 1,
                None => {
                    highly_recommended_content.insert(p.id.to_owned(), (1, p.length));
                    ()
                }
            }
        }
    }

    let mut trending: HashMap<String, (i32, u64)> = HashMap::new();
    for (_, v) in &ps.peer_map {
        if let Some(p) = &v.i_just_saw_this {
            match trending.get_mut(&p.id) {
                Some(h) => h.0 += 1,
                None => {
                    trending.insert(p.id.to_owned(), (1, p.length));
                    ()
                }
            }
        }
    }

    let mut active_peers: Vec<(SocketAddr, Ed25519Pub)> = ps.active_peers_from_pub_map()
        .into_iter()
        .map(|(sa, pub_, _)| (sa, pub_))
        .collect();

    let mut found_special = false;
    active_peers.sort_by_key(|(_, pub_)| {
        if *pub_ == SPECIAL_PUB.parse::<Ed25519Pub>().unwrap() {
            found_special = true;
            0u8
        } else {
            1u8
        }
    });

    let mut seen_ips: HashSet<IpAddr> = HashSet::new();
    let mut all_ips: Vec<IpAddr> = Vec::new();
    for (k, _) in &ps.peer_map {
        if seen_ips.insert(k.ip()) {
            all_ips.push(k.ip());
        }
    }
    let unique_ips_count = all_ips.len();

    let fast_peers: Vec<(Duration, SocketAddr)> = ps
        .peer_vec
        .iter()
        .filter_map(|v| {
            let p = match ps.peer_map.get(v) {
                Some(p) => p,
                None => {
                    error!("status_html: {v} in peer_vec but not in peer_map, skipping, this shouldnt happen");
                    return None;
                }
            };
            if p.delay < Duration::from_millis(ACTIVE_PEER_DELAY_MS) {
                Some((p.delay, *v))
            } else {
                None
            }
        })
        .collect();

    let mut page = format!("HTTP/1.0 200 OK\r\nContent-type: text/html\r\n\r\n<html><head><meta http-equiv=refresh content=10><title>cjp2p status {}</title>\
            <style>body{{font-family:monospace;font-size:13px;margin:1em}}b{{color:#0ff}}</style></head><body>\n\
            <b>{} {}</b>\n\n\
            <p><b>pubkey</b> {}<br><b>uptime</b> {:?}<p>
            ",
            env!("BUILD_VERSION"),
            std::env::consts::OS,
            env!("BUILD_VERSION"),
            public_key_hex,ps.boot.elapsed());

    page += &format!("<h3>known peers ({})</h3>\n", ps.peer_map_by_pub.len());
    let inbound_info: Vec<(String, usize, usize)> = inbound_states
        .values()
        .map(|i| (i.id.clone(), i.bytes_complete, i.eof))
        .collect();
    if !found_special {
        let pub_str = SPECIAL_PUB;
        page += &format!("<p><a href=/latest/{pub_str}/><big>click here for network hosted group chat, files, demos, and other apps</big></a></p>");
    }
    page += "<h3>active keys</h3><pre>";
    stream.set_nonblocking(false).ok();
    thread::spawn(move || {
        for (sa, pub_) in &active_peers {
            let pub_str = pub_.to_string();
            let home_link = if pub_str == SPECIAL_PUB {
                format!("<span style=\"position:relative;display:inline-block;vertical-align:middle;\"><span style=\"display:inline-block;border:4px solid gold;border-radius:50%;padding:10px 18px;background:rgba(255,215,0,0.25);font-weight:bold;box-shadow:0 0 0 5px rgba(255,215,0,0.4);\"><a href=/latest/{pub_str}/>home</a></span><span style=\"position:absolute;bottom:calc(100% + 12px);left:0;white-space:nowrap;pointer-events:none;\"><span style=\"display:inline-block;background:#fffde7;border:2px solid #aaa;border-radius:14px;padding:4px 12px;font-size:11px;color:#333;font-weight:normal;\">go here for group chat &amp; apps!</span><span style=\"position:absolute;bottom:-10px;left:18px;width:0;height:0;border-left:6px solid transparent;border-right:6px solid transparent;border-top:10px solid #aaa;\"></span><span style=\"position:absolute;bottom:-8px;left:19px;width:0;height:0;border-left:5px solid transparent;border-right:5px solid transparent;border-top:8px solid #fffde7;\"></span></span></span>")
            } else {
                format!("<a href=/latest/{pub_str}/>home</a>")
            };
            page += &format!("<p>0x{pub_str} {home_link} <a href=/latest/{SPECIAL_PUB}/video.html?ed25519={pub_str}>call</a> <a href=/latest/{SPECIAL_PUB}/pong.html?ed25519={pub_str}>pong</a> <a href=/latest/{SPECIAL_PUB}/chat.html?ed25519={pub_str}>chat</a> {}:{}",
                if let Ok(hn) = dns_lookup::lookup_addr(&sa.ip()) { hn } else { sa.ip().to_string() },
                sa.port(),
            );
        }
        page += "</pre>";
        page += &format!("<h3>download</h3><div>saved to {}/cjp2p/public/ &mdash; also drop files there by sha256 to share: <form style='display:inline'><input name=get></form></div><pre>\n", current_dir);
        for (id, bytes_complete, eof) in &inbound_info {
            page += &format!("{} {}/{}\n", id, bytes_complete, eof);
        }
        page += "</pre>";

        if is_local(&stream) {
            let mut downloads: Vec<(String, u64, String, std::time::SystemTime)> = Vec::new();
            for (dir, prefix) in [("./cjp2p/public/blake3", "blake3/"), ("./cjp2p/public", "")] {
                if let Ok(entries) = fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        if entry.path().is_dir() {
                            continue;
                        }
                        let name = entry.file_name().into_string().unwrap_or_default();
                        if name.len() != 64 || !name.chars().all(|c| c.is_ascii_hexdigit()) {
                            continue;
                        }
                        let Ok(meta) = entry.metadata() else { continue };
                        let size = meta.len();
                        let modified = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                        let mime = File::open(entry.path())
                            .ok()
                            .and_then(|mut f| {
                                let mut buf = [0u8; 512];
                                let n = f.read(&mut buf).ok()?;
                                Some(mimetype_detector::detect(&buf[..n]).mime().to_string())
                            })
                            .unwrap_or_else(|| "application/octet-stream".to_string());
                        downloads.push((format!("{}{}", prefix, name), size, mime, modified));
                    }
                }
            }
            downloads.sort_by(|a, b| b.3.cmp(&a.3));
            downloads.truncate(30);
            page += "<h3>your recent downloads</h3><table style='font-family:monospace'>\n";
            if downloads.is_empty() {
                page += "<tr><td>(none yet)</td></tr>\n";
            }
            for (hash, size, mime, modified) in &downloads {
                let size_str = if *size < 1024 {
                    format!("{} B", size)
                } else if *size < 1024 * 1024 {
                    format!("{} KB", size / 1024)
                } else {
                    format!("{} MB", size / (1024 * 1024))
                };
                use chrono::DateTime;
                page += &format!(
                    "<tr><td><a href='/{hash}' target='_blank'>{hash}</a></td>\
                     <td>&nbsp;{size_str}&nbsp;</td><td>{mime}</td><td>{}</td></tr>\n",
                    DateTime::<Utc>::from(*modified).format("%Y-%m-%d %H:%M:%S")
                );
            }
            page += "</table>\n";
        }

        let mut sorted_list_results: Vec<_> = highly_recommended_content.iter().collect();
        sorted_list_results.sort_by_key(|&(_, b)| b.0);
        page += "<h3>recommended</h3><p>via '/recommend sha256' CLI</p><pre>";
        for (k, v) in &sorted_list_results {
            page += &format!("<a href={}>{}</a> {} {}\n",k,k,v.0,v.1);
        }
        page += "</pre>";

        let mut sorted_list_results: Vec<_> = trending.iter().collect();
        sorted_list_results.sort_by_key(|&(_, b)| b.0);
        page += "<h3>trending</h3><p>most recently downloaded</p><pre>";
        for (k, v) in sorted_list_results.into_iter().rev() {
            page += &format!("<a href={}>{}</a> {} {}\n",k,k,v.0,v.1);
        }
        page += "</pre>";

        page += &format!("<h3>fast peers</h3><p>{} unique IPs seen &mdash; peers with &lt;250ms latency</p><pre>", unique_ips_count);
        for (d, v) in &fast_peers {
            page += &format!("{:21?} {:21}\n", d, v);
        }
        page += &format!("</pre><body></html>");
        stream.write_all(page.as_bytes()).ok();
    });
}
fn handle_web_request(
    index: usize,
    stream_states: &mut HashMap<String, StreamState>,
    inbound_states: &mut HashMap<String, InboundState>,
    ps: &mut PeerState,
) {
    let mut stream = ps.http_clients.remove(index);
    let mut buf = [0; 16];
    let Ok(len) = stream.peek(&mut buf) else {
        return;
    };
    if len < 7 {
        if len > 0 {
            debug!("got short http request, {len} bytes, discarding");
        }
        return;
    }
    if is_local(&stream) && buf.starts_with(b"GET /wt") {
        let mut ws = accept(stream).unwrap();
        info!("websocket connected");
        let message_out_string = if ps.p.my_ed25519_signed_by_web_wallet.is_none() {
            format!("[{{\"PleaseSignYourPub\":{{\"ed25519\":\"{}\"}}}}]", ps.keypair.public)
        } else {
            format!("[{{\"YourEd25519\":{{\"ed25519\":\"{}\"}}}}]", ps.keypair.public)
        };
        info!("sending websocktet: {}",message_out_string);
        ws.write(tungstenite::Message::Text(message_out_string.into()))
            .unwrap();
        ws.flush().ok();
        ps.ws_vec.push(ws);
        return;
    }

    let mut page = format!("");
    let Some(req) = parse_header(&mut stream) else {
        return;
    };
    let mut start: usize = 0;
    let mut end: usize = 0;
    if req.path == "/" {
        debug!("got http request for {:?}",req);
        status_page(inbound_states, ps, stream);
        return;
    }
    if req.path == "/status.json" {
        debug!("got http request for {:?}",req);
        status_json(ps, stream);
        return;
    }
    if req.path == "/content.json" {
        debug!("got http request for {:?}", req);
        if !is_local(&stream) {
            stream
                .write_all(b"HTTP/1.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .ok();
            return;
        }
        content_json(ps, stream);
        return;
    }
    if req.path == "/favicon.ico" {
        let data = include_bytes!("favicon.png");
        let hdr = format!("HTTP/1.0 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\n\r\n", data.len());
        stream.write_all(hdr.as_bytes()).ok();
        stream.write_all(data).ok();
        return;
    }

    info!("got http request for {:?}",HttpRequest {body_prefix: vec![],..req.clone()});
    fs::create_dir_all("./cjp2p/log").ok();
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        .read(true)
        .open("./cjp2p/log/http.v3.json")
    {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let mut entry = serde_json::to_value(&json![req]).unwrap();
        entry["t"] = serde_json::json!(t);
        file.write_all(&serde_json::to_vec(&entry).unwrap()).ok();
        file.write(b"\n").ok();
    }

    if is_local(&stream) && req.path.starts_with("/chat/") {
        let v = &req.path[6..];
        let their_pub = v.split('?').next().unwrap();
        page += &format!("HTTP/1.0 200 OK\r\nContent-type: text/html\r\n\r\n<html><head><meta http-equiv=refresh content='6; url=/chat/{}' ><title>cjp2p chat {}</title></head><body><pre>\n\
                    try /ping or /version. \n\
                If they can't find you through main page, the URL they need to get here (not the same as yours) is
                <a href=http://127.0.0.1:{}/chat/{}>http://127.0.0.1:{}/chat/{}</a>
                    <br><a href=/latest/{SPECIAL_PUB}/video.html?ed25519={}>click here</a> for high quality video call (just mute the video for audio only)</a>\n
                    <br><a href=/latest/{SPECIAL_PUB}/pong.html?ed25519={}>click here</a> to play pong</a>\n
                    send a message (type fast before the next page refresh) : <form><input name=line_chat_msg></form>\n\n\
                    <a href=/latest/{SPECIAL_PUB}/chat.html?{}>click here</a> to switch to character-by-character mode\n\
                    "
                    ,their_pub
                    ,their_pub
                    ,ps.http_port
                    ,ps.keypair.public
                    ,ps.http_port
                    ,ps.keypair.public
                    ,their_pub
                    ,their_pub
                    ,their_pub
                    );
        if !ps.recorded_chats.get_mut(their_pub).is_some() {
            let mut past_chats = vec![];
            for (their_pub_hex, msg) in &ps.all_chats {
                if their_pub_hex == their_pub {
                    past_chats.push(msg.to_string());
                }
            }
            ps.recorded_chats.insert(their_pub.to_string(), past_chats);
        }
        for m in (&ps.recorded_chats[their_pub]).into_iter().rev() {
            page += &format!("{}\n",m);
        }

        if req.path.contains("?line_chat_msg=") {
            let mut parts = v.split("?line_chat_msg=");
            let _ = parts.next().unwrap().to_string();
            let msg_ = parts.next().unwrap().to_string();
            let msg = urlencoding::decode(&msg_).unwrap().to_string();
            if let Ok(pub_key) = their_pub.parse::<Ed25519Pub>() {
                chat_to_pub(ps, pub_key, &msg);
            }
            page += &format!("\n\n{} sent..",msg);
            ps.recorded_chats.get_mut(their_pub).unwrap().push(msg);
        }
        stream.write_all(page.as_bytes()).ok();
        return;
    }
    // /latest/<pub_hex>/<name> -- updatable named content via signed Latest message
    if req.path.starts_with("/latest/") {
        let rest = &req.path[8..];
        let mut parts = rest.splitn(2, '?').next().unwrap().splitn(2, '/');
        let Some(raw_pub) = parts.next() else { return };
        let name_raw = match parts.next() {
            Some(p) => {
                if p.len() > 0 && !p.ends_with('/') {
                    p
                } else {
                    &(p.to_owned() + "index.html")
                }
            }
            None => {
                let qs = req
                    .path
                    .splitn(2, '?')
                    .nth(1)
                    .map_or(String::new(), |q| format!("?{}", q));
                let redirect = format!(
                        "HTTP/1.0 301 Moved Permanently\r\nLocation: /latest/{}/{}\r\n\r\n",
                        raw_pub, qs);
                stream.write_all(redirect.as_bytes()).ok();
                return;
            }
        };
        let name = urlencoding::decode(name_raw)
            .unwrap_or_default()
            .to_string();
        if is_safe_relative_path(&name) {
            if let Ok(ed25519) = raw_pub.parse::<Ed25519Pub>() {
                let gl = GetLatest {
                    ed25519,
                    name: name.clone(),
                };
                gl.clone().receive(
                    ps,
                    &Source::S(stream.peer_addr().unwrap()),
                    &mut false,
                    stream_states,
                    inbound_states,
                    None,
                );
                let mut start: usize = 0;
                let mut end: usize = 0;
                let mut ranged = false;
                if let Some(range) = req.headers.get("range") {
                    sscanf!(range, "bytes={}-{}", start, end).ok();
                    if end > 0 { end+=1; }
                    info!("got ranged http req {} range {:?}",req.path,range);
                    ranged = true;
                } else {
                    info!("got unranged http req {} start/end {} {} {:?} ",req.path,start,end,req.headers);
                }
                let cache_path = latest_cache_path(&ed25519.to_string(), &name);
                let sha256_opt = load_sha256_from_latest_cache(&cache_path);
                if !is_local(&stream) && sha256_opt.is_none() {
                    stream.write_all(b"HTTP/1.0 403 Forbidden\r\n\n").ok();
                    return;
                }
                let pending_latest = if sha256_opt.is_none() {
                    Some(LatestData {
                        pub_key: ed25519,
                        name: name.clone(),
                        highest_version: -1,
                        delay_for_newest_until: Some(Instant::now() + Duration::from_millis(300)),
                    })
                } else {
                    Some(LatestData {
                        pub_key: ed25519,
                        name: name.clone(),
                        highest_version: load_seq_from_latest_cache(&cache_path) as i64,
                        delay_for_newest_until: Some(Instant::now() + Duration::from_millis(300)),
                    })
                };
                if ed25519 != ps.keypair.public {
                    let mut peers = ps.best_peers(250, 6);
                    if let Some(Source::S(sa)) = ps.peer_map_by_pub.get(&ed25519) {
                        let mut msg_out = vec![Message::GetLatest(gl.clone())];
                        msg_out.append(&mut ps.always_returned(*sa));
                        ps.socket
                            .send_to(&serde_json::to_vec(&msg_out).unwrap(), sa)
                            .ok();
                        peers.insert(*sa);
                    }
                    if is_local(&stream) {
                        // dont do an aggressive search for just anyone
                        for sa in &peers {
                            let mut msg_out = vec![Message::GetLatest(gl.clone())];
                            msg_out.append(&mut ps.always_returned(*sa));
                            ps.socket
                                .send_to(&serde_json::to_vec(&msg_out).unwrap(), sa)
                                .ok();
                        }
                    }
                }
                let index = ps.content_gateways.len();
                ps.content_gateways.push(ContentGateway {
                    id: sha256_opt.unwrap_or_default(),
                    http_start: start,
                    http_end: end,
                    ranged: ranged,
                    http_socket: stream,
                    waiting_for_browser: false,
                    http_done: false,
                    sent_header: false,
                    eof: None,
                    pending_latest,
                    initiator: Initiator::Latest,
                });
                if ps.content_gateways[index].pending_latest.is_none() {
                    ps.serve_http_content(stream_states, inbound_states, index);
                }
            }
        }
        return;
    }
    // /stream/{pubkey_hex}/{stream_id} route
    if req.path.starts_with("/stream/") && is_local(&stream) {
        let rest = &req.path[8..];
        let mut parts = rest.splitn(2, '/');
        let (Some(pubkey_hex), Some(stream_id)) = (parts.next(), parts.next()) else {
            return;
        };
        let stream_id = stream_id.split('?').next().unwrap_or("");
        if !is_safe_relative_path(&stream_id) {
            return;
        }
        let origin_pubkey = match pubkey_hex.parse::<Ed25519Pub>() {
            Ok(p) => p,
            _ => return,
        };
        let full_id = format!("stream/{}/{}", pubkey_hex, stream_id);
        if !stream_states.contains_key(&full_id) {
            let new_ss = StreamState::new(origin_pubkey, &full_id);
            stream_states.insert(full_id.clone(), new_ss);
        }
        // Send initial PleaseSendContent to best peers
        if let Some(ss) = stream_states.get_mut(&full_id) {
            let peers = ps.best_peers(250, 6);
            ss.request_blocks(ps, peers);
        }
        let mut ranged = false;
        if let Some(range) = req.headers.get("range") {
            info!("got ranged http req {} range {:?}",req.path,range);
            sscanf!(range, "bytes={}-{}",start,end).ok();
            if end > 0 { end+=1; }
            ranged = true;
        } else {
            info!("got unranged http req {} start/end {} {} {:?} ",req.path,start,end,req.headers);
        }

        info!("http start end {start} {end}");
        let index = ps.content_gateways.len();
        ps.content_gateways.push(ContentGateway {
            id: full_id,
            http_start: start,
            http_end: if end != 0 { end } else { 0x7fffffffff },
            http_socket: stream,
            ranged: ranged,
            waiting_for_browser: false,
            http_done: false,
            sent_header: false,
            eof: None,
            pending_latest: None,
            initiator: Initiator::Stream,
        });
        ps.serve_http_content(stream_states, inbound_states, index);
        return;
    }

    if is_local(&stream) && req.method == "POST" && req.path == "/upload" {
        handle_upload(stream, req);
        return;
    }

    if is_local(&stream) && req.method == "POST" && req.path == "/publish_origin" {
        handle_publish_origin(stream, req);
        return;
    }

    if req.path.starts_with("/?get=") {
        if !is_local(&stream) {
            let page = format!("HTTP/1.0 403 Forbidden\r\n\n");
            stream.write_all(page.as_bytes()).ok();
            return;
        }
        let v = &req.path[6..];
        InboundState::new(v, ps, inbound_states);
        println!("http requested ordinary download of {}",v);
        let response = format!(
                    "HTTP/1.0 301 OK\r\n\
                     Location: /\r\n\r\n");
        stream.write_all(response.as_bytes()).ok();
        return;
    }

    if req.path.starts_with("/?getb3=") {
        if !is_local(&stream) {
            let page = format!("HTTP/1.0 403 Forbidden\r\n\n");
            stream.write_all(page.as_bytes()).ok();
            return;
        }
        let v = req.path[8..].split('&').next().unwrap_or("");
        if is_safe_relative_path(v) {
            let id = format!("blake3/{}", v);
            InboundState::new(&id, ps, inbound_states);
            info!("http requested blake3 download of {}", v);
        }
        let response = format!("HTTP/1.0 301 OK\r\nLocation: /blake3/{}\r\n\r\n", v);
        stream.write_all(response.as_bytes()).ok();
        return;
    }

    let mut ranged = false;
    if let Some(range) = req.headers.get("range") {
        info!("got ranged http req {} range {:?}",req.path,range);
        sscanf!(range, "bytes={}-{}",start,end).ok();
        if end > 0 { end+=1; }
        ranged = true;
    } else {
        info!("got unranged http req {} start/end {} {} {:?} ",req.path,start,end,req.headers);
    }

    let content_id: String = if req.path.starts_with("/blake3/") {
        let hash = req.path[8..]
            .split('?')
            .next()
            .unwrap_or("")
            .split('/')
            .next()
            .unwrap_or("");
        if !is_safe_relative_path(hash) {
            return;
        }
        format!("blake3/{}", hash)
    } else {
        let id = req.path[1..]
            .split('?')
            .next()
            .unwrap_or("")
            .split('/')
            .next()
            .unwrap_or("");
        let id = id.strip_prefix("0x").unwrap_or(id);
        if !is_safe_relative_path(id) || id.contains('/') || id == "favicon.ico" {
            return;
        }
        id.to_string()
    };
    info!("http start end {start} {end}");
    let index = ps.content_gateways.len();
    ps.content_gateways.push(ContentGateway {
        id: content_id,
        http_start: start,
        http_end: end,
        ranged: ranged,
        http_socket: stream,
        waiting_for_browser: false,
        http_done: false,
        sent_header: false,
        eof: None,
        pending_latest: None,
        initiator: Initiator::ByHash,
    });
    ps.serve_http_content(stream_states, inbound_states, index);
}
fn handle_network(
    ps: &mut PeerState,
    stream_states: &mut HashMap<String, StreamState>,
    inbound_states: &mut HashMap<String, InboundState>,
) {
    let mut buf = [0; 0x10000];

    let (message_in_len, src) = ps.socket.recv_from(&mut buf).unwrap();

    let src = match src {
        SocketAddr::V4(_) => src,
        SocketAddr::V6(v6) => match v6.ip().to_ipv4() {
            Some(ip) => SocketAddr::new(std::net::IpAddr::V4(ip), src.port()),
            _ => src,
        },
    };

    let message_in_bytes = &buf[0..message_in_len];
    trace!( "incoming message {} from {src}", String::from_utf8_lossy(message_in_bytes));
    let messages: Messages = match serde_json::from_slice(message_in_bytes) {
        Ok(r) => r,
        Err(e) => {
            debug!( "could not deserialize incoming messages from {} {e}  :  {}",src,
                    String::from_utf8_lossy(message_in_bytes));
            return;
        }
    };
    let messages = messages.0;
    let mut new_peer = !ps.peer_map.contains_key(&src);
    let mut might_be_ip_spoofing = ps.check_key(&messages, src);
    new_peer &= ps.peer_map.contains_key(&src);
    if ps.ws_vec.len() > 0 {
        let message_out_string = serde_json::to_string(&json![
            [Message::Forwarded(Forwarded{
                src,
                from_ed25519:None,
                maybe_ed25519: ps.peer_map.get(&src).and_then(|p| p.ed25519),
                messages: String::from_utf8_lossy(&message_in_bytes).to_string(),
                might_be_ip_spoofing,
            })]])
        .unwrap();
        trace!( "sending raw message {} to {} websocket(s)", message_out_string,ps.ws_vec.len());
        for ws in &mut ps.ws_vec {
            if ws
                .write(tungstenite::Message::Text(
                    message_out_string.clone().into(),
                ))
                .is_ok()
            {
                ws.flush().ok();
            }
        }
    }
    let mut message_out = ps.handle_messages(
        messages,
        &Source::S(src),
        &mut might_be_ip_spoofing,
        stream_states,
        inbound_states,
        None,
    );
    if new_peer {
        message_out.push(SignedMessage::new(ps, serde_json::to_vec(&ps.always_returned(src)).unwrap()));
        message_out.push(MyPublicKey::new(ps));
        message_out.push(Message::PleaseSendPeers(PleaseSendPeers {}));
        message_out.push(PleaseReturnThisMessage::new(ps));
    }
    if might_be_ip_spoofing {
        trim_reply(&mut message_out, message_in_len);
        message_out.push(ps.please_always_return(src));
    }
    if message_out.len() == 0 {
        return;
    }
    message_out.append(&mut ps.always_returned(src));
    if message_out.len() == 0 {
        return;
    }
    let message_out_bytes = serde_json::to_vec(&message_out).unwrap();
    trace!( "sending message {1:?} to {0}{src}", if might_be_ip_spoofing {
               "\x1b[7munverified\x1b[m "} else {""},  String::from_utf8_lossy(&message_out_bytes));
    // 256M cb407d7355bb63929d7f4b282684f5a2884a0c3fb73d56642455600569a6888b
    // seconds of user/sys time
    // these were NOT done with RUSTFLAGS="-C target-cpu=native"
    //NO IFTOP NO TCPDUMP NO IPV6
    // Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz
    // # to/from itself
    // 5/2 unencrypted
    // 68/3 EncryptedMessages
    // 30/3 FastEncryptedMessages
    // # receiving :
    // 4/3 unencrypted
    // 38/2 EncryptedMessages
    // 20/2 FastEncryptedMessages
    // # sending :
    // 3/3 unencrypted
    // 32/4 EncryptedMessages
    // 16/4 FastEncryptedMessages
    //
    // AMD EPYC-Rome-v4 Processor
    // # to/from itself
    // 3/2 unencrypted
    // 53/4 EncryptedMessages
    // 27/2 FastEncryptedMessages
    // # receiving :
    // 3/4 unencrypted
    // 32/4 EncryptedMessages
    // 17/5 FastEncryptedMessages
    // # sending :
    // 3/6 unencrypted
    // 32/4 EncryptedMessages
    // 15/4 FastEncryptedMessages
    /*if let Some(their_pub) = &ps.peer_map[&src].ed25519 {
        message_out_bytes = serde_json::to_vec(
            &(vec![
                          FastEncryptedMessages::new(ps,their_pub, message_out_bytes),
                          ]),
        )
        .unwrap();
    } */
    match ps.socket.send_to(&message_out_bytes, src) {
        Ok(s) => trace!("sent {s}"),
        Err(e) => {
            if e.raw_os_error() == Some(11) {
                debug!("EWOULDBLOCK failed to reply to {src} (your wifi/mobile connection is probably backing up)");
                // failed to send (your wifi/mobile connection is probably backing up) {0} {e}", msg_out.len());
            } else {
                warn!("failed to reply {} bytes to {src} {e}", message_out_bytes.len())
            }
        }
    }
}
fn trim_reply(message_out: &mut Vec<Message>, message_in_length: usize) {
    let mut ratio;
    let mut message_out_bytes;
    while {
        message_out_bytes = serde_json::to_vec(&message_out).unwrap();
        ratio = // 20 is IP header, 8 is UDP header, 57 is the the cookie they seem to need
            (message_out_bytes.len() as f64 + 20.0 + 8.0 + 57.0) / (message_in_length  as f64 + 20.0 + 8.0 + 57.0);
        trace!("ratio: {ratio}");
        message_out.len() > 0 && ratio > rand::rng().random_range(1.0..5.0)
    } {
        let popped = message_out.pop();
        debug!("{ratio}x ratio: dropping part of response to unverified source IP, so that you are not used as a flood/stressor/DDOS. {:?}", popped);
    }
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct Peers {
    peers: HashSet<SocketAddr>,
}
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct AlwaysReturned {
    cookie: String,
}
impl Receive for AlwaysReturned {
    fn receive(
        self,
        _: &mut PeerState,
        _: &Source,
        _: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        _: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        //this is handled early
        return vec![];
    }
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct PleaseAlwaysReturnThisMessage {
    cookie: String,
}
impl Receive for PleaseAlwaysReturnThisMessage {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        _: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        if *might_be_ip_spoofing {
            ps.last_cookie = Some(self.cookie);
            return vec![];
        }
        if let Source::S(src) = *src {
            // not even needed for websockets
            trace!("saving cookie {} for {:?}",self.cookie,src);
            if !ps.peer_map.contains_key(&src) {
                let mut pi = PeerInfo::new();
                pi.delay = Duration::from_millis(100);
                ps.peer_map.insert(src, pi);
            }
            ps.peer_map
                .get_mut(&src)
                .unwrap()
                .anti_ip_spoofing_cookie_they_expect = Some(self.cookie);
        }
        return vec![];
    }
}
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct PleaseSendPeers {}
impl Receive for PleaseSendPeers {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        _: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        let p = ps.best_peers(1 + 45 * !*might_be_ip_spoofing as usize, 6);
        trace!("sending {:?}/{:?} peers", p.len(), ps.peer_map.len());
        let mut message_out = vec![Message::Peers(Peers { peers: p })];
        let mpk = MyPublicKey {
            ed25519h: ps.keypair.public.clone(),
            ed25519_eth_signed: None,
        };
        if !*might_be_ip_spoofing {
            if let Source::S(src) = *src {
                message_out.push(SignedMessage::new(ps, serde_json::to_vec(&ps.always_returned(src)).unwrap()));
            }
            message_out.push(Message::MyPublicKey(mpk));
        }
        return message_out;
    }
}
impl Receive for Peers {
    fn receive(
        self,
        ps: &mut PeerState,
        _: &Source,
        _: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        _: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        trace!("received peers {:?} ", self.peers.len());
        if ps.suggested_peers.len() >= 500 {
            debug!("suggesteted peers {}",ps.suggested_peers.len());
            return vec![];
        }
        for p in &self.peers {
            let sa: SocketAddr = *p;
            if !ps.peer_map.contains_key(&sa) && ps.suggested_peers.len() < 500 {
                trace!("new peer suggested {sa}");
                ps.suggested_peers.insert(sa);
            }
        }
        return vec![];
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
struct IJustSawThis {
    id: String,
    length: u64,
}
impl Receive for IJustSawThis {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        inbound_states: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        if !is_safe_relative_path(&self.id) || self.id == "favicon.ico" {
            return vec![];
        }
        if let Source::S(src) = *src {
            if let Some(i) = inbound_states.get_mut(&self.id) {
                i.peers.insert(src);
            } else {
                InboundState::send_content_peers_from_disk(&self.id, 1, &src);
            }
            if !*might_be_ip_spoofing && src.port() == 24254 {
                if let Some(pi) = ps.peer_map.get_mut(&src) {
                    pi.i_just_saw_this = Some(self);
                }
            }
        }
        return vec![];
    }
}
#[derive(Clone, Serialize, Deserialize, Debug, JsonSchema)]
struct YouShouldSeeThis {
    id: String,
    length: u64,
}
impl Receive for YouShouldSeeThis {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        inbound_states: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        if !is_safe_relative_path(&self.id) || self.id == "favicon.ico" {
            return vec![];
        }
        if let Source::S(src) = *src {
            if let Some(i) = inbound_states.get_mut(&self.id) {
                i.peers.insert(src);
            } else {
                InboundState::send_content_peers_from_disk(&self.id, 1, &src);
            }
            if !*might_be_ip_spoofing && src.port() == 24254 {
                if let Some(pi) = ps.peer_map.get_mut(&src) {
                    pi.you_should_see_this = Some(self);
                }
            }
        }
        return vec![];
    }
}
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct PleaseSendContent {
    id: String,
    length: usize,
    offset: usize,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct Content {
    id: String,
    offset: usize,
    #[schemars(with = "String")]
    #[serde_as(as = "Base64")]
    base64: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eof: Option<usize>,
}

impl PleaseSendContent {
    fn new_messages(i: &mut InboundState, ps: &PeerState) -> Vec<Message> {
        // Don't request content blocks until leaf CVs are loaded; every block
        // must be CV-checked on receipt, so there is no point starting earlier.
        //    if i.id.starts_with("blake3/") && i.segment_hashes.is_none() {
        //      info!("waiting for blake3 tree for {} before startind download",i.id);
        //     return vec![];
        // }
        for cg in &ps.content_gateways {
            let new_next_block = cg.http_start as usize / BLOCK_SIZE!();
            if !cg.http_done && !cg.waiting_for_browser && cg.id == i.id {
                if new_next_block != i.next_block
                    && (i.next_block * BLOCK_SIZE!() < cg.http_start
                        || i.next_block * BLOCK_SIZE!() >= cg.http_start + 0x400000
                        || i.next_block * BLOCK_SIZE!() > cg.http_end)
                {
                    info!("http {} ressetting next_block from {} to {} !",line!(), i.next_block,new_next_block);
                    i.next_block = new_next_block;
                }
                break;
            }
        }
        while {
            if i.next_block * BLOCK_SIZE!() >= i.eof && i.bytes_complete > 0 {
                // %EOF
                debug!( "\x1b[36m{} almost done {}/{}/{}  blocks done/remaining/next \x1b[m", i.id, i.bytes_complete / BLOCK_SIZE!(), (i.eof - i.bytes_complete) / BLOCK_SIZE!(), i.next_block);
                if log_enabled!(Level::Trace) {
                    if let Some(ref bm) = i.bitmap {
                        for j in (0..bm.size()).filter(|&k| !bm.get(k)) {
                            trace!("{j}");
                        }
                    }
                } //this can cause window loss in debug build

                if i.id.starts_with("blake3_tree_v2/") {
                    // good chance we need this done before moving on, but this probably breaks the speed
                    // of web pages full of images back to back, but those should use sha256 really
                    i.next_block = 0;
                }
                return vec![];
            }
            i.bytes_complete > 0 && i.bitmap.as_ref().map_or(false, |bm| bm.get(i.next_block))
        } {
            i.next_block += 1;
        }
        debug!( "\x1b[32;7mPleaseSendContent {} {} {} \x1b[m", i.id, i.next_block, i.next_block * BLOCK_SIZE!());
        i.last_activity = Instant::now();
        return vec![Message::PleaseSendContent(PleaseSendContent {
            id: i.id.to_owned(),
            offset: i.next_block * BLOCK_SIZE!(),
            length: BLOCK_SIZE!(),
        })];
    }
}
impl Receive for PleaseSendContent {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        inbound_states: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        if !is_safe_relative_path(&self.id) {
            return vec![];
        };
        let mut message_out: Vec<Message> = Vec::new();
        if let Source::S(src) = *src {
            if let Some(i) = inbound_states.get_mut(&self.id) {
                i.peers.insert(src);
                message_out.append(&mut i.send_content_peers(*might_be_ip_spoofing, src));
                // For verified blake3 in-progress downloads, serve already-verified blocks
                if let Some(content) = i.serve_block(self.offset / BLOCK_SIZE!()) {
                    message_out.push(Message::Content(content));
                }
            }
        }
        if message_out.len() == 0 {
            message_out.append(&mut Content::new_block(&self, might_be_ip_spoofing, ps));
            if let Source::S(src) = *src {
                if message_out.len() > 0 && self.offset == 0 && !self.id.starts_with("stream/") {
                    info!("sending {} to {src:?} from {src}", self.id);
                    fs::create_dir_all("./cjp2p/log").ok();
                    if let Ok(mut log_file) = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .write(true)
                        .open("./cjp2p/log/content.json")
                    {
                        let t = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as i64;
                        log_file
                            .write_all(
                                &serde_json::to_vec(&json!({"src":src,"id": self.id, "t": t}))
                                    .unwrap(),
                            )
                            .ok();
                        log_file.write_all(b"\n").ok();
                    }
                }
            }
        }
        let Source::S(src) = *src else {
            return message_out;
        };
        if message_out.len() == 0
            || (!*might_be_ip_spoofing && rand::rng().random::<u32>() % 43 == 0)
        {
            message_out.append(&mut InboundState::send_content_peers_from_disk(
                &self.id,
                3 + 45 * !*might_be_ip_spoofing as usize,
                &src,
            ));
        }
        return message_out;
    }
}

impl Content {
    fn new_block(
        req: &PleaseSendContent,
        might_be_ip_spoofing: &mut bool,
        ps: &mut PeerState,
    ) -> Vec<Message> {
        if *might_be_ip_spoofing && rand::rng().random::<u32>() % 27 == 0 {
            info!("randomly ignoring unverified source IPs for {} so a dumb client doesn't get stuck in a loop",req.id);
            return vec![];
        }

        if std::env::var("SKIP_LOCAL").is_ok() {
            return vec![];
        }

        if req.id.starts_with("stream/") {
            let mut id_parts = req.id.splitn(3, '/');
            id_parts.next();
            let (source_ed25519, file_name) = match (
                id_parts.next().map(|a| a.parse::<Ed25519Pub>()),
                id_parts.next(),
            ) {
                (Some(Ok(pk)), Some(b)) => (pk, b),
                _ => return vec![],
            };
            let dir = StreamState::stream_dir(&source_ed25519.to_string());
            if !is_safe_relative_path(file_name) {
                return vec![];
            }
            let data_path = dir.clone() + file_name;
            let sig_path = dir.clone() + file_name + ".signatures";
            let bitmap_path = dir.clone() + file_name + ".bitmap";
            let block_number = req.offset / BLOCK_SIZE!();
            let block_offset = block_number * BLOCK_SIZE!();
            if !MmapBitVec::open(&bitmap_path, None, true)
                .map(|bv| block_number < bv.size() && bv.get(block_number))
                .unwrap_or(false)
            {
                return vec![];
            }
            let (sig_file, data_file) = match (File::open(&sig_path), File::open(&data_path)) {
                (Ok(a), Ok(b)) => (a, b),
                _ => return vec![],
            };
            let file_len = data_file.metadata().map_or(0, |m| m.len() as usize);
            let block_len = BLOCK_SIZE!().min(file_len.saturating_sub(block_offset));
            if block_len == 0 {
                return vec![];
            }
            let mut buf = vec![0u8; block_len];
            let n = data_file
                .read_at(&mut buf, block_offset as u64)
                .unwrap_or(0);
            buf.truncate(n);
            if buf.is_empty() {
                return vec![];
            }
            let mut arr = [0u8; 64];
            if !sig_file
                .read_at(&mut arr, (block_number * 64) as u64)
                .map_or(false, |n| n == 64)
                || arr == [0u8; 64]
            {
                return vec![];
            }
            let payload = serde_json::to_vec(&[Message::Content(Self {
                id: req.id.clone(),
                offset: block_offset,
                base64: buf,
                eof: None,
            })])
            .unwrap();
            return vec![Message::SignedMessage(SignedMessage {
                            ed25519: source_ed25519, signature: arr.to_vec(),
                            payload: None, payload_json: Some(String::from_utf8(payload).unwrap()),
                        })];
        }

        let length = if *might_be_ip_spoofing {
            32
        } else if req.length > 0xa000 {
            0xa000
        } else {
            req.length
        };
        let ofr = if let Some(ofr) = ps.open_file_cache.get(&req.id) {
            ofr
        } else if let Ok(file) = File::open("./cjp2p/public/".to_owned() + &req.id) {
            let meta = file.metadata().unwrap();
            if meta.is_dir() {
                return vec![];
            }
            let ofr = OpenFile {
                eof: meta.len() as usize,
                file: file,
            };
            ps.open_file_cache.insert(req.id.to_owned(), ofr);
            &ps.open_file_cache[&req.id]
        } else {
            return vec![];
        };
        debug!( "going to send {:?} at {:?}", req.id, req.offset / BLOCK_SIZE!());
        let mut buf = vec![0; length];
        let length = ofr.file.read_at(&mut buf, req.offset as u64).unwrap();
        buf.truncate(length);
        if req.id.starts_with("blake3_tree_v2/")
            && req.offset == 0
            && buf.len() >= 4
            && &buf[..4] != b"B3T\x02"
        {
            warn!("SERVING block0 of {} with bad magic {:02x}{:02x}{:02x}{:02x} len={} file_eof={}", req.id, buf[0], buf[1], buf[2], buf[3], buf.len(), ofr.eof);
        }
        return vec![Message::Content(Self {
            id: req.id.clone(),
            offset: req.offset,
            base64: buf,
            eof: Some(ofr.eof),
        })];
    }
}
impl Receive for Content {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        _: &mut bool,
        stream_states: &mut HashMap<String, StreamState>,
        inbound_states: &mut HashMap<String, InboundState>,
        mut signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        let parts: Vec<&str> = self.id.splitn(3, '/').collect();
        if matches!(src, Source::None)
            && parts.len() == 3
            && parts[0] == "stream"
            && is_safe_relative_path(parts[2])
        {
            if let Ok(origin_pubkey) = parts[1].parse::<Ed25519Pub>() {
                let full_id = self.id.clone();
                if !stream_states.contains_key(&full_id) {
                    let new_ss = StreamState::new(origin_pubkey, &full_id);
                    stream_states.insert(full_id.clone(), new_ss);
                }
                debug!("received stream block from web socket id/offset/eof {} {} {:?}",self.id,self.offset,self.eof);
                if let Some(ss) = stream_states.get_mut(&full_id) {
                    let block_number = self.offset / BLOCK_SIZE!();
                    /*                    let block_end = self.offset + self.base64.len();
                    let new_eof = (block_end + (1 << 20)).max(ss.eof);
                    if new_eof > ss.eof {
                        ss.resize_to(new_eof);
                    }
                    ss.mmap[self.offset..block_end]
                        .copy_from_slice(&self.base64[..self.base64.len()]);
                    ss.set_block_bit(block_number); */
                    signer = Some(ps.keypair.public);
                    let block_start = block_number * BLOCK_SIZE!();
                    let (sign_offset, sign_base64) = if self.offset > block_start {
                        // Not block-aligned: prefix from already-written mmap data for this block
                        let prefix_len = self.offset - block_start;
                        let prefix = if self.offset <= ss.mmap.len() {
                            ss.mmap[block_start..self.offset].to_vec()
                        } else {
                            vec![0u8; prefix_len]
                        };
                        let mut combined = prefix;
                        let max_new = BLOCK_SIZE!() as usize - prefix_len;
                        combined.extend_from_slice(&self.base64[..self.base64.len().min(max_new)]);
                        (block_start, combined)
                    } else {
                        (self.offset, self.base64.clone())
                    };
                    let payload = serde_json::to_vec(&[Message::Content(Self {
                        id: self.id.clone(),
                        offset: sign_offset,
                        base64: sign_base64,
                        eof: None,
                    })])
                    .unwrap();
                    let signed_msg = SignedMessage::new(ps, payload);
                    if let Message::SignedMessage(ref sm) = signed_msg {
                        let sig_offset = block_number * 64;
                        if sig_offset + 64 <= ss.sig_mmap.len() {
                            ss.sig_mmap[sig_offset..sig_offset + 64].copy_from_slice(&sm.signature);
                        }
                    }
                    ss.last_activity = Instant::now();
                }
            }
            //            return vec![];
        }
        if self.eof.is_some() {
            ps.p.i_just_saw_this = Some(IJustSawThis {
                id: self.id.to_owned(),
                length: self.eof.unwrap() as u64,
            });
        }
        if let Some(ss) = stream_states.get_mut(&self.id) {
            let mut message_out = vec![];
            if let Some(pk) = signer {
                if pk != ss.origin_pubkey {
                    warn!("stream content from wrong signer: expected {} got {}", ss.origin_pubkey, pk);
                    return message_out;
                }
            } else {
                warn!("unsigned streamstate Content");
                return message_out;
            }
            if self.base64.len() == 0 {
                return message_out;
            }
            let block_end = self.offset + self.base64.len();
            if block_end < ss.data_file_len && self.base64.len() != BLOCK_SIZE!() {
                return message_out;
            }
            if let Source::S(src) = *src {
                ss.peers.insert(src);
                if (rand::rng().random::<u32>() % 101) == 0 {
                    debug!("growing window ({}) for {} at {}", ss.next_block as i32 -self.offset as i32 /BLOCK_SIZE!(),ss.id,ss.next_block);
                    ss.request_blocks(ps, HashSet::from([src]));
                    ss.next_block += 1;
                }
                message_out = StreamState::PleaseSendContent__new_messages(ss, ps);
                ss.next_block += 1;
            }
            if block_end > ss.data_file_len {
                let new_eof = (block_end + (1 << 20)).max(ss.eof);
                if new_eof > ss.eof {
                    ss.resize_to(new_eof);
                }
                ss.data_file_len = block_end;
                ss.data_file.set_len(block_end as u64).unwrap();
            }
            let block_number = self.offset / BLOCK_SIZE!();
            debug!( "\x1b[34mreceived block {:?} {:?} {:?} from {:?} window \x1b[7m{:}\x1b[m", self.id, block_number, block_number * BLOCK_SIZE!(), src, ss.next_block as i64 - block_number as i64);
            ss.mmap[self.offset..block_end].copy_from_slice(&self.base64);
            if self.base64.len() == BLOCK_SIZE!() || block_end == ss.data_file_len {
                ss.set_block_bit(block_number);
            }
            ss.last_activity = Instant::now();
            for idx in 0..ps.content_gateways.len() {
                if ps.content_gateways[idx].id != self.id || ps.content_gateways[idx].http_done {
                    continue;
                }
                ps.content_gateways[idx].serve_content_from_stream_state(ss);
                if ps.content_gateways[idx].http_done {
                    let cg = ps.content_gateways.remove(idx);
                    ps.http_clients.push(cg.http_socket);
                    break;
                }
            }
            return message_out;
        }
        let src = match *src {
            Source::S(src) => src,
            _ => return vec![],
        };

        if !inbound_states.contains_key(&self.id) {
            debug!( "unwanted content, probably dups -- the tail still in flight after completion, for {0} block {1}",
                self.id, self.offset / BLOCK_SIZE!());
            return vec![];
        }
        //if (rand::rng().random::<u32>() % (if cg.http_socket.is_some() { 7 } else { 101 })) == 0 ||
        if (rand::rng().random::<u32>() % 101) == 0 {
            for (_, i) in inbound_states.iter_mut() {
                if i.next_block * BLOCK_SIZE!() >= i.eof || i.bytes_complete == i.eof {
                    continue;
                }
                if i.id.starts_with("blake3/") && i.segment_hashes.is_none() {
                    continue;
                }
                debug!("growing window ({}) for {} at {}", i.next_block as i32 -self.offset as i32 /BLOCK_SIZE!(),i.id,i.next_block);
                i.request_blocks(ps, HashSet::from([src]));
                i.next_block += 1;
                break;
            }
        }
        let i = inbound_states.get_mut(&self.id).unwrap();
        i.peers.insert(src);
        let mut message_out = vec![];
        if i.done || i.hash_future.is_some() {
            // Duplicate block arrived after download already completed (e.g. in-flight twin request).
            // Avoid recreating the mmap (which was taken for segment_hashes) onto a fresh zero file.
            debug!("ignoring late dup block {} for completed {}", self.offset / BLOCK_SIZE!(), self.id);
        } else {
            let block_number = self.offset / BLOCK_SIZE!();
            debug!( "\x1b[34mreceived block {:?} {:?} {:?} from {:?} window \x1b[7m{:}\x1b[m", self.id, block_number, block_number * BLOCK_SIZE!(), src, i.next_block as i64 - block_number as i64);
            message_out = i.receive_content(&self, ps);
            let tree_eof = i.eof;
            if i.bytes_complete == i.eof && i.eof > 0 && self.id.starts_with("blake3_tree_v2/") {
                let hash = self.id["blake3_tree_v2/".len()..].to_string();
                let bad: Vec<usize> = match (
                    n_leaves_from_tree_v2_eof(tree_eof),
                    inbound_states.get(&self.id).unwrap().mmap.as_deref(),
                ) {
                    (Some(n), Some(data)) => check_tree_v2_data(data, &hash, n),
                    (None, _) => {
                        error!("{} cannot derive n_leaves from eof {}", self.id, tree_eof);
                        vec![0]
                    }
                    (_, None) => {
                        error!("{} missing mmap",self.id);
                        vec![0]
                    }
                };
                if bad.is_empty() {
                    let incoming = format!("./cjp2p/incoming/{}", self.id);
                    let public = format!("./cjp2p/public/{}", self.id);
                    if fs::rename(&incoming, &public).is_ok() {
                        info!("{} tree complete", self.id);
                        println!("{} tree complete", self.id);
                        let content_id = format!("blake3/{}", hash);
                        let ro_mmap = inbound_states
                            .get_mut(&self.id)
                            .and_then(|ti| ti.mmap.take())
                            .and_then(|mm| mm.make_read_only().ok());
                        if let Some(mm) = ro_mmap {
                            if let Some(ci) = inbound_states.get_mut(&content_id) {
                                ci.segment_hashes = Some(mm);
                            }
                        }
                    }
                    if let Some(ti) = inbound_states.get_mut(&self.id) {
                        ti.done = true;
                    }
                } else {
                    let Some(ti) = inbound_states.get_mut(&self.id) else {
                        error!("where did inbound_states go, this should never happen!");
                        return vec![];
                    };
                    ti.hash_failures += 1;
                    if ti.hash_failures > 2 {
                        error!("{} tree check failed 3 times, giving up", self.id);
                        ti.done = true;
                    } else {
                        let mut bad_sorted = bad.clone();
                        bad_sorted.sort();
                        warn!("{} tree check attempt {} failed, bad blocks: {:?} (eof={} bytes_complete={})", self.id, ti.hash_failures, bad_sorted, ti.eof, ti.bytes_complete);
                        for b in bad {
                            if let Some(ref mut bm) = ti.bitmap {
                                if b < bm.size() && bm.get(b) {
                                    bm.set(b, false);
                                    let byte_start = b * BLOCK_SIZE!();
                                    let byte_end = (byte_start + BLOCK_SIZE!()).min(ti.eof);
                                    ti.bytes_complete =
                                        ti.bytes_complete.saturating_sub(byte_end - byte_start);
                                    warn!("{} clearing block {} (bytes {}-{}) for retry", self.id, b, byte_start, byte_end);
                                } else {
                                    warn!("{} bad block {} not in bitmap (bitmap_size={} set={})", self.id, b, bm.size(), b < bm.size() && bm.get(b));
                                }
                            }
                        }
                        ti.next_block = 0;
                    }
                }
            }
        }
        if message_out.len() == 0 {
            for (_, i) in inbound_states.iter_mut() {
                if i.next_block * BLOCK_SIZE!() >= i.eof || i.bytes_complete == i.eof {
                    continue;
                }
                message_out = PleaseSendContent::new_messages(i, ps);
                i.next_block += 1;
                break;
            }
        }
        if message_out.len() == 0 {
            if let Some(i) = inbound_states.get_mut(&self.id) {
                i.next_block = 0;
                message_out = PleaseSendContent::new_messages(i, ps);
                i.next_block += 1;
            }
        }
        return message_out;
    }
}

struct InboundState {
    mmap: Option<MmapMut>,
    next_block: usize,
    bitmap: Option<MmapBitVec>,
    id: String,
    eof: usize,
    bytes_complete: usize,
    peers: HashSet<SocketAddr>,
    last_activity: Instant,
    hash_failures: i32,
    hash_future: Option<std::sync::mpsc::Receiver<bool>>,
    verifying_mmap: Option<std::sync::Arc<Mmap>>,
    segment_hashes: Option<Mmap>,
    done: bool,
}

struct StreamState {
    mmap: MmapMut,
    data_file: File,
    data_file_len: usize,
    sig_mmap: MmapMut,
    bitmap: MmapBitVec,
    id: String,
    origin_pubkey: Ed25519Pub,
    eof: usize,
    next_block: usize,
    peers: HashSet<SocketAddr>,
    last_activity: Instant,
    last_viewed: Instant,
}
impl StreamState {
    fn stream_dir(pubkey: &str) -> String {
        "./cjp2p/streams/".to_owned() + pubkey + "/"
    }
    fn new(origin_pubkey: Ed25519Pub, id: &str) -> Self {
        let dir = StreamState::stream_dir(&origin_pubkey.to_string());
        fs::create_dir_all(&dir).ok();
        let file_name = id.splitn(3, '/').nth(2).unwrap_or(id);
        let existing_data_len = fs::metadata(dir.clone() + file_name)
            .map(|m| m.len() as usize)
            .unwrap_or(0);
        let initial_mmap_size = (1usize << 18).max(existing_data_len);
        let (mmap, data_file, sig_mmap, bitmap) = Self::open_files(&dir, id, initial_mmap_size, existing_data_len);
        Self {
            mmap,
            data_file,
            data_file_len: existing_data_len,
            sig_mmap,
            bitmap,
            id: id.to_string(),
            origin_pubkey,
            eof: initial_mmap_size,
            next_block: 0,
            peers: HashSet::new(),
            last_activity: Instant::now() - Duration::from_secs(999),
            last_viewed: Instant::now(),
        }
    }
    fn open_files(dir: &str, id: &str, mmap_size: usize, data_file_size: usize) -> (MmapMut, File, MmapMut, MmapBitVec) {
        let n_blocks = (mmap_size + BLOCK_SIZE!() - 1) / BLOCK_SIZE!();
        let file_name = id.splitn(3, '/').nth(2).unwrap_or(id);
        let full_path = dir.to_owned() + file_name;
        if let Some(parent) = std::path::Path::new(&full_path).parent() {
            fs::create_dir_all(parent).ok();
        }
        let data_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&full_path)
            .unwrap();
        if data_file.metadata().map_or(0, |m| m.len()) < data_file_size as u64 {
            data_file.set_len(data_file_size as u64).unwrap();
        }
        let mmap = unsafe { MmapOptions::new().len(mmap_size).map_mut(&data_file).unwrap() };

        let sig_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(full_path.clone() + ".signatures")
            .unwrap();
        let sig_target = (n_blocks * 64) as u64;
        if sig_file.metadata().map_or(0, |m| m.len()) < sig_target {
            sig_file.set_len(sig_target).unwrap();
        }
        let sig_mmap = unsafe { MmapMut::map_mut(&sig_file).unwrap() };

        let bitmap =
            MmapBitVec::create(full_path + ".bitmap", n_blocks, None, &[])
                .unwrap();

        (mmap, data_file, sig_mmap, bitmap)
    }
    fn resize_to(&mut self, new_eof: usize) {
        let dir = StreamState::stream_dir(&self.origin_pubkey.to_string());
        let (mmap, data_file, sig_mmap, bitmap) = Self::open_files(&dir, &self.id, new_eof, self.data_file_len);
        self.mmap = mmap;
        self.data_file = data_file;
        self.sig_mmap = sig_mmap;
        self.bitmap = bitmap;
        self.eof = new_eof;
    }
    fn block_bit(&self, n: usize) -> bool {
        n < self.bitmap.size() && self.bitmap.get(n)
    }
    fn set_block_bit(&mut self, n: usize) {
        if n < self.bitmap.size() {
            self.bitmap.set(n, true);
        }
    }
    fn first_zero_from(&self, start_block: usize) -> Option<usize> {
        let n_blocks = (self.eof + BLOCK_SIZE!() - 1) / BLOCK_SIZE!();
        let end = n_blocks.min(self.bitmap.size());
        (start_block..end).find(|&i| !self.bitmap.get(i))
    }
    fn has_viewers(&self, ps: &PeerState) -> bool {
        let a = self.last_viewed.elapsed() <= Duration::from_secs(30);
        let b = ps.content_gateways.iter().any(|cg| cg.id == self.id);
        debug!("has_viewers {a} {b}");
        a || b
    }
    #[allow(non_snake_case)]
    fn PleaseSendContent__new_messages(ss: &mut StreamState, ps: &PeerState) -> Vec<Message> {
        for cg in &ps.content_gateways {
            let new_next_block = cg.http_start / BLOCK_SIZE!();
            if !cg.http_done && !cg.waiting_for_browser && cg.id == ss.id {
                debug!("PleaseSendContent__new_messages {} {} {} {}",new_next_block*BLOCK_SIZE!(),ss.next_block*BLOCK_SIZE!(),cg.http_start,ss.eof);
                if new_next_block != ss.next_block
                    && (ss.next_block * BLOCK_SIZE!() < cg.http_start
                        || ss.next_block * BLOCK_SIZE!() >= cg.http_start + 0x400000)
                {
                    ss.next_block = new_next_block;
                }
                break;
            }
        }
        // skip already-received blocks
        while ss.next_block < ss.data_file_len/BLOCK_SIZE!() && ss.block_bit(ss.next_block) {
            ss.next_block += 1;
        }
        ss.last_activity = Instant::now();
        debug!( "\x1b[32;7mPleaseSendContent {} {} {} \x1b[m", ss.id, ss.next_block, ss.next_block * BLOCK_SIZE!());
        vec![Message::PleaseSendContent(PleaseSendContent {
            id: ss.id.clone(),
            offset: ss.next_block * BLOCK_SIZE!(),
            length: BLOCK_SIZE!(),
        })]
    }
    fn request_blocks(&mut self, ps: &mut PeerState, some_peers: HashSet<SocketAddr>) {
        for sa in some_peers {
            let mut message_out: Vec<Message> = Vec::new();
            for m in StreamState::PleaseSendContent__new_messages(self, ps) {
                message_out.push(m);
            }
            if message_out.len() < 1 {
                return;
            }
            message_out.append(&mut ps.always_returned(sa));
            let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
            debug!( "requesting additional blocks {:?} to {sa}", String::from_utf8_lossy(&message_out_bytes)
            );
            ps.socket.send_to(&message_out_bytes, sa).ok();
        }
    }
}

struct LatestData {
    pub_key: Ed25519Pub,
    name: String,
    highest_version: i64,
    delay_for_newest_until: Option<Instant>,
}

struct ContentGateway {
    id: String,
    ///http_time: Instant,
    http_start: usize,
    http_end: usize,
    ranged: bool,
    http_socket: TcpStream,
    waiting_for_browser: bool,
    http_done: bool,
    sent_header: bool,
    eof: Option<usize>,
    pending_latest: Option<LatestData>,
    initiator: Initiator,
}
enum Initiator {
    Latest,
    Stream,
    ByHash,
}
impl ContentGateway {
    fn serve_content_from_disk(&mut self, file: &File) {
        if self.eof.is_none() {
            self.eof = Some(file.metadata().unwrap().len() as usize);
        }
        if self.http_end == 0 || self.eof.unwrap() < self.http_end {
            self.http_end = self.eof.unwrap();
        }
        // i couldnt figure out how to get serve_mmap to take both Mmap or MmapMut.
        let mmap = unsafe { MmapMut::map_mut(file).unwrap() };
        self.serve_mmap(&mmap, self.http_end);
    }

    fn serve_content_from_inbound_state(&mut self, i: &mut InboundState) {
        if self.http_done || i.bytes_complete == 0 {
            self.waiting_for_browser = false;
            return;
        }
        self.eof = Some(i.eof);
        if self.http_end == 0 || self.eof.unwrap() < self.http_end {
            self.http_end = self.eof.unwrap();
        }

        let mut available_end = self.http_end;
        if let Some(not_available) = ((self.http_start / BLOCK_SIZE!())
            ..((self.http_end + (BLOCK_SIZE!() - 1)) / BLOCK_SIZE!()))
            .find(|&blk| i.bitmap.as_ref().map_or(true, |bm| !bm.get(blk)))
        {
            available_end = not_available * BLOCK_SIZE!();
        }
        if available_end <= self.http_start {
            self.waiting_for_browser = false;
            return;
        }
        let data: &[u8] = if let Some(mm) = i.mmap.as_deref() {
            mm
        } else if let Some(arc) = i.verifying_mmap.as_deref() {
            arc
        } else {
            error!("should not happen, no mmap!");
            return;
        };
        self.serve_mmap(data, available_end);
    }
    fn serve_content_from_stream_state(&mut self, ss: &mut StreamState) {
        ss.last_viewed = Instant::now();
        let start_block = self.http_start / BLOCK_SIZE!();
        let mut available_end = match ss.first_zero_from(start_block) {
            Some(zero_block) => zero_block * BLOCK_SIZE!(),
            None => ss.data_file_len,
        };
        if available_end > ss.data_file_len { available_end = ss.data_file_len; };
        debug!("cgss http_start {} eof {} available_end {available_end}",self.http_start,ss.eof);
        if available_end <= self.http_start {
            self.waiting_for_browser = false;
            return;
        }
        info!("cgss serving available_end {available_end} to socket {:?}",self.http_socket.peer_addr().unwrap());
        let mmap = &mut ss.mmap;
        self.serve_mmap(mmap, available_end);
    }
    fn serve_mmap(&mut self, mmap: &[u8], mut available_end: usize) {
        if !self.sent_header {
            let mime_type = mimetype_detector::detect(&mmap[0..]);
            // text/x-typescript is a misdetection of plain JS -- the detector pattern-matches
            // syntax that is a superset of JS. Browsers require a JS MIME type to load scripts.
            let mime_str = if mime_type.mime() == "text/x-typescript" {
                "application/javascript"
            } else {
                mime_type.mime()
            };
            let response = if self.ranged {
                debug!("cg {} serve_mmap ranged {}-{} of {} {}",self.http_socket.as_raw_fd(),self.http_start,self.http_end,self.eof.unwrap_or(0x7fffffffff),mime_str);
                debug!("cg {} http end minus start {}",self.http_socket.as_raw_fd(),self.http_end-self.http_start);
                if self.http_end - self.http_start > 0x100000 {
                    self.http_end = self.http_start + 0x100000;
                    if available_end > self.http_end {
                        available_end = self.http_end;
                    }
                } // seems to improve seeking in Brave
                format!(
                        "HTTP/1.0 206 Partial Content\r\n\
                         Connection: keep-alive\r\n\
                         Content-Length: {}\r\n\
                         Content-Disposition: inline\r\n\
                         Accept-Ranges: bytes\r\n\
                         Content-Range: bytes {}-{}/{}\r\n\
                         Content-Type: {}\r\n\r\n"
            ,self.http_end-self.http_start,self.http_start,self.http_end-1, self.eof.unwrap_or(0x7fffffffff), mime_str)
            } else {
                debug!("cg {} serve_mmap unranged {}-{} of {} {}",self.http_socket.as_raw_fd(),self.http_start,self.http_end,self.eof.unwrap_or(0x7fffffffff),mime_str);
                format!(
                        "HTTP/1.0 200 OK\r\n\
                         Connection: keep-alive\r\n\
                         Content-Length: {}\r\n\
                         Content-Disposition: inline\r\n\
                         Accept-Ranges: bytes\r\n\
                         Content-Type: {}\r\n\r\n"
            ,self.http_end-self.http_start, mime_str)
            };
            info!("cg {} sending http client {}",self.http_socket.as_raw_fd(),response);
            match self.http_socket.write_all(response.as_bytes()) {
                Ok(_) => (),
                Err(e) => {
                    warn!("cg {} http failed to write header {}",self.http_socket.as_raw_fd(),e);
                    self.http_done = true; // give up, that shouldnt happen
                    self.waiting_for_browser = false;
                }
            }
            self.sent_header = true;
        }

        debug!("cg {} serve_mmap {}-{} [available {} ] of {}",self.http_socket.as_raw_fd(),self.http_start,self.http_end,available_end,self.eof.unwrap_or(0x7fffffffff));
        match self
            .http_socket
            .write(&mmap[self.http_start..available_end])
        {
            Ok(sent) => self.http_start += sent,
            Err(e) => {
                if e.raw_os_error() == Some(11) {
                    debug!("cg {} EWOULDBLOCK failed to send (your wifi/mobile connection is probably backing up) {e}",self.http_socket.as_raw_fd());
                    // failed to send (your wifi/mobile connection is probably backing up) {0} {e}", msg_out.len());
                } else {
                    warn!("cg {} http client error {e}",self.http_socket.as_raw_fd());
                    self.http_done = true;
                    self.waiting_for_browser = false;
                    return;
                }
            }
        }
        if self.http_start != available_end {
            debug!("cg {} sent up to {} ..wanted to send up to {}",self.http_socket.as_raw_fd(),self.http_start,available_end);
        } else {
            debug!("cg {} sent up to {} ",self.http_socket.as_raw_fd(),self.http_start);
        }
        self.http_done = self.http_start == self.http_end;
        self.waiting_for_browser = self.http_start != available_end;
    }
}
impl InboundState {
    fn bitmap_path(id: &str) -> String {
        "./cjp2p/incoming/".to_owned() + id + ".bitmap"
    }
    fn new(id: &str, ps: &mut PeerState, inbound_states: &mut HashMap<String, InboundState>) {
        if inbound_states.contains_key(id) {
            return;
        }
        fs::create_dir_all("./cjp2p/public/blake3").ok();
        fs::create_dir_all("./cjp2p/public/blake3_tree_v2").ok();
        fs::create_dir_all("./cjp2p/incoming/blake3").ok();
        fs::create_dir_all("./cjp2p/incoming/blake3_tree_v2").ok();
        let mut peers: HashSet<SocketAddr> = HashSet::new();
        let peers_from_disk = InboundState::send_content_peers_from_disk(
            &id.to_string(),
            999999999,
            &"127.0.0.1:24254".parse().unwrap(),
        );
        if peers_from_disk.len() > 0 {
            if let Message::MaybeTheyHaveSome(p) = &peers_from_disk[0] {
                peers.extend(&p.peers);
                info!("{} loadedd {} peers frorm disk",id,p.peers.len());
            }
        }
        let bitmap_path = Self::bitmap_path(id);
        let bitmap = MmapBitVec::open(&bitmap_path, None, false).ok();
        let mut new_i = Self {
            mmap: None,
            next_block: 0,
            bitmap,
            id: id.to_string(),
            eof: 1 << 18,
            bytes_complete: 0,
            peers: peers,
            last_activity: Instant::now() - Duration::from_secs(999),
            hash_failures: 0,
            hash_future: None,
            verifying_mmap: None,
            segment_hashes: None,
            done: false,
        };
        if id.starts_with("blake3/") {
            let hash = &id["blake3/".len()..];
            let tree_path = format!("./cjp2p/public/blake3_tree_v2/{}", hash);
            if let Ok(f) = File::open(&tree_path) {
                if let Ok(mm) = unsafe { Mmap::map(&f) } {
                    new_i.segment_hashes = Some(mm);
                }
            }
            if new_i.segment_hashes.is_none() {
                let tree_id = format!("blake3_tree_v2/{}", hash);
                InboundState::new(&tree_id, ps, inbound_states);
            }
        }
        for _ in 0..(1 + 5 / (1 + new_i.peers.len())) {
            new_i.request_blocks(ps, new_i.peers.clone()); // resume (un-stall)
        }
        let peers = ps.best_peers(250, 6);
        info!("searchng  {} peers",peers.len());
        new_i.request_blocks(ps, peers);
        inbound_states.insert(id.to_string(), new_i);
    }

    fn receive_content(&mut self, content: &Content, ps: &mut PeerState) -> Vec<Message> {
        let this_eof = match content.eof {
            Some(n) => n,
            None => content.offset + content.base64.len() + 1,
        };

        if this_eof == 0 {
            warn!("{} received content with zero-length EOF, ignoring", self.id);
            return vec![];
        }

        if this_eof != self.eof || self.mmap.is_none() || self.bitmap.is_none() {
            if self.mmap.is_some() && this_eof != self.eof {
                warn!("{} conflicting EOF {} vs established {}, ignoring", self.id, this_eof, self.eof);
                return vec![];
            }
            self.eof = this_eof;
            let blocks = (self.eof + BLOCK_SIZE!() - 1) / BLOCK_SIZE!();
            self.bitmap =
                Some(MmapBitVec::create(Self::bitmap_path(&self.id), blocks, None, &[]).unwrap());
            let file = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open("./cjp2p/incoming/".to_owned() + &self.id)
                .unwrap();
            if file.metadata().map_or(0, |m| m.len()) < self.eof as u64 {
                file.set_len(self.eof as u64).unwrap();
            }
            self.mmap = Some(unsafe { MmapMut::map_mut(&file).unwrap() });
            let bm = self.bitmap.as_mut().unwrap();
            if blocks > 0 {
                bm.set(blocks - 1, false);
            }
            let set_bits = bm.rank(0..blocks);
            self.bytes_complete = set_bits * BLOCK_SIZE!();
        }

        if content.offset >= self.eof {
            warn!("{} got data at {}, past EOF {}!",self.id,content.offset,self.eof);
            return vec![];
        }
        let block_number = content.offset / BLOCK_SIZE!();
        if self
            .bitmap
            .as_ref()
            .map_or(false, |bm| bm.get(block_number))
        {
            debug!("dup {block_number}");
        } else if content.base64.len() == BLOCK_SIZE!()
            || content.base64.len() + content.offset == self.eof
        {
            if self.id.starts_with("blake3/") {
                if self.segment_hashes.is_none() {
                    let hash = &self.id["blake3/".len()..];
                    if let Ok(f) = File::open(format!("./cjp2p/public/blake3_tree_v2/{}", hash)) {
                        if let Ok(mm) = unsafe { Mmap::map(&f) } {
                            self.segment_hashes = Some(mm);
                        }
                    }
                }
                let Some(ref tree_mmap) = self.segment_hashes else {
                    debug!("{} not ready but got blake3 content already",self.id);
                    return vec![];
                };
                let Some(expected_cv) = leaf_cv_in_tree_v2(tree_mmap, block_number) else {
                    return vec![];
                };
                let cv = block_chaining_value(&content.base64, (block_number * BLOCK_SIZE!()) as u64);
                if cv != expected_cv {
                    warn!("{} block {} blake3 CV mismatch, re-requesting", self.id, block_number);
                    self.last_activity = Instant::now();
                    return vec![];
                }
            }
            if self.id.starts_with("blake3_tree_v2/")
                && block_number == 0
                && content.base64.len() >= 4
            {
                let magic = &content.base64[..4];
                if magic != b"B3T\x02" {
                    warn!("{} writing block0 with bad magic {:02x}{:02x}{:02x}{:02x} (len={} eof={}) -- sender gave zeros?", self.id, magic[0], magic[1], magic[2], magic[3], content.base64.len(), self.eof);
                }
            }
            self.mmap.as_mut().unwrap()[content.offset..content.base64.len() + content.offset]
                .copy_from_slice(content.base64.as_ref());
            self.bytes_complete += content.base64.len();
            if let Some(ref mut bm) = self.bitmap {
                bm.set(block_number, true);
            }
            for (index, cg) in (&mut (ps.content_gateways)).into_iter().enumerate() {
                if cg.id == self.id {
                    cg.serve_content_from_inbound_state(self);
                    if cg.http_done {
                        let cg = ps.content_gateways.remove(index);
                        ps.http_clients.push(cg.http_socket);
                        break;
                    }
                }
            }
        }
        self.last_activity = Instant::now();
        if self.bytes_complete == self.eof && self.id.starts_with("blake3/") {
            let path = "./cjp2p/incoming/".to_owned() + &self.id;
            let new_path = "./cjp2p/public/".to_owned() + &self.id;
            if fs::rename(&path, &new_path).is_ok() {
                info!("{0} finished {1} bytes", self.id, self.eof);
                println!("{0} finished {1} bytes", self.id, self.eof);
                self.save_content_peers();
                fs::remove_file(Self::bitmap_path(&self.id)).ok();
                let link_path = new_path.clone();
                thread::spawn(move || add_sha256_link(&link_path));
            }
            self.done = true;
        } else if self.bytes_complete == self.eof
            && !self.id.starts_with("blake3_tree_v2/")
            && self.hash_future.is_none()
        {
            let id = self.id.clone();
            if let Some(mm) = self.mmap.take() {
                match mm.make_read_only() {
                    Ok(ro) => {
                        let arc = std::sync::Arc::new(ro);
                        let thread_arc = std::sync::Arc::clone(&arc);
                        self.verifying_mmap = Some(arc);
                        let eof = self.eof;
                        let (tx, rx) = std::sync::mpsc::channel();
                        self.hash_future = Some(rx);
                        debug!("{} starting sha256 verification", id);
                        thread::spawn(move || {
                            let mut hasher = Sha256::new();
                            hasher.update(&thread_arc[..eof]);
                            let hash = format!("{:x}", hasher.finalize());
                            info!("{} sha256sum {}", id, hash);
                            let matched = hash == id.to_lowercase();
                            drop(thread_arc);
                            tx.send(matched).ok();
                        });
                    }
                    Err(e) => {
                        error!("{} make_read_only failed: {}", id, e);
                    }
                }
            }
        }
        let message_out = PleaseSendContent::new_messages(self, ps);
        self.next_block += 1;
        return message_out;
    }

    fn request_blocks(&mut self, ps: &mut PeerState, some_peers: HashSet<SocketAddr>) {
        for sa in some_peers {
            let mut message_out: Vec<Message> = Vec::new();
            for m in PleaseSendContent::new_messages(self, ps) {
                message_out.push(m);
            }
            if message_out.len() < 1 {
                return;
            }
            message_out.append(&mut ps.always_returned(sa));
            let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
            debug!( "requesting additional blocks {:?} to {sa}", String::from_utf8_lossy(&message_out_bytes)
            );
            ps.socket.send_to(&message_out_bytes, sa).ok();
        }
    }

    fn save_content_peers(&self) -> () {
        debug!("saving inbound state peers");
        let filename = "./cjp2p/metadata/".to_owned() + &self.id + ".json";
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(filename)
            .unwrap()
            .write_all(
                serde_json::to_vec_pretty(&json!({"Peers":&self.peers}))
                    .unwrap()
                    .as_slice(),
            )
            .ok();
    }
    fn send_content_peers_from_disk(id: &String, at_most: usize, src: &SocketAddr) -> Vec<Message> {
        if !is_safe_relative_path(id) {
            return vec![];
        }
        let path = "./cjp2p/metadata/".to_owned() + &id + ".json";
        let filename = Path::new(&path);
        if let Some(parent) = filename.parent() {
            fs::create_dir_all(parent).ok();
        }

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(false)
            .open(filename)
            .unwrap();

        let peers: &mut HashSet<SocketAddr> = &mut HashSet::new();
        if file.metadata().unwrap().len() > 0 {
            let json: Value = serde_json::from_reader(BufReader::new(&file)).unwrap();
            let loaded_peers: HashSet<SocketAddr> =
                serde_json::from_value(json["Peers"].clone()).unwrap();
            peers.extend(loaded_peers);
        }
        if peers.insert(*src) {
            file.seek(SeekFrom::Start(0)).ok();
            serde_json::to_writer_pretty(BufWriter::new(file), &json!({"Peers":&peers})).unwrap();
        }
        peers.remove(&src);
        if peers.len() == 0 {
            return vec![];
        }

        return vec![Message::MaybeTheyHaveSome(MaybeTheyHaveSome {
            id: id.to_owned(),
            peers: peers.iter().take(at_most).cloned().collect(),
        })];
    }
    // Serve a verified block from an in-progress blake3 download.
    // Only safe for blake3 IDs: each received block was CV-checked before writing,
    // so we can forward it without propagating corruption.
    fn serve_block(&self, block_number: usize) -> Option<Content> {
        if !self.id.starts_with("blake3/") {
            return None;
        }
        let mmap = self.mmap.as_ref()?;
        if self.eof == 0 {
            return None;
        }
        if self.bitmap.as_ref().map_or(true, |bm| {
            block_number >= bm.size() || !bm.get(block_number)
        }) {
            return None;
        }
        let offset = block_number * BLOCK_SIZE!();
        if offset >= self.eof {
            return None;
        }
        let end = (offset + BLOCK_SIZE!()).min(self.eof);
        Some(Content {
            id: self.id.clone(),
            offset,
            base64: mmap[offset..end].to_vec(),
            eof: Some(self.eof),
        })
    }

    fn send_content_peers(&self, might_be_ip_spoofing: bool, src: SocketAddr) -> Vec<Message> {
        debug!("{} sending peers", self.id);
        let at_most = 3 + 45 * !might_be_ip_spoofing as usize;
        let mut peers: HashSet<SocketAddr> = self.peers.iter().take(at_most).cloned().collect();
        peers.remove(&src);
        if peers.len() == 0 {
            return vec![];
        }
        return vec![Message::MaybeTheyHaveSome(MaybeTheyHaveSome {
            id: self.id.clone(),
            peers: peers,
        })];
    }
    fn finished(&mut self) {
        if self.done || self.hash_future.is_none() {
            return;
        }
        match self.hash_future.as_ref().unwrap().try_recv() {
            Ok(matched) => {
                self.hash_future = None;
                if matched {
                    info!("{0} finished {1} bytes", self.id, self.eof);
                    println!("{0} finished {1} bytes", self.id, self.eof);
                    let path = "./cjp2p/incoming/".to_owned() + &self.id;
                    let new_path = "./cjp2p/public/".to_owned() + &self.id;
                    self.verifying_mmap = None;
                    fs::rename(path, &new_path).unwrap();
                    self.save_content_peers();
                    fs::remove_file(Self::bitmap_path(&self.id)).ok();
                    if self.eof > 0x100000 {
                        thread::spawn(move || upgrade_to_blake3(&new_path));
                    }
                    self.done = true;
                } else {
                    error!("{} hash doesnt match! restarting", self.id);
                    self.hash_failures += 1;
                    if self.hash_failures > 2 {
                        error!("{} hash failed 3 times, giving up!", self.id);
                        self.done = true;
                    } else {
                        if let Some(arc) = self.verifying_mmap.take() {
                            match std::sync::Arc::try_unwrap(arc) {
                                Ok(ro) => match ro.make_mut() {
                                    Ok(mm) => self.mmap = Some(mm),
                                    Err(e) => error!("{} make_mut failed: {}", self.id, e),
                                },
                                Err(_) => error!("{} arc still has refs on hash failure", self.id),
                            }
                        }
                        let n_blocks = (self.eof + BLOCK_SIZE!() - 1) / BLOCK_SIZE!();
                        let bp = Self::bitmap_path(&self.id);
                        fs::remove_file(&bp).ok();
                        self.bitmap = Some(MmapBitVec::create(&bp, n_blocks, None, &[]).unwrap());
                        self.next_block = 0;
                        self.bytes_complete = 0;
                    }
                }
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.hash_future = None;
                self.hash_failures += 1;
            }
        }
    }
}

fn maintenance(
    stream_states: &mut HashMap<String, StreamState>,
    inbound_states: &mut HashMap<String, InboundState>,
    ps: &mut PeerState,
) -> () {
    if ps.next_maintenance.elapsed() <= Duration::ZERO {
        return;
    }
    debug!("maintenance");
    ps.next_maintenance = Instant::now()
        + Duration::from_millis(rand::rng().random_range(888..999) * ps.maintenance_period as u64);
    let active_peers = ps.active_peers_from_pub_map();
    let n = active_peers.len();
    let new_pubs: HashSet<Ed25519Pub> = active_peers.iter().map(|(_, pub_, _)| *pub_).collect();
    if n > ps.active_peer_pubs.len() {
        for pub_ in new_pubs.difference(&ps.active_peer_pubs) {
            info!("peer count increased to {n}, caused by {pub_}");
        }
    }
    ps.active_peer_pubs = new_pubs;
    ps.active_peer_count
        .store(n, std::sync::atomic::Ordering::Relaxed);
    if let Some(next) = ps.group_chat_backoff_next {
        if next.elapsed() > Duration::ZERO && !ps.group_chat_outbox.is_empty() {
            let msgs: Vec<serde_json::Value> = ps
                .group_chat_outbox
                .iter()
                .map(|m| serde_json::to_value(&Message::GroupChatMessage(m.clone())).unwrap())
                .collect();
            let peers: Vec<Ed25519Pub> = ps.peer_map_by_pub.keys().cloned().collect();
            for pub_key in peers {
                msgs_to_pub(ps, pub_key, &msgs);
            }
            ps.group_chat_backoff_delay_ms *= 1.5;
            ps.group_chat_backoff_next =
                Some(Instant::now() + Duration::from_millis(ps.group_chat_backoff_delay_ms as u64));
        }
    }
    let nowi = Instant::now();
    log_if_slow(nowi, line!().to_string());
    let n =  ps.active_peer_count.load(std::sync::atomic::Ordering::Relaxed);
    if ps.recent_peer_timer.elapsed() > Duration::from_secs(5 * 60) {
        if n < ps.recent_peer_counter_max * 4 / 5 {
            error!("only {} peers in 5 minutes, vs max (since last notice) of {}",n,ps.recent_peer_counter_max);
            ps.recent_peer_counter_max = n; 
        }
        if n > ps.recent_peer_counter_max * 4 / 5 {
            ps.recent_peer_counter_max = n;
        }
        ps.recent_peer_timer = Instant::now();
    }
    log_if_slow(nowi, line!().to_string());
    if let Ok(dur) = ps.last_upnp.elapsed() {
        if dur > Duration::from_secs(1200) {
            ps.last_upnp = std::time::SystemTime::now();
            ps.upnp();
            ps.pcp_ipv6();
            ps.upnp_ipv6();
        }
    }
    let mut to_remove = vec![];
    log_if_slow(nowi, line!().to_string());
    for (index, cg) in ps.content_gateways.iter().enumerate() {
        if cg.http_done || tcpstream_is_closed(&cg.http_socket) {
            to_remove.push(index);
        }
    }
    log_if_slow(nowi, line!().to_string());
    for tr in to_remove.iter().rev() {
        debug!("CG garbage collection..this should be handled elsewhere already i think? oh not if it errors i think like if the browser hangs up");
        ps.content_gateways.remove(*tr);
    }
    log_if_slow(nowi, line!().to_string());
    ps.sort();
    log_if_slow(nowi, line!().to_string());
    if ps.next_save.elapsed() > Duration::ZERO {
        ps.next_save = Instant::now() + Duration::from_secs(300);
        ps.save_peers();
        ps.p.save();
    }
    log_if_slow(nowi, line!().to_string());
    ps.probe_interfaces();
    log_if_slow(nowi, line!().to_string());
    ps.probe();
    log_if_slow(nowi, line!().to_string());
    ps.open_file_cache = HashMap::new(); // clear the cache
    log_if_slow(nowi, line!().to_string());
    for (_, i) in inbound_states.iter_mut() {
        i.finished();
    }
    inbound_states.retain(|_, i| !i.done);
    log_if_slow(nowi, line!().to_string());
    for (_, i) in inbound_states.iter_mut() {
        if i.bytes_complete == i.eof {
            continue;
        }
        if i.last_activity.elapsed() <= Duration::from_secs(1) {
            continue;
        }
        if i.next_block != 0 {
            debug!("stalled {}", i.id);
        }
        i.next_block = 0;
    }
    log_if_slow(nowi, line!().to_string());
    for (_, i) in inbound_states.iter_mut() {
        if i.last_activity.elapsed() <= Duration::from_secs(1) || i.bytes_complete == i.eof {
            continue;
        }
        if i.id.starts_with("blake3/") && i.segment_hashes.is_none() {
            continue;
        }
        info!("{} stalled, restarting", i.id);
        let mut try_harder = 1;
        for cg in &ps.content_gateways {
            // try harder if user is actively waiting
            if !cg.http_done && cg.id == i.id {
                try_harder = 5;
                i.next_block=cg.http_start/BLOCK_SIZE!();
                break;
            }
        }
        log_if_slow(nowi, line!().to_string());
        for _ in 0..(1 + try_harder / (1 + i.peers.len())) {
            i.request_blocks(ps, i.peers.clone()); // resume (un-stall)
        }
        log_if_slow(nowi, line!().to_string());
        let peers = ps.best_peers(50 * try_harder, 6);
        info!("searching  {} peers for {}",peers.len(),i.id);
        i.request_blocks(ps, peers);
        // TODO the longer its been stuck, the more it should be ignored to try others, instead of
        // this pure random
        if rand::rng().random::<u32>() % 2 == 0 {
            break;
        }
        log_if_slow(nowi, line!().to_string());
    }

    log_if_slow(nowi, line!().to_string());
    ps.unstall_getlatests();
    log_if_slow(nowi, line!().to_string());

    // Drop stream_states with no viewers and stale activity
    stream_states.retain(|_, ss| ss.has_viewers(ps));
    log_if_slow(nowi, line!().to_string());
    // Stall detection: restart next_block for active streams
    for (_, ss) in stream_states.iter_mut() {
        if ss.origin_pubkey == ps.keypair.public {
            continue;
        }
        log_if_slow(nowi, line!().to_string());
        if ss.last_activity.elapsed() <= Duration::from_secs(1) || !ss.has_viewers(ps) {
            continue;
        }
        for cg in &ps.content_gateways {
            if !cg.http_done && cg.id == ss.id {
                ss.next_block=cg.http_start/BLOCK_SIZE!();
                break;
            }
        }

        if let Some(Source::S(origin)) = ps.peer_map_by_pub.get(&ss.origin_pubkey) {
            let peers = HashSet::from([origin.clone()]);
            ss.request_blocks(ps, peers.clone());
            ss.request_blocks(ps, peers);
        }
        for _ in 0..(1 + 5 / (1 + ss.peers.len())) {
            ss.request_blocks(ps, ss.peers.clone());
        }
        let peers = ps.best_peers(50 * 5, 6);
        debug!("searching  {} peers for {}",peers.len(),ss.id);
        ss.request_blocks(ps, peers);
        // TODO the longer its been stuck, the more it should be ignored to try others, instead of
        // this pure random
        if rand::rng().random::<u32>() % 2 == 0 {
            break;
        }
    }

    log_if_slow(nowi, line!().to_string());
    if ps.list_time + Duration::from_secs(1) < Instant::now() {
        let mut sorted_list_results: Vec<_> = ps.list_results.iter().collect();
        sorted_list_results.sort_by_key(|&(_, b)| b.0);
        for (k, v) in &sorted_list_results {
            println!("{} {} {}",v.0,k,v.1);
        }
        ps.list_time += Duration::from_secs(60 * 60 * 24 * 365 * 99);
    }
    log_if_slow(nowi, line!().to_string());
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct MaybeTheyHaveSome {
    id: String,
    peers: HashSet<SocketAddr>,
}

impl Receive for MaybeTheyHaveSome {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        _: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        inbound_states: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        if !inbound_states.contains_key(&self.id) {
            return vec![];
        }
        let i = inbound_states.get_mut(&self.id).unwrap();
        for p in self.peers {
            if i.peers.insert(p) {
                // new possible source? try it
                debug!("{} trying new peer {} suggested by {:?}",self.id,p,src);
                i.request_blocks(ps, HashSet::from([p]));
            }
        }
        return vec![];
    }
}
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct PleaseReturnThisMessage {
    cookie: String,
}
impl Receive for PleaseReturnThisMessage {
    fn receive(
        self,
        _: &mut PeerState,
        _: &Source,
        _: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        _: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        return vec![Message::ReturnedMessage(ReturnedMessage { cookie: self.cookie, })];
    }
}
impl PleaseReturnThisMessage {
    fn new(ps: &PeerState) -> Message {
        Message::PleaseReturnThisMessage(Self {
            cookie: ps.boot.elapsed().as_secs_f64().to_string(),
        })
    }
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct ReturnedMessage {
    cookie: String,
}
impl Receive for ReturnedMessage {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        _: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        if let Source::S(src) = *src {
            if !*might_be_ip_spoofing {
                if let Some(peer) = ps.peer_map.get_mut(&src) {
                    peer.delay =
                        (ps.boot + Duration::from_secs_f64(self.cookie.parse().unwrap())).elapsed();
                    trace!("measured {0} at {1}", src, peer.delay.as_secs_f64())
                }
            };
        }
        return vec![];
    }
}
//        socket.send(JSON.stringify([{GetPubByEth:{eth_addr:their_eth_addr}}]));
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
struct WhereAreThey {
    ed25519h: Ed25519Pub,
}
impl Receive for WhereAreThey {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        _: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        let Some(Source::S(sa)) = ps.peer_map_by_pub.get(&self.ed25519h) else {
            return vec![];
        };
        let Some(p) = ps.peer_map.get(&sa) else {
            return vec![];
        };
        let mpk = MyPublicKey {
            ed25519h: self.ed25519h,
            ed25519_eth_signed: p.ed25519_eth_signed.clone(),
        };
        let message_out = vec![Message::MyPublicKey(mpk)];
        let from_ed25519 = None;
        let maybe_ed25519 = None;
        let messages = serde_json::to_string(&message_out).unwrap();
        trace!("sending {:?} ed25519 {} from  {}",src,self.ed25519h,sa);
        let src = *sa;
        return vec![Message::Forwarded(Forwarded{
            src,
            from_ed25519,
            maybe_ed25519,
            messages,
            might_be_ip_spoofing: *might_be_ip_spoofing,
        })];
    }
}
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
struct GetPubByEth {
    eth_addr: String,
}
impl Receive for GetPubByEth {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        _: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        for (k, p) in &ps.peer_map {
            if let Some(signer) = &p.ed25519_eth_signer {
                if let Some(ed25519) = &p.ed25519 {
                    if *signer == self.eth_addr {
                        let mpk = MyPublicKey {
                            ed25519h: *ed25519,
                            ed25519_eth_signed: p.ed25519_eth_signed.clone(),
                        };
                        let message_out = vec![Message::MyPublicKey(mpk)];
                        let from_ed25519 = Some(*ed25519);
                        let maybe_ed25519 = None;

                        let messages = serde_json::to_string(&message_out).unwrap();
                        trace!("sending {:?} ed25519 {}",src,ed25519);
                        info!("sending {:?} ed25519 {} for eth addr {}",src,ed25519,signer);
                        let src = *k;
                        return vec![Message::Forwarded(Forwarded{
                            src,
                            from_ed25519,
                            maybe_ed25519,
                            messages,
                            might_be_ip_spoofing: *might_be_ip_spoofing,
                        })];
                    }
                }
            }
        }
        return vec![];
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct SignedPub {
    signature: String,
}
impl Receive for SignedPub {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        _: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        _: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        if let Source::S(_) = src {
            return vec![];
        }
        info!("websocket used old SignedPub (just use MyPublicKey now) sent signed {:?} to ",
            &self.signature);
        ps.p.my_ed25519_signed_by_web_wallet = Some(self.signature);
        return vec![];
    }
}
fn default_true() -> bool { true }
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct Forwarded {
    src: SocketAddr,
    from_ed25519: Option<Ed25519Pub>,
    #[serde(skip_serializing_if = "Option::is_none")]
    maybe_ed25519: Option<Ed25519Pub>,
    messages: String,
    #[serde(default = "default_true")]
    might_be_ip_spoofing: bool,
}
impl Receive for Forwarded {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        _: &mut bool,
        stream_states: &mut HashMap<String, StreamState>,
        inbound_states: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        let messages: Messages = match serde_json::from_str(&self.messages) {
            Ok(r) => r,
            Err(e) => {
                debug!( "could not deserialize incoming messages forwarded from {} by {:?} {e}  :  {}",self.src,src,
                    self.messages);
                return vec![];
            }
        };
        let messages = messages.0;

        return ps.handle_messages(
            messages,
            &Source::S(self.src),
            &mut true,
            stream_states,
            inbound_states,
            None,
        );
    }
}
#[serde_as]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct Forward {
    #[serde(skip_serializing_if = "Option::is_none")]
    to_ed25519: Option<Ed25519Pub>,
    #[serde(skip_serializing_if = "Option::is_none")]
    src: Option<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sign: Option<bool>,
    messages: Vec<Value>,
}
impl Receive for Forward {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        _: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        _: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        if let Source::S(_) = src {
            // we could allow this, i dont see why not, though theres not a currrent use
            // case..maybe dual-nat issues if they're encountered, or web socket clients to
            // gateways if gateways with mulitple clients becomes a use case,
            // with web sockets like light nodes stuck behind unusually difficult NAT
            // but better to just leave it off for now, its not clear yet if the webclient
            // is always a trusted localhost or a random
            return vec![];
        }
        debug!("websocket asked me to forward {:?}", &self.messages);
        let mut messages = self.messages;
        if let Some(to) = self.src {
            error!("i dont think this section of code is ever called and i forgot why it is here");
            let c = ps.always_returned(to);
            if c.len() > 0 {
                messages.push(serde_json::to_value(&c[0]).unwrap());
            }
            let message_out_bytes = serde_json::to_vec(&messages).unwrap();
            ps.socket.send_to(&message_out_bytes, to).ok();
            return vec![];
        }
        if let Some(to) = self.to_ed25519 {
            if self.sign == Some(true) {
                let payload = serde_json::to_vec(&messages).unwrap();
                let signed = SignedMessage::new(ps, payload);
                msgs_to_pub(ps, to, &vec![serde_json::to_value(&signed).unwrap()]);
            } else {
                msgs_to_pub(ps, to, &messages);
            }
        }
        return vec![];
    }
}
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct MyPublicKey {
    ed25519h: Ed25519Pub,
    #[serde(skip_serializing_if = "Option::is_none")]
    ed25519_eth_signed: Option<String>,
}
impl MyPublicKey {
    fn new(ps: &PeerState) -> Message {
        return Message::MyPublicKey(Self {
            ed25519h: ps.keypair.public.clone(),
            ed25519_eth_signed: ps.p.my_ed25519_signed_by_web_wallet.clone(),
        });
    }
}
impl Receive for MyPublicKey {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        _: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        use alloy::signers::Signature;
        use std::str::FromStr;
        let mut recovered_address: Option<String> = None;
        let ed25519h_hex = self.ed25519h.to_string();
        if let Some(sig) = &self.ed25519_eth_signed {
            if let Ok(sig) = Signature::from_str(sig.as_str()) {
                // takes 0.0003s so do this in advance
                if let Ok(address) = sig
                    .recover_address_from_msg(format!("my ed25519 public key is {}",ed25519h_hex))
                {
                    debug!("Recovered address: {}", address);
                    // comes out like 0x9aE035dEE8318A9b9fD080Dda31D7524098f65EF
                    // address
                    recovered_address = Some(address.to_string());
                } else {
                    warn!("eth signature failed recover from {:?}",src);
                    return vec![];
                }
            } else {
                warn!("eth signature failed from {:?}",src);
                return vec![];
            }
        }
        if let Source::S(ssrc) = *src {
            if ps.peer_map_by_pub.get(&self.ed25519h).is_none()  || (ps.last_always_returned_signed && ( !*might_be_ip_spoofing || {
                    // if they change IPs, update it faster
                    // this indentation is correct!
                    if let Some(Source::S(old_src)) =  ps.peer_map_by_pub.get(&self.ed25519h) {
                        if let Some(lar) = &ps.last_always_returned {
                            *lar == ps.hash_ip(*old_src) 
                        } else {false}
                    } else {false}
                } )) {
                if ps
                    .peer_map_by_pub
                    .insert(self.ed25519h, src.to_owned())
                    .is_none()
                {
                    info!("new pub found: {}", self.ed25519h);
                }
                if let Some(pi) = ps.peer_map.get_mut(&ssrc) {
                    pi.ed25519 = Some(self.ed25519h);
                    if let Some(a) = recovered_address {
                        pi.ed25519_eth_signer = Some(a);
                        pi.ed25519_eth_signed = self.ed25519_eth_signed;
                    }
                } else {
                    let mut pi = PeerInfo::new();
                    pi.ed25519 = Some(self.ed25519h);
                    if let Some(a) = recovered_address {
                        pi.ed25519_eth_signer = Some(a);
                        pi.ed25519_eth_signed = self.ed25519_eth_signed;
                    }
                    pi.delay = Duration::from_millis(120);
                    ps.peer_map.insert(ssrc, pi);
                }
            }
        } else {
            info!("websocket sent signed {} to ", ed25519h_hex);
            if self.ed25519h == ps.keypair.public {
                if let Some(ed25519_eth_signed) = self.ed25519_eth_signed {
                    info!("websocket signature saved");
                    ps.p.my_ed25519_signed_by_web_wallet = Some(ed25519_eth_signed);
                    ps.p.save();
                }
            } else {
                error!("why is websocket eth signing someone else's ed25519 pub");
            }
        }
        return vec![];
    }
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct ChatMessage {
    message: String,
}
impl ChatMessage {
    fn new(ps: &PeerState, message: String) -> Vec<Message> {
        let message_out = vec![
            PleaseReturnThisMessage::new(ps),
            MyPublicKey::new(ps),
            Message::ChatMessage(Self { message: message }),
        ];
        return message_out;
    }
}
impl Receive for ChatMessage {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        _: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        let Source::S(src) = *src else {
            return vec![];
        };
        if *might_be_ip_spoofing {
            info!("unusual that a chat messagge was received from an unconfirmed source ({}), so it is being dropped. it was: {}",src,self.message);
            return vec![];
        }
        let peer_info = ps.peer_map.get(&src);
        let their_pub_hex = peer_info
            .and_then(|p| p.ed25519)
            .map(|p| p.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        println!("\x1b[7m{} {src} 0x{} from {:?} away said \x1b[33m{}\x1b[m",
                Utc::now().to_rfc3339(),
                their_pub_hex,
                peer_info.map(|p| p.delay).unwrap_or_default(),
                self.message
            );
        if (ps.all_chats.len() == 0
            || ps.all_chats.last().unwrap().0 != their_pub_hex
            || ps.all_chats.last().unwrap().1 != self.message)
            && self.message.len() > 0
        {
            ps.all_chats
                .push((their_pub_hex.to_string(), self.message.to_owned()));
        }
        if let Some(v) = ps.recorded_chats.get_mut(&their_pub_hex) {
            if (v.len() == 0 || v.last().unwrap() != &self.message)
                && self.message.clone().len() > 0
            {
                v.push(self.message.to_owned());
            }
        }
        if self.message.starts_with("/version") {
            // encrypt if we know the key
            let mut message_out = Self::new(ps, format!("VERSION {}\n",env!("BUILD_VERSION")));
            if let Some(pi) = &ps.peer_map.get(&src) {
                if let Some(their_pub) = &pi.ed25519 {
                    message_out = vec![
                EncryptedMessages::new(ps,their_pub, serde_json::to_vec(&message_out).unwrap()),
                ];
                }
            }
            return message_out;
        }
        if self.message.starts_with("/ping") {
            let mut message_out = Self::new(ps, "PONG".to_string());
            // encrypt if we know the key
            if let Some(pi) = &ps.peer_map.get(&src) {
                if let Some(their_pub) = &pi.ed25519 {
                    message_out = vec![
                EncryptedMessages::new(ps,their_pub, serde_json::to_vec(&message_out).unwrap()),
                ];
                }
            }

            return message_out;
        }
        return vec![];
    }
}
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
struct GroupChatMessage {
    group_name: String,
    text: String,
    timestamp: i64,
}
impl Receive for GroupChatMessage {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        _: &mut bool,
        _: &mut HashMap<String, StreamState>,
        _: &mut HashMap<String, InboundState>,
        signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        let pub_key_hex = signer
            .map(|p| p.to_string())
            .or_else(|| {
                if let Source::S(sa) = src {
                    ps.peer_map
                        .get(sa)
                        .and_then(|pi| pi.ed25519)
                        .map(|p| p.to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "unknown".to_string());
        let id = (pub_key_hex.clone(), self.timestamp);
        if !ps.displayed_group_chat_ids.contains(&id) {
            ps.displayed_group_chat_ids.insert(id);
            print_group_chat_msg(&pub_key_hex, &self);
        }
        vec![]
    }
}
impl GroupChatMessage {
    fn send(ps: &mut PeerState, group_name: String, text: String) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let gcm = GroupChatMessage {
            group_name,
            text,
            timestamp,
        };
        let msg_val = serde_json::to_value(&Message::GroupChatMessage(gcm.clone())).unwrap();
        let peers: Vec<Ed25519Pub> = ps.peer_map_by_pub.keys().cloned().collect();
        for pub_key in peers {
            msgs_to_pub(ps, pub_key, &vec![msg_val.clone()]);
        }
        ps.group_chat_outbox.push(gcm);
        ps.group_chat_backoff_delay_ms = 500.0;
        ps.group_chat_backoff_next = Some(Instant::now() + Duration::from_millis(500));
    }
}
fn announce_version_change(ps: &mut PeerState) {
    let current_version = env!("BUILD_VERSION");
    let last_version_path = "./cjp2p/state/last_version.txt";
    let last_version = fs::read_to_string(last_version_path).unwrap_or_default();
    let _ = fs::write(last_version_path, current_version);
    if !last_version.trim().is_empty() && last_version.trim() != current_version {
        GroupChatMessage::send(
            ps,
            ps.last_group.clone(),
            format!("* now running {}", current_version),
        );
    }
}
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct PleaseListContent {}
impl Receive for PleaseListContent {
    fn receive(
        self,
        _: &mut PeerState,
        _: &Source,
        might_be_ip_spoofing: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        _: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        let mut results: Vec<(String, u64)> = vec![];
        let limit = 70 * !*might_be_ip_spoofing as usize + 1;
        for path in fs::read_dir("./cjp2p/public/blake3")
            .unwrap_or_else(|_| fs::read_dir("/dev/null").unwrap())
        {
            let p = path.unwrap().path();
            let length = match File::open(&p).and_then(|f| f.metadata()) {
                Ok(m) => m.len(),
                Err(_) => continue,
            };
            if p.file_name().unwrap_or_default().len() != 64 || length == 1 << 18 {
                continue;
            }
            let hash = p.file_name().unwrap().to_str().unwrap();
            results.push((format!("blake3/{}", hash), length));
            if results.len() > limit {
                break;
            }
        }
        if results.len() <= limit {
            for path in fs::read_dir("./cjp2p/public")
                .unwrap_or_else(|_| fs::read_dir("/dev/null").unwrap())
            {
                let p = path.unwrap().path();
                if p.is_dir() {
                    continue;
                }
                let length = match File::open(&p).and_then(|f| f.metadata()) {
                    Ok(m) => m.len(),
                    Err(_) => continue,
                };
                if p.file_name().unwrap_or_default().len() != 64 || length == 1 << 18 {
                    continue;
                }
                results.push((p.file_name().unwrap().to_str().unwrap().to_string(), length));
                if results.len() > limit {
                    break;
                }
            }
        }
        if results.len() == 0 {
            return vec![];
        }
        return vec![
            Message::ContentList(ContentList { results: results }),
        ];
    }
}
impl PleaseListContent {
    fn new(ps: &PeerState) -> Vec<Message> {
        let message_out = vec![
            PleaseReturnThisMessage::new(ps),
            Message::PleaseListContent(Self {}),
        ];
        return message_out;
    }
}
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct ContentList {
    results: Vec<(String, u64)>,
}
impl Receive for ContentList {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        _: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        inbound_states: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        let Source::S(src) = *src else {
            return vec![];
        };
        let peer_info = ps.peer_map.get(&src);
        for (id, size) in &self.results {
            trace!("\x1b[7m{} {src} 0x{} from {:?} has \x07\x1b[32m{:?}\x1b[m",
                    Utc::now().to_rfc3339(),
                    peer_info.and_then(|p| p.ed25519).map(|p| p.to_string()).unwrap_or_default(),
                    peer_info.map(|p| p.delay).unwrap_or_default(),
                    self.results
                );
            if !is_safe_relative_path(id) {
                return vec![];
            }
            if let Some(i) = inbound_states.get_mut(id) {
                i.peers.insert(src);
            } else {
                InboundState::send_content_peers_from_disk(&id, 1, &src);
            }
            match ps.list_results.get_mut(&id.to_owned()) {
                Some(h) => h.0 += 1,
                None => {
                    ps.list_results.insert(id.to_owned(), (1, *size));
                    ()
                }
            }
        }

        return vec![];
    }
}

// forward secrecy, 2x the CPU as FastEncryptedMessages
#[serde_as]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct EncryptedMessages {
    #[schemars(with = "String")]
    #[serde_as(as = "Base64")]
    base64: Vec<u8>,
    noise_params: String,
}
impl EncryptedMessages {
    fn new(ps: &PeerState, their_pub: &Ed25519Pub, message: Vec<u8>) -> Message {
        use curve25519_dalek::edwards::CompressedEdwardsY;
        let their_x25519 = CompressedEdwardsY(*their_pub.as_bytes())
            .decompress()
            .expect("valid ed25519 public key")
            .to_montgomery()
            .to_bytes();
        let mut noise = Builder::new(NOISE_PARAMS.parse().unwrap())
            .local_private_key(&ps.keypair.x25519_private())
            .remote_public_key(&their_x25519)
            .build_initiator()
            .unwrap();
        let mut buf = [0u8; 99999];
        let len = noise.write_message(&message, &mut buf).unwrap();
        let message_out = Message::EncryptedMessages(Self {
            base64: buf[..len].to_vec(),
            noise_params: NOISE_PARAMS.to_string(),
        });
        return message_out;
    }
}
impl Receive for EncryptedMessages {
    fn receive(
        self,
        ps: &mut PeerState,
        src_: &Source,
        might_be_ip_spoofing: &mut bool,
        stream_states: &mut HashMap<String, StreamState>,
        inbound_states: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        let Source::S(src) = *src_ else {
            return vec![];
        };
        let mut noise = Builder::new(NOISE_PARAMS.parse().unwrap())
            .local_private_key(&ps.keypair.x25519_private())
            .build_responder()
            .unwrap();
        let mut message_in_bytes = vec![0u8; 99999];
        let Ok(len) = noise.read_message(&self.base64, &mut message_in_bytes) else {
            info!("failed to decrypt a message from {src}");
            return vec![];
        };
        let their_x25519: [u8; 32] = noise.get_remote_static().unwrap().try_into().unwrap();
        let Some((Source::S(_), their_pub)) = ps.x25519_to_ed25519(their_x25519).clone() else {
            return vec![];
        };

        if let Some(pi) = ps.peer_map.get_mut(&src) {
            pi.ed25519 = Some(their_pub);
        } else {
            let mut pi = PeerInfo::new();
            pi.ed25519 = Some(their_pub);
            pi.delay = Duration::from_millis(120);
            ps.peer_map.insert(src, pi);
        }
        if ps.peer_map_by_pub.insert(their_pub, src_.clone()).is_none() {
            info!("new pub found: {}", their_pub);
        }


        message_in_bytes.truncate(len);
        trace!("handling decrypted message from {src} {}: {}",
                    their_pub.to_string(),
                     String::from_utf8_lossy(&message_in_bytes));
        let messages: Messages = match serde_json::from_slice(&message_in_bytes) {
            Ok(r) => r,
            Err(e) => {
                debug!( "could not deserialize incoming messages from {} {e}  :  {}",src,
                    String::from_utf8_lossy(&message_in_bytes));
                return vec![];
            }
        };
        let messages = messages.0;

        *might_be_ip_spoofing &= ps.check_key(&messages, src);
        if ps.ws_vec.len() > 0 {
            let message_out_string =
                serde_json::to_string(
                    &json![
                            [Message::Forwarded(Forwarded{
                                src:src,
                                from_ed25519:Some(their_pub),
                                maybe_ed25519:None,
                                messages: String::from_utf8_lossy(&message_in_bytes).to_string(),
                                might_be_ip_spoofing: *might_be_ip_spoofing,
                            })]],
                )
                .unwrap();
                trace!( "sending decrypted message {} to {} websockets", message_out_string,ps.ws_vec.len());
            for ws in &mut ps.ws_vec {
                if ws
                    .write(tungstenite::Message::Text(
                        message_out_string.clone().into(),
                    ))
                    .is_ok()
                {
                    ws.flush().ok();
                }
            }
        }
        return ps.handle_messages(
            messages,
            &Source::S(src),
            might_be_ip_spoofing,
            stream_states,
            inbound_states,
            Some(their_pub),
        );
    }
}

// Static-static X25519 ECDH + AES-256-GCM. No ephemeral keys, no handshake, no RTT.
// Not forward-secret by design -- the shared secret is stable between any two peers.
#[serde_as]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct FastEncryptedMessages {
    #[schemars(with = "String")]
    #[serde_as(as = "Base64")]
    nonce: [u8; 12],
    sender: Ed25519Pub,
    #[schemars(with = "String")]
    #[serde_as(as = "Base64")]
    ciphertext: Vec<u8>,
}
impl FastEncryptedMessages {
    #[allow(dead_code)]
    fn new(ps: &PeerState, their_pub: &Ed25519Pub, message: Vec<u8>) -> Message {
        use aes_gcm::{aead::Aead, Aes256Gcm, NewAead, Nonce};
        use curve25519_dalek::{edwards::CompressedEdwardsY, montgomery::MontgomeryPoint};

        let their_x25519 = CompressedEdwardsY(*their_pub.as_bytes())
            .decompress()
            .expect("valid ed25519 public key")
            .to_montgomery()
            .to_bytes();

        let shared = MontgomeryPoint(their_x25519)
            .mul_clamped(ps.keypair.x25519_private())
            .to_bytes();

        let aes_key = Sha256::digest(shared);
        let nonce: [u8; 12] = rand::rng().random();
        let cipher = Aes256Gcm::new(&aes_key.into());
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), message.as_ref())
            .unwrap();

        Message::FastEncryptedMessages(Self {
            nonce,
            sender: ps.keypair.public,
            ciphertext,
        })
    }
}
impl Receive for FastEncryptedMessages {
    fn receive(
        self,
        ps: &mut PeerState,
        src_: &Source,
        might_be_ip_spoofing: &mut bool,
        stream_states: &mut HashMap<String, StreamState>,
        inbound_states: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        use aes_gcm::{aead::Aead, Aes256Gcm, NewAead, Nonce};
        use curve25519_dalek::{edwards::CompressedEdwardsY, montgomery::MontgomeryPoint};

        let Source::S(src) = *src_ else {
            return vec![];
        };
        let sender_x25519 = CompressedEdwardsY(*self.sender.as_bytes())
            .decompress()
            .expect("Ed25519Pub invariant: valid Edwards point")
            .to_montgomery()
            .to_bytes();
        let shared = MontgomeryPoint(sender_x25519)
            .mul_clamped(ps.keypair.x25519_private())
            .to_bytes();
        let aes_key = Sha256::digest(shared);
        let cipher = Aes256Gcm::new(&aes_key.into());
        let Ok(plaintext) =  cipher.decrypt(Nonce::from_slice(&self.nonce), self.ciphertext.as_ref()) else {
            info!("failed to fast-decrypt a message from {src}");
            return vec![];
        };
        if let Some(pi) = ps.peer_map.get_mut(&src) {
            pi.ed25519 = Some(self.sender);
        } else {
            let mut pi = PeerInfo::new();
            pi.ed25519 = Some(self.sender);
            pi.delay = Duration::from_millis(120);
            ps.peer_map.insert(src, pi);
        }
        if ps.peer_map_by_pub.insert(self.sender, src_.clone()).is_none() {
            info!("new pub found: {}", self.sender);
        }

        trace!("handling fast-decrypted message from {src} {}: {}",
                self.sender.to_string(),
                String::from_utf8_lossy(&plaintext));

        let messages: Messages = match serde_json::from_slice(&plaintext) {
            Ok(r) => r,
            Err(e) => {
                debug!("could not deserialize fast-encrypted messages from {} {e}: {}",
                        src, String::from_utf8_lossy(&plaintext));
                return vec![];
            }
        };
        let messages = messages.0;
        *might_be_ip_spoofing &= ps.check_key(&messages, src);

        if ps.ws_vec.len() > 0 {
            let message_out_string = serde_json::to_string(&json![
                    [Message::Forwarded(Forwarded {
                        src: src,
                        from_ed25519: Some(self.sender),
                        maybe_ed25519: None,
                        messages: String::from_utf8_lossy(&plaintext).to_string(),
                        might_be_ip_spoofing: *might_be_ip_spoofing,
                    })]
                ])
            .unwrap();
                trace!("sending fast-decrypted message {} to {} websockets", message_out_string, ps.ws_vec.len());
            for ws in &mut ps.ws_vec {
                if ws
                    .write(tungstenite::Message::Text(
                        message_out_string.clone().into(),
                    ))
                    .is_ok()
                {
                    ws.flush().ok();
                }
            }
        }
        return ps.handle_messages(
            messages,
            &Source::S(src),
            might_be_ip_spoofing,
            stream_states,
            inbound_states,
            Some(self.sender),
        );
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
struct SignedMessage {
    ed25519: Ed25519Pub,
    #[schemars(with = "String")]
    #[serde_as(as = "Base64")]
    signature: Vec<u8>,
    #[schemars(with = "Option<String>")]
    #[serde_as(as = "Option<Base64>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payload: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payload_json: Option<String>,
}
impl SignedMessage {
    fn new(ps: &PeerState, messages: Vec<u8>) -> Message {
        let signature = ps.keypair.sign(&messages).to_vec();
        Message::SignedMessage(Self {
            ed25519: ps.keypair.public,
            signature,
            payload: None,
            payload_json: Some(String::from_utf8(messages).unwrap()),
        })
    }
    fn payload_bytes(&self) -> Option<&[u8]> {
        if let Some(s) = &self.payload_json {
            return Some(s.as_bytes());
        }
        self.payload.as_deref()
    }
}
impl Receive for SignedMessage {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        stream_states: &mut HashMap<String, StreamState>,
        inbound_states: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        use ed25519_dalek::{Verifier, VerifyingKey};
        let verifying_key = match VerifyingKey::from_bytes(self.ed25519.as_bytes()) {
            Ok(k) => k,
            Err(_) => {
                warn!("SignedMessage: bad ed25519 key from {:?}", src);
                return vec![];
            }
        };
        let signature = match ed25519_dalek::Signature::try_from(self.signature.as_slice()) {
            Ok(s) => s,
            Err(_) => {
                warn!("SignedMessage: bad signature from {:?}", src);
                return vec![];
            }
        };
        let payload_bytes = match self.payload_bytes() {
            Some(b) => b,
            None => {
                warn!("SignedMessage: no payload from {:?}", src);
                return vec![];
            }
        };
        if verifying_key.verify(payload_bytes, &signature).is_err() {
            warn!("SignedMessage: invalid signature from {:?}", src);
            return vec![];
        }
        let messages: Messages = match serde_json::from_slice(payload_bytes) {
            Ok(r) => r,
            Err(e) => {
                debug!("could not deserialize signed messages from {:?}: {e}", src);
                return vec![];
            }
        };
        let messages = messages.0;
        // Cache any Latest message found inside this valid SignedMessage
        // since it saves the signature, this couldnt be handled inside the Latest receiver
        // without passing the signature and the payload down the handling chain so its special case either way, but maybe this should be in a different function in Latest
        for msg in &messages {
            if let Message::Latest(latest) = msg {
                if latest.ed25519 != self.ed25519
                    || !is_safe_relative_path(&latest.name)
                    || latest.sha256.len() != 64
                    || !hex::decode(&latest.sha256).is_ok()
                {
                    continue;
                }
                let pub_hex = self.ed25519.to_string();
                let cache_path = latest_cache_path(&pub_hex, &latest.name);
                let cached_seq = load_seq_from_latest_cache(&cache_path);
                if latest.seq > cached_seq {
                    if let Some(dir) = Path::new(&cache_path).parent() {
                        fs::create_dir_all(dir).ok();
                    }
                    if let Ok(json) =
                        serde_json::to_vec_pretty(&Message::SignedMessage(self.clone()))
                    {
                        fs::write(&cache_path, json).ok();
                    }
                    info!("cached latest {}/{} seq={} sha256={}", pub_hex, latest.name, latest.seq, latest.sha256);
                    // If an existing latest was updated to a new sha256 that we don't have,
                    // and no active content gateway (still in its 300ms window) will pick it
                    // up via Latest::receive, fetch it now, so we don't have mismatched caches.
                    if cached_seq > 0
                        && !Path::new(&format!("./cjp2p/public/{}", latest.sha256)).exists()
                        && !inbound_states.contains_key(&latest.sha256)
                        && !ps.content_gateways.iter().any(|cg| {
                            cg.pending_latest.as_ref().map_or(false, |l| {
                                l.pub_key == latest.ed25519
                                    && l.name == latest.name
                                    && l.delay_for_newest_until
                                        .map_or(false, |t| !has_passed(t))
                            })
                        })
                    {
                        info!(
                            "latest updated {}/{}: fetching new sha256 {}",
                            pub_hex, latest.name, latest.sha256
                        );
                        InboundState::new(&latest.sha256, ps, inbound_states);
                    }
                }
            }
            if let Message::Content(c) = msg {
                let sig_bytes = match <[u8; 64]>::try_from(self.signature.as_slice()) {
                    Ok(s) => s,
                    _ => continue,
                };
                let ss = match stream_states.get_mut(&c.id) {
                    Some(s) => s,
                    _ => continue,
                };
                if ss.origin_pubkey != self.ed25519 || c.base64.len() == 0 {
                    continue;
                }
                let block_number = c.offset / BLOCK_SIZE!();
                let sig_offset = block_number * 64;
                let block_end = c.offset + c.base64.len();
                let new_eof = (block_end + (1 << 20)).max(ss.eof);
                if new_eof > ss.eof {
                    ss.resize_to(new_eof);
                }
                if block_end > ss.data_file_len {
                    ss.sig_mmap[sig_offset..sig_offset + 64].copy_from_slice(&sig_bytes);
                }
            }
        }
        if let Source::S(src) = src { *might_be_ip_spoofing &= ps.check_key(&messages, *src); }
        if ps.ws_vec.len() > 0 {
            let message_out_string = serde_json::to_string(&json![
                [Message::Forwarded(Forwarded{
                    src: if let Source::S(s) = src { *s } else { "0.0.0.0:0".parse().unwrap() },
                    from_ed25519: Some(self.ed25519),
                    maybe_ed25519: None,
                    messages: String::from_utf8_lossy(payload_bytes).to_string(),
                    might_be_ip_spoofing: *might_be_ip_spoofing,
                })]])
            .unwrap();
            trace!("sending signed message from ed25519={} to {} websockets",
            self.ed25519.to_string(),
                ps.ws_vec.len());
            for ws in &mut ps.ws_vec {
                if ws
                    .write(tungstenite::Message::Text(
                        message_out_string.clone().into(),
                    ))
                    .is_ok()
                {
                    ws.flush().ok();
                }
            }
        }
        return ps.handle_messages(
            messages,
            src,
            might_be_ip_spoofing,
            stream_states,
            inbound_states,
            Some(self.ed25519),
        );
    }
}

fn is_safe_relative_path(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('\\')
        && !name.contains('\0')
        && !name.contains("/.")
        && !name.starts_with('.')
        && !name.starts_with('/')
        && !name.ends_with('/')
}

fn latest_cache_path(pub_hex: &str, name: &str) -> String {
    format!("./cjp2p/metadata/latest/{}/{}.json", pub_hex, name)
}

fn load_seq_from_latest_cache(cache_path: &str) -> u64 {
    let Ok(json) = fs::read(cache_path) else {
        return 0;
    };
    let Ok(msg) = serde_json::from_slice::<Message>(&json) else {
        return 0;
    };
    let Message::SignedMessage(sm) = msg else {
        return 0;
    };
    let Ok(msgs) = sm
        .payload_bytes()
        .and_then(|b| serde_json::from_slice::<Vec<Message>>(b).ok())
        .ok_or(())
    else {
        return 0;
    };
    for inner in msgs {
        if let Message::Latest(l) = inner {
            return l.seq;
        }
    }
    0
}

fn load_sha256_from_latest_cache(cache_path: &str) -> Option<String> {
    let json = fs::read(cache_path).ok()?;
    let msg = serde_json::from_slice::<Message>(&json).ok()?;
    let Message::SignedMessage(sm) = msg else {
        return None;
    };
    let msgs = sm
        .payload_bytes()
        .and_then(|b| serde_json::from_slice::<Vec<Message>>(b).ok())?;
    for inner in msgs {
        if let Message::Latest(l) = inner {
            return Some(l.sha256);
        }
    }
    None
}

fn load_latest_signed_message(cache_path: &str) -> Vec<Message> {
    let Ok(json) = fs::read(cache_path) else {
        return vec![];
    };
    let Ok(msg) = serde_json::from_slice::<Message>(&json) else {
        return vec![];
    };
    vec![msg]
}

fn create_and_cache_latest(ps: &PeerState, name: &str, pub_hex: &str, seq: u64, cache_path: &str) {
    let origin_path = format!("./cjp2p/origin/{}", name);
    let temp_name = format!(".tmp_{:016x}", rand::rng().random::<u64>());
    let temp_path = format!("./cjp2p/public/{}", temp_name);
    if fs::copy(&origin_path, &temp_path).is_err() {
        warn!("create_and_cache_latest: failed to copy origin/{}", name);
        return;
    }
    let contents = match fs::read(&temp_path) {
        Ok(c) => c,
        Err(e) => {
            warn!("create_and_cache_latest: read temp failed: {e}");
            fs::remove_file(&temp_path).ok();
            return;
        }
    };
    let sha256 = format!("{:x}", Sha256::digest(&contents));
    let hash_path = format!("./cjp2p/public/{}", sha256);
    if let Err(e) = fs::rename(&temp_path, &hash_path) {
        warn!("create_and_cache_latest: rename to {} failed: {e}", sha256);
        fs::remove_file(&temp_path).ok();
        return;
    }
    let latest = Latest {
        ed25519: ps.keypair.public,
        name: name.to_string(),
        sha256: sha256.clone(),
        seq,
    };
    let payload = serde_json::to_vec(&vec![Message::Latest(latest)]).unwrap();
    let signed_msg = SignedMessage::new(ps, payload);
    if let Some(dir) = Path::new(cache_path).parent() {
        fs::create_dir_all(dir).ok();
    }
    if let Err(e) = fs::write(cache_path, serde_json::to_vec_pretty(&signed_msg).unwrap()) {
        warn!("create_and_cache_latest: write cache failed: {e}");
        return;
    }
    info!("created latest for {}/{} sha256={} seq={}", pub_hex, name, sha256, seq);
}

// GetLatest: ask for the latest signed hash for a named file owned by ed25519 publisher
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
struct GetLatest {
    ed25519: Ed25519Pub,
    name: String,
}
impl Receive for GetLatest {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        _: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        _: &mut HashMap<String, InboundState>,
        signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        if !is_safe_relative_path(&self.name) {
            return vec![];
        }
        let pub_hex = self.ed25519.to_string();
        let cache_path = latest_cache_path(&pub_hex, &self.name);
        let mut result = vec![];
        let mut source = "";

        if ps.keypair.public == self.ed25519 {
            let origin_path = format!("./cjp2p/origin/{}", self.name);
            if let Ok(origin_meta) = fs::metadata(&origin_path)
                .ok()
                .filter(|m| m.is_file())
                .ok_or(())
            {
                let origin_seq = origin_meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(1);
                let cached_seq = load_seq_from_latest_cache(&cache_path);
                if cached_seq < origin_seq || !Path::new(&cache_path).exists() {
                    create_and_cache_latest(ps, &self.name, &pub_hex, origin_seq, &cache_path);
                }
                result = load_latest_signed_message(&cache_path);
                source = "origin";
            }
        }

        if result.is_empty() && Path::new(&cache_path).exists() {
            result = load_latest_signed_message(&cache_path);
            source = "cache";
        }

        if !result.is_empty() {
            let sender = if let Some(pk) = signer {
                pk.to_string()
            } else {
                match src {
                    Source::S(sa) => ps
                        .peer_map
                        .get(sa)
                        .and_then(|pi| pi.ed25519)
                        .map(|pk| pk.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    Source::None => "websocket".to_string(),
                }
            };
            info!("sending Latest {} to {src:?} from {sender}", self.name);
            fs::create_dir_all("./cjp2p/log").ok();
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .write(true)
                .open("./cjp2p/log/latest.json")
            {
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;
                file.write_all(
                    &serde_json::to_vec(&json!({
                        "name": self.name,
                        "source": source,
                        "sender": sender,
                        "src": src,
                        "t": t,
                    }))
                    .unwrap(),
                )
                .ok();
                file.write_all(b"\n").ok();
            }
        }

        result
    }
}

// Latest: the signed response carrying the sha256 and sequence number of a named file
#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
struct Latest {
    ed25519: Ed25519Pub,
    name: String,
    sha256: String,
    seq: u64,
}
impl Receive for Latest {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        _: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        _: &mut HashMap<String, InboundState>,
        signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        // Caching is handled upstream in SignedMessage::receive; here we resolve waiting connections.
        if signer != Some(self.ed25519) {
            warn!("Latest received without matching SignedMessage wrapper -- dropping");
            return vec![];
        }
        if self.sha256.len() != 64 || hex::decode(&self.sha256).is_err() {
            warn!("Latest has invalid sha256: {}", self.sha256);
            return vec![];
        }
        for cg in &mut ps.content_gateways {
            if let Some(l) = &cg.pending_latest {
                if l.pub_key == self.ed25519
                    && l.name == self.name
                    && cg.pending_latest.as_ref().map_or(0, |l| l.highest_version) < self.seq as i64
                {
                    if let Source::S(src_addr) = *src {
                        InboundState::send_content_peers_from_disk(&self.sha256, 0, &src_addr);
                    }
                    cg.id = self.sha256.clone();
                }
            }
        }
        vec![]
    }
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct PleaseListSupportedMessages {}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
struct SupportedMessages {
    schema: serde_json::Value,
}

impl Receive for PleaseListSupportedMessages {
    fn receive(
        self,
        _ps: &mut PeerState,
        _src: &Source,
        _: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        _: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        let schema = schema_for!(Message);
        let schema_value = serde_json::to_value(&schema).unwrap_or(serde_json::Value::Null);
        vec![Message::SupportedMessages(SupportedMessages { schema: schema_value })]
    }
}

impl Receive for SupportedMessages {
    fn receive(
        self,
        _ps: &mut PeerState,
        _src: &Source,
        _: &mut bool,
        _stream_states: &mut HashMap<String, StreamState>,
        _: &mut HashMap<String, InboundState>,
        _signer: Option<Ed25519Pub>,
    ) -> Vec<Message> {
        vec![]
    }
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[enum_dispatch]
enum Message {
    PleaseSendPeers(PleaseSendPeers),
    Peers(Peers),
    PleaseSendContent(PleaseSendContent),
    Content(Content),
    PleaseReturnThisMessage(PleaseReturnThisMessage),
    ReturnedMessage(ReturnedMessage),
    MaybeTheyHaveSome(MaybeTheyHaveSome),
    PleaseAlwaysReturnThisMessage(PleaseAlwaysReturnThisMessage),
    AlwaysReturned(AlwaysReturned),
    MyPublicKey(MyPublicKey),
    ChatMessage(ChatMessage),
    GroupChatMessage(GroupChatMessage),
    EncryptedMessages(EncryptedMessages),
    FastEncryptedMessages(FastEncryptedMessages),
    SignedMessage(SignedMessage),
    PleaseListContent(PleaseListContent),
    ContentList(ContentList),
    YouShouldSeeThis(YouShouldSeeThis),
    IJustSawThis(IJustSawThis),
    Forward(Forward),
    Forwarded(Forwarded),
    SignedPub(SignedPub),
    GetPubByEth(GetPubByEth),
    WhereAreThey(WhereAreThey),
    GetLatest(GetLatest),
    Latest(Latest),
    PleaseListSupportedMessages(PleaseListSupportedMessages),
    SupportedMessages(SupportedMessages),
}

// this struct only exists to be able to get that VecSkipError in there.
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct Messages(#[serde_as(as = "VecSkipError<_,ErrorInspector>")] Vec<Message>);

struct ErrorInspector;

impl InspectError for ErrorInspector {
    fn inspect_error(error: impl serde::de::Error) {
        debug!( "could not deserialize an incoming message {error}");
    }
}

#[enum_dispatch(Message)]
trait Receive {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        stream_states: &mut HashMap<String, StreamState>,
        inbound_states: &mut HashMap<String, InboundState>,
        signer: Option<Ed25519Pub>,
    ) -> Vec<Message>;
}

fn msgs_to_pub(ps: &mut PeerState, to: Ed25519Pub, messages: &Vec<Value>) -> () {
    if let Some(Source::S(sa)) = ps.peer_map_by_pub.get(&to) {
        let mut message_out: Vec<Value> = vec![];
        if rand::rng().random::<u32>() % 37 == 0 {
            message_out.push(serde_json::to_value(PleaseReturnThisMessage::new(ps)).unwrap());
        } else if rand::rng().random::<u32>() % 5 == 0
            && ps.p.my_ed25519_signed_by_web_wallet.is_some()
        {
            message_out.push(serde_json::to_value(MyPublicKey::new(ps)).unwrap());
        }
        // an optimization would be to skip serde once we know where
        // it should go and just copy the message bytes
        for m in messages {
            message_out.push(serde_json::to_value(m).unwrap());
        }
        message_out = vec![
                            serde_json::to_value(&EncryptedMessages::new(ps,&to, serde_json::to_vec(&message_out).unwrap())).unwrap(),
                        ];
        let c = ps.always_returned(*sa);
        if c.len() > 0 {
            message_out.push(serde_json::to_value(&c[0]).unwrap());
        }
        let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
        if c.len() > 0 {
            message_out.pop();
        }
        trace!( "sending message {:?} to {sa} {to}", String::from_utf8_lossy(&message_out_bytes));
        ps.socket.send_to(&message_out_bytes, sa).ok();
        return;
    }
    ps.socket.set_nonblocking(false).unwrap();
    warn!("failed to find ed25519 requested {}, searching..",to);
    let peers = ps.best_peers(250, 6);
    info!("searching {} peers for ed25519 addr",peers.len());
    for sa in peers {
        let mut message_out = vec![Message::WhereAreThey(WhereAreThey{ed25519h:to})];
        message_out.append(&mut ps.always_returned(sa));
        let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
        ps.socket.send_to(&message_out_bytes, sa).ok();
    }
    ps.socket.set_nonblocking(true).unwrap();
}

fn chat_to_pub(ps: &mut PeerState, their_pub: Ed25519Pub, msg: &String) -> () {
    let mut message_out: Vec<Value> = Vec::new();
    for m in ChatMessage::new(&ps, msg.clone()) {
        message_out.push(serde_json::to_value(m).unwrap());
    }
    msgs_to_pub(ps, their_pub, &message_out);
}

// Android JNI entry point for the standalone APK (com.cjp2p package).
// The Tauri APK has its own entry point in tauri-app/src-tauri/src/lib.rs
// because #[no_mangle] symbols in rlib dependencies are dead-stripped out
// of the final cdylib -- the function must live in the cdylib's own crate.
#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod android_jni {
    use jni::objects::{JClass, JString};
    use jni::JNIEnv;

    /// Called once from BackendService.onStartCommand in the standalone APK.
    #[no_mangle]
    pub extern "C" fn Java_com_cjp2p_NativeLib_start<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        data_dir: JString<'local>,
        lcdp_port: i32,
        http_port: i32,
    ) {
        let dir: String = env
            .get_string(&data_dir)
            .map(|s| s.into())
            .unwrap_or_default();
        let lp = lcdp_port as u16;
        let hp = http_port as u16;
        let _ = std::thread::Builder::new()
            .name("cjp2p".into())
            .spawn(move || {
                super::run_from_android(&dir, lp, hp);
            });
    }
}

fn is_local(stream: &TcpStream) -> bool {
    stream
        .peer_addr()
        .map(|a| {
            let local = a.ip().is_loopback();
            if !local {
                info!("remote http request from {}", a);
            }
            local
        })
        .unwrap_or_else(|e| {
            trace!("peer_addr race: {e}"); // Transport endpoint not connected
            false
        })
}

fn has_passed(deadline: std::time::Instant) -> bool {
    std::time::Instant::now() >= deadline
}

fn log_if_slow(nowi: Instant, line: String) {
    if cfg!(target_os = "android") {
        return;
    }
    let prof = nowi.elapsed();
    let txt = format!("line {} took {:?} since timer set \x1b[m",line,prof);
    if prof > Duration::from_millis(80) {
        error!("\x1b[7;31m {} ",txt);
    } else if prof > Duration::from_millis(40) {
        warn!("{}",txt);
    } else if prof > Duration::from_millis(20) {
        info!("{}",txt);
    } else if prof > Duration::from_millis(10) {
        debug!("{}",txt);
    } else {
        trace!("{}",txt);
    }
}

fn tcpstream_is_closed(stream: &TcpStream) -> bool {
    let mut buf = [0; 16];
    match stream.peek(&mut buf) {
        Ok(0) => true,
        Ok(_) => false,
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
        Err(_) => true,
    }
}
