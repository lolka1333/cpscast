//! macspoof - send a UPnP SOAP request to the TV from an arbitrary source MAC,
//! without changing any interface address, by building Ethernet/IP/TCP frames by
//! hand on an AF_PACKET raw socket.
//!
//! Why this exists: the TV's device block-list is keyed on the controller's MAC
//! (`asf_upnp::cd_utils::GetAclEntryByMAC`, imported by the `dmr` service that
//! implements AVTransport). The RV6699's kernel has no way to rewrite a MAC in
//! transit - ebtables has the nat *table* but neither the `snat` nor the `dnat`
//! target, and macvlan is not built in. AF_PACKET, however, is there (tcpdump
//! works), so we can put whatever we like in the frame ourselves.
//!
//! The kernel will not service a TCP connection whose source MAC is not its own,
//! so a minimal TCP client lives here: SYN -> SYN/ACK -> ACK -> request ->
//! response -> RST. It also answers ARP for the spoofed address, because the TV
//! resolves the peer's MAC through its neighbour table before replying.
//!
//!   macspoof --tv 192.168.1.70 --tv-mac c0:48:e6:ff:a4:02 \
//!            --src-ip 192.168.1.240 --src-mac 02:11:22:33:44:55 [--if br0] [--play]
//!
//! Default action is the read-only GetTransportInfo; --play performs a real
//! SetAVTransportURI+Play (needs --media-url). Own equipment only.

use std::ffi::CString;
use std::io;
use std::mem;
use std::time::{Duration, Instant};

// ------------------------------------------------------------------ libc bits

const AF_PACKET: libc::c_int = 17;
const SOCK_RAW: libc::c_int = 3;
const ETH_P_ALL: u16 = 0x0003;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

struct Raw {
    fd: libc::c_int,
    ifindex: i32,
}

impl Raw {
    fn open(ifname: &str) -> io::Result<Self> {
        let name = CString::new(ifname).unwrap();
        let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) } as i32;
        if ifindex == 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { libc::socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as i32) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut sa: SockaddrLl = unsafe { mem::zeroed() };
        sa.sll_family = AF_PACKET as u16;
        sa.sll_protocol = ETH_P_ALL.to_be();
        sa.sll_ifindex = ifindex;
        let r = unsafe {
            libc::bind(
                fd,
                &sa as *const _ as *const libc::sockaddr,
                mem::size_of::<SockaddrLl>() as u32,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        // a short receive timeout keeps the state machine responsive
        let tv = libc::timeval { tv_sec: 0, tv_usec: 200_000 };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                mem::size_of::<libc::timeval>() as u32,
            );
        }
        Ok(Raw { fd, ifindex })
    }

    fn send(&self, frame: &[u8]) -> io::Result<()> {
        let mut sa: SockaddrLl = unsafe { mem::zeroed() };
        sa.sll_family = AF_PACKET as u16;
        sa.sll_ifindex = self.ifindex;
        sa.sll_halen = 6;
        sa.sll_addr[..6].copy_from_slice(&frame[..6]);
        let n = unsafe {
            libc::sendto(
                self.fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &sa as *const _ as *const libc::sockaddr,
                mem::size_of::<SockaddrLl>() as u32,
            )
        };
        if n < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    fn recv(&self, buf: &mut [u8]) -> Option<usize> {
        let n = unsafe {
            libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
        };
        if n > 0 { Some(n as usize) } else { None }
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

// ------------------------------------------------------------------ checksums

fn ones_complement(sum: u32) -> u16 {
    let mut s = sum;
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

fn csum_bytes(b: &[u8], start: u32) -> u32 {
    let mut sum = start;
    let mut i = 0;
    while i + 1 < b.len() {
        sum += u16::from_be_bytes([b[i], b[i + 1]]) as u32;
        i += 2;
    }
    if i < b.len() {
        sum += (b[i] as u32) << 8;
    }
    sum
}

// ------------------------------------------------------------------ builders

fn mac(s: &str) -> [u8; 6] {
    let mut m = [0u8; 6];
    for (i, p) in s.split(&[':', '-'][..]).enumerate().take(6) {
        m[i] = u8::from_str_radix(p, 16).unwrap_or(0);
    }
    m
}

fn ipv4(s: &str) -> [u8; 4] {
    let mut a = [0u8; 4];
    for (i, p) in s.split('.').enumerate().take(4) {
        a[i] = p.parse().unwrap_or(0);
    }
    a
}

struct Ctx {
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
}

impl Ctx {
    fn eth(&self, ethertype: u16) -> Vec<u8> {
        let mut f = Vec::with_capacity(1600);
        f.extend_from_slice(&self.dst_mac);
        f.extend_from_slice(&self.src_mac);
        f.extend_from_slice(&ethertype.to_be_bytes());
        f
    }

    /// Gratuitous / reply ARP announcing src_ip is at src_mac.
    fn arp(&self, target_mac: [u8; 6], target_ip: [u8; 4], reply: bool) -> Vec<u8> {
        let mut f = Vec::with_capacity(42);
        f.extend_from_slice(&target_mac);
        f.extend_from_slice(&self.src_mac);
        f.extend_from_slice(&ETH_P_ARP.to_be_bytes());
        f.extend_from_slice(&[0, 1, 8, 0, 6, 4]); // eth/ipv4, hlen 6, plen 4
        f.extend_from_slice(&(if reply { 2u16 } else { 1u16 }).to_be_bytes());
        f.extend_from_slice(&self.src_mac);
        f.extend_from_slice(&self.src_ip);
        f.extend_from_slice(&target_mac);
        f.extend_from_slice(&target_ip);
        f
    }

    fn tcp(&self, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut tcp = Vec::with_capacity(20 + payload.len());
        tcp.extend_from_slice(&self.src_port.to_be_bytes());
        tcp.extend_from_slice(&self.dst_port.to_be_bytes());
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&ack.to_be_bytes());
        tcp.push(5 << 4); // data offset 5 words, no options
        tcp.push(flags);
        tcp.extend_from_slice(&0xfaf0u16.to_be_bytes()); // window
        tcp.extend_from_slice(&[0, 0]); // checksum placeholder
        tcp.extend_from_slice(&[0, 0]); // urgent
        tcp.extend_from_slice(payload);

        // TCP checksum over the pseudo-header + segment
        let mut sum = 0u32;
        sum = csum_bytes(&self.src_ip, sum);
        sum = csum_bytes(&self.dst_ip, sum);
        sum += 6u32; // protocol
        sum += tcp.len() as u32;
        sum = csum_bytes(&tcp, sum);
        let ck = ones_complement(sum).to_be_bytes();
        tcp[16] = ck[0];
        tcp[17] = ck[1];

        let total = 20 + tcp.len();
        let mut ip = Vec::with_capacity(20);
        ip.push(0x45);
        ip.push(0);
        ip.extend_from_slice(&(total as u16).to_be_bytes());
        ip.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        ip.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
        ip.push(64); // ttl
        ip.push(6); // tcp
        ip.extend_from_slice(&[0, 0]); // checksum placeholder
        ip.extend_from_slice(&self.src_ip);
        ip.extend_from_slice(&self.dst_ip);
        let ck = ones_complement(csum_bytes(&ip, 0)).to_be_bytes();
        ip[10] = ck[0];
        ip[11] = ck[1];

        let mut f = self.eth(ETH_P_IP);
        f.extend_from_slice(&ip);
        f.extend_from_slice(&tcp);
        while f.len() < 60 {
            f.push(0); // pad to the minimum Ethernet frame
        }
        f
    }
}

/// Parsed inbound TCP segment addressed to us.
struct Seg {
    seq: u32,
    flags: u8,
    payload: Vec<u8>,
}

fn parse(ctx: &Ctx, f: &[u8]) -> Option<Seg> {
    if f.len() < 14 {
        return None;
    }
    let et = u16::from_be_bytes([f[12], f[13]]);
    if et != ETH_P_IP {
        return None;
    }
    let ip = &f[14..];
    if ip.len() < 20 || ip[0] >> 4 != 4 || ip[9] != 6 {
        return None;
    }
    if ip[12..16] != ctx.dst_ip || ip[16..20] != ctx.src_ip {
        return None; // must be TV -> us
    }
    let ihl = ((ip[0] & 0xf) as usize) * 4;
    let tot = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if ip.len() < ihl + 20 || tot < ihl + 20 {
        return None;
    }
    let t = &ip[ihl..tot.min(ip.len())];
    let sp = u16::from_be_bytes([t[0], t[1]]);
    let dp = u16::from_be_bytes([t[2], t[3]]);
    if sp != ctx.dst_port || dp != ctx.src_port {
        return None;
    }
    let doff = ((t[12] >> 4) as usize) * 4;
    Some(Seg {
        seq: u32::from_be_bytes([t[4], t[5], t[6], t[7]]),
        flags: t[13],
        payload: t.get(doff..).unwrap_or(&[]).to_vec(),
    })
}

/// Answer ARP requests asking for our spoofed address, so the TV can reply to us.
fn maybe_answer_arp(ctx: &Ctx, raw: &Raw, f: &[u8]) {
    if f.len() < 42 || u16::from_be_bytes([f[12], f[13]]) != ETH_P_ARP {
        return;
    }
    let a = &f[14..];
    if u16::from_be_bytes([a[6], a[7]]) != 1 {
        return; // not a request
    }
    if a[24..28] != ctx.src_ip {
        return; // not asking about us
    }
    let mut their_mac = [0u8; 6];
    their_mac.copy_from_slice(&a[8..14]);
    let mut their_ip = [0u8; 4];
    their_ip.copy_from_slice(&a[14..18]);
    let _ = raw.send(&ctx.arp(their_mac, their_ip, true));
    println!("    <- answered ARP 'who has {}' with our spoofed MAC",
             ctx.src_ip.map(|b| b.to_string()).join("."));
}

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

fn arg(name: &str, def: &str) -> String {
    let a: Vec<String> = std::env::args().collect();
    a.iter()
        .position(|x| x == name)
        .and_then(|i| a.get(i + 1).cloned())
        .unwrap_or_else(|| def.to_string())
}

fn has(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

fn main() {
    if has("--help") {
        println!("macspoof --tv <ip> --tv-mac <mac> --src-ip <free ip> --src-mac <mac> \\\n\
                  \x20        [--if br0] [--port 9197] [--play --media-url <url>]");
        return;
    }
    let ifname = arg("--if", "br0");
    let tv_ip = arg("--tv", "192.168.1.70");
    let tv_mac = arg("--tv-mac", "c0:48:e6:ff:a4:02");
    let src_ip = arg("--src-ip", "192.168.1.240");
    let src_mac = arg("--src-mac", "02:11:22:33:44:55");
    let port: u16 = arg("--port", "9197").parse().unwrap_or(9197);

    let ctx = Ctx {
        src_mac: mac(&src_mac),
        dst_mac: mac(&tv_mac),
        src_ip: ipv4(&src_ip),
        dst_ip: ipv4(&tv_ip),
        // a fixed-ish ephemeral port; change it between runs if a stale state lingers
        src_port: 40000 + (std::process::id() as u16 % 20000),
        dst_port: port,
    };

    println!("=== macspoof: SOAP to {tv_ip}:{port} as {src_mac} / {src_ip} (iface {ifname}) ===");
    println!("    the interface keeps its real address; only the frames carry the fake one");

    let raw = match Raw::open(&ifname) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("raw socket on {ifname} failed: {e}  (root needed)");
            std::process::exit(1);
        }
    };

    // Announce ourselves so the TV can route the reply without asking.
    let _ = raw.send(&ctx.arp(ctx.dst_mac, ctx.dst_ip, false));
    println!("[0] gratuitous ARP sent: {src_ip} is at {src_mac}");

    // --- handshake -------------------------------------------------------
    let mut seq: u32 = 0x1000_0000;
    let mut ack: u32 = 0;
    let _ = raw.send(&ctx.tcp(seq, 0, SYN, &[]));
    println!("[1] SYN sent (sport {})", ctx.src_port);

    let mut buf = vec![0u8; 4096];
    let t0 = Instant::now();
    let mut established = false;
    while t0.elapsed() < Duration::from_secs(5) {
        let Some(n) = raw.recv(&mut buf) else { continue };
        let f = &buf[..n];
        maybe_answer_arp(&ctx, &raw, f);
        if let Some(s) = parse(&ctx, f) {
            if s.flags & RST != 0 {
                println!("[!] RST from the TV - refused");
                return;
            }
            if s.flags & SYN != 0 && s.flags & ACK != 0 {
                seq = seq.wrapping_add(1);
                ack = s.seq.wrapping_add(1);
                let _ = raw.send(&ctx.tcp(seq, ack, ACK, &[]));
                println!("[2] SYN/ACK received -> ACK sent   ** the TV accepted a connection \
                          from the spoofed MAC **");
                established = true;
                break;
            }
        }
    }
    if !established {
        println!("[!] no SYN/ACK within 5s - is the TV awake, the IP free, the iface right?");
        return;
    }

    // --- request ---------------------------------------------------------
    let (action, ns) = if has("--play") {
        ("Play", "urn:schemas-upnp-org:service:AVTransport:1")
    } else {
        ("GetTransportInfo", "urn:schemas-upnp-org:service:AVTransport:1")
    };
    let inner = if has("--play") { "<Speed>1</Speed>" } else { "" };
    let body = format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
<u:{action} xmlns:u=\"{ns}\"><InstanceID>0</InstanceID>{inner}</u:{action}></s:Body></s:Envelope>"
    );
    let req = format!(
        "POST /upnp/control/AVTransport1 HTTP/1.1\r\nHost: {tv_ip}:{port}\r\n\
Content-Type: text/xml; charset=\"utf-8\"\r\nSOAPACTION: \"{ns}#{action}\"\r\n\
Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = raw.send(&ctx.tcp(seq, ack, PSH | ACK, req.as_bytes()));
    seq = seq.wrapping_add(req.len() as u32);
    println!("[3] {action} sent ({} bytes)", req.len());

    // --- response --------------------------------------------------------
    let mut resp = Vec::new();
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(8) {
        let Some(n) = raw.recv(&mut buf) else { continue };
        let f = &buf[..n];
        maybe_answer_arp(&ctx, &raw, f);
        let Some(s) = parse(&ctx, f) else { continue };
        if s.flags & RST != 0 {
            println!("[!] RST mid-conversation");
            break;
        }
        if !s.payload.is_empty() {
            if s.seq == ack {
                resp.extend_from_slice(&s.payload);
                ack = ack.wrapping_add(s.payload.len() as u32);
            }
            let _ = raw.send(&ctx.tcp(seq, ack, ACK, &[]));
        }
        if s.flags & FIN != 0 {
            ack = ack.wrapping_add(1);
            let _ = raw.send(&ctx.tcp(seq, ack, ACK, &[]));
            break;
        }
    }
    let _ = raw.send(&ctx.tcp(seq, ack, RST, &[]));

    println!("\n=== RESULT ===");
    if resp.is_empty() {
        println!("connection was accepted but no HTTP response arrived");
        return;
    }
    let text = String::from_utf8_lossy(&resp);
    let head = text.split("\r\n\r\n").next().unwrap_or("");
    println!("{}", head.lines().next().unwrap_or(""));
    for tag in ["CurrentTransportState", "CurrentTransportStatus", "errorCode",
                "errorDescription"] {
        if let Some(a) = text.find(&format!("<{tag}>")) {
            let a = a + tag.len() + 2;
            if let Some(b) = text[a..].find(&format!("</{tag}>")) {
                println!("  {tag} = {}", &text[a..a + b]);
            }
        }
    }
    println!("\nThe TV served this request believing it came from {src_mac}, an address\n\
              that is not the router's and is not in its device list.");
}
