//! Minimal userspace TCP over AF_PACKET, so SOAP can be sent from an arbitrary
//! source MAC without touching any interface address.
//!
//! Why: the TV's device block-list is keyed on the controller's MAC — the `dmr`
//! service that implements AVTransport imports
//! `asf_upnp::cd_utils::GetAclEntryByMAC`. The RV6699 cannot rewrite a MAC in
//! transit (its kernel has the ebtables nat table but neither the `snat` nor the
//! `dnat` target, and macvlan is `Operation not supported`), but AF_PACKET is
//! there — tcpdump works — so the frames get built by hand instead.
//!
//! The kernel will not service a connection whose source MAC is not its own, so
//! the handshake lives here: SYN / SYN-ACK / ACK / request / reassemble / RST.
//! ARP requests for the spoofed address are answered too, because the TV
//! resolves the peer through its neighbour table before replying.
//!
//! Deliberately minimal: no retransmission, no options, no reordering. Enough
//! for one short SOAP exchange, which is all the control channel needs.

use std::ffi::CString;
use std::io;
use std::mem;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const AF_PACKET: libc::c_int = 17;
const SOCK_RAW: libc::c_int = 3;
const ETH_P_ALL: u16 = 0x0003;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

/// Monotonic per-call sequence. Every control call takes a fresh source port and
/// initial sequence number from this, so no two calls in one run share a 4-tuple.
/// Without it the port was effectively constant per process (the old code XORed
/// in `Instant::now().elapsed()`, which is ~0 ns right after the Instant is made)
/// and the TV dropped every SYN after the first as a duplicate of a connection it
/// still held in TIME_WAIT - the intermittent "no SYN/ACK" / 401-on-every-call.
static PORT_SEQ: AtomicU32 = AtomicU32::new(0);

/// Where the spoofed frames claim to come from.
#[derive(Clone)]
pub struct Spoof {
    pub iface: String,
    pub src_mac: [u8; 6],
    pub src_ip: [u8; 4],
    pub dst_mac: [u8; 6],
}

pub fn parse_mac(s: &str) -> [u8; 6] {
    let mut m = [0u8; 6];
    for (i, p) in s.split(&[':', '-'][..]).enumerate().take(6) {
        m[i] = u8::from_str_radix(p, 16).unwrap_or(0);
    }
    m
}

pub fn parse_ip(s: &str) -> [u8; 4] {
    let mut a = [0u8; 4];
    for (i, p) in s.split('.').enumerate().take(4) {
        a[i] = p.parse().unwrap_or(0);
    }
    a
}

/// Look the peer's MAC up in the kernel neighbour table, so the caller does not
/// have to pass it. Returns None when the TV has not been talked to recently.
pub fn arp_lookup(ip: &str) -> Option<[u8; 6]> {
    let txt = std::fs::read_to_string("/proc/net/arp").ok()?;
    for line in txt.lines().skip(1) {
        let mut f = line.split_whitespace();
        let addr = f.next()?;
        if addr != ip {
            continue;
        }
        let hw = f.nth(2)?; // IP, HWtype, Flags, HWaddress
        if hw.len() == 17 && hw != "00:00:00:00:00:00" {
            return Some(parse_mac(hw));
        }
    }
    None
}

// ---------------------------------------------------------------- raw socket

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
            return Err(io::Error::new(io::ErrorKind::NotFound,
                                      format!("no such interface: {ifname}")));
        }
        let fd = unsafe { libc::socket(AF_PACKET, SOCK_RAW, ETH_P_ALL.to_be() as i32) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut sa: SockaddrLl = unsafe { mem::zeroed() };
        sa.sll_family = AF_PACKET as u16;
        sa.sll_protocol = ETH_P_ALL.to_be();
        sa.sll_ifindex = ifindex;
        if unsafe {
            libc::bind(fd, &sa as *const _ as *const libc::sockaddr,
                       mem::size_of::<SockaddrLl>() as u32)
        } < 0
        {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        let tv = libc::timeval { tv_sec: 0, tv_usec: 200_000 };
        unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO,
                             &tv as *const _ as *const libc::c_void,
                             mem::size_of::<libc::timeval>() as u32);
        }
        Ok(Raw { fd, ifindex })
    }

    fn send(&self, frame: &[u8]) {
        let mut sa: SockaddrLl = unsafe { mem::zeroed() };
        sa.sll_family = AF_PACKET as u16;
        sa.sll_ifindex = self.ifindex;
        sa.sll_halen = 6;
        sa.sll_addr[..6].copy_from_slice(&frame[..6]);
        unsafe {
            libc::sendto(self.fd, frame.as_ptr() as *const libc::c_void, frame.len(), 0,
                         &sa as *const _ as *const libc::sockaddr,
                         mem::size_of::<SockaddrLl>() as u32);
        }
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

// ---------------------------------------------------------------- checksums

fn fold(sum: u32) -> u16 {
    let mut s = sum;
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

fn csum(b: &[u8], start: u32) -> u32 {
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

// ---------------------------------------------------------------- frames

struct Conn<'a> {
    sp: &'a Spoof,
    dst_ip: [u8; 4],
    sport: u16,
    dport: u16,
}

impl Conn<'_> {
    fn arp(&self, target_mac: [u8; 6], target_ip: [u8; 4], reply: bool) -> Vec<u8> {
        let mut f = Vec::with_capacity(42);
        f.extend_from_slice(&target_mac);
        f.extend_from_slice(&self.sp.src_mac);
        f.extend_from_slice(&ETH_P_ARP.to_be_bytes());
        f.extend_from_slice(&[0, 1, 8, 0, 6, 4]);
        f.extend_from_slice(&(if reply { 2u16 } else { 1u16 }).to_be_bytes());
        f.extend_from_slice(&self.sp.src_mac);
        f.extend_from_slice(&self.sp.src_ip);
        f.extend_from_slice(&target_mac);
        f.extend_from_slice(&target_ip);
        f
    }

    fn tcp(&self, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut t = Vec::with_capacity(20 + payload.len());
        t.extend_from_slice(&self.sport.to_be_bytes());
        t.extend_from_slice(&self.dport.to_be_bytes());
        t.extend_from_slice(&seq.to_be_bytes());
        t.extend_from_slice(&ack.to_be_bytes());
        t.push(5 << 4);
        t.push(flags);
        t.extend_from_slice(&0xfaf0u16.to_be_bytes());
        t.extend_from_slice(&[0, 0, 0, 0]); // checksum + urgent
        t.extend_from_slice(payload);
        let mut s = csum(&self.sp.src_ip, 0);
        s = csum(&self.dst_ip, s);
        s += 6 + t.len() as u32;
        let ck = fold(csum(&t, s)).to_be_bytes();
        t[16] = ck[0];
        t[17] = ck[1];

        let mut ip = Vec::with_capacity(20);
        ip.push(0x45);
        ip.push(0);
        ip.extend_from_slice(&((20 + t.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&0x1234u16.to_be_bytes());
        ip.extend_from_slice(&0x4000u16.to_be_bytes());
        ip.push(64);
        ip.push(6);
        ip.extend_from_slice(&[0, 0]);
        ip.extend_from_slice(&self.sp.src_ip);
        ip.extend_from_slice(&self.dst_ip);
        let ck = fold(csum(&ip, 0)).to_be_bytes();
        ip[10] = ck[0];
        ip[11] = ck[1];

        let mut f = Vec::with_capacity(14 + 20 + t.len());
        f.extend_from_slice(&self.sp.dst_mac);
        f.extend_from_slice(&self.sp.src_mac);
        f.extend_from_slice(&ETH_P_IP.to_be_bytes());
        f.extend_from_slice(&ip);
        f.extend_from_slice(&t);
        while f.len() < 60 {
            f.push(0);
        }
        f
    }

    /// (seq, flags, payload) of a segment that belongs to this connection.
    fn parse(&self, f: &[u8]) -> Option<(u32, u8, Vec<u8>)> {
        if f.len() < 34 || u16::from_be_bytes([f[12], f[13]]) != ETH_P_IP {
            return None;
        }
        let ip = &f[14..];
        if ip[0] >> 4 != 4 || ip[9] != 6 {
            return None;
        }
        if ip[12..16] != self.dst_ip || ip[16..20] != self.sp.src_ip {
            return None;
        }
        let ihl = ((ip[0] & 0xf) as usize) * 4;
        let tot = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        if ip.len() < ihl + 20 || tot < ihl + 20 {
            return None;
        }
        let t = &ip[ihl..tot.min(ip.len())];
        if u16::from_be_bytes([t[0], t[1]]) != self.dport
            || u16::from_be_bytes([t[2], t[3]]) != self.sport
        {
            return None;
        }
        let doff = ((t[12] >> 4) as usize) * 4;
        Some((
            u32::from_be_bytes([t[4], t[5], t[6], t[7]]),
            t[13],
            t.get(doff..).unwrap_or(&[]).to_vec(),
        ))
    }

    fn answer_arp(&self, raw: &Raw, f: &[u8]) {
        if f.len() < 42 || u16::from_be_bytes([f[12], f[13]]) != ETH_P_ARP {
            return;
        }
        let a = &f[14..];
        if u16::from_be_bytes([a[6], a[7]]) != 1 || a[24..28] != self.sp.src_ip {
            return;
        }
        let mut m = [0u8; 6];
        m.copy_from_slice(&a[8..14]);
        let mut i = [0u8; 4];
        i.copy_from_slice(&a[14..18]);
        raw.send(&self.arp(m, i, true));
    }
}

/// Resolve the peer's MAC ourselves, from the spoofed identity, instead of
/// leaning on the kernel's neighbour table. That table is only populated if
/// something already talked to the TV (a ping), and it holds
/// 00:00:00:00:00:00 while the entry is incomplete - i.e. exactly when the TV
/// was asleep. Asking directly also means the TV learns our fake address in the
/// same breath.
pub fn resolve(iface: &str, src_mac: [u8; 6], src_ip: [u8; 4], dst_ip: [u8; 4])
    -> io::Result<[u8; 6]>
{
    let raw = Raw::open(iface)?;
    let bcast = [0xffu8; 6];
    let c = Conn { sp: &Spoof { iface: iface.into(), src_mac, src_ip, dst_mac: bcast },
                   dst_ip, sport: 0, dport: 0 };
    let mut buf = vec![0u8; 2048];
    for _ in 0..8 {
        raw.send(&c.arp(bcast, dst_ip, false));      // who has dst_ip?
        let t = Instant::now();
        while t.elapsed() < Duration::from_millis(600) {
            let Some(n) = raw.recv(&mut buf) else { continue };
            let f = &buf[..n];
            if f.len() < 42 || u16::from_be_bytes([f[12], f[13]]) != ETH_P_ARP {
                continue;
            }
            let a = &f[14..];
            if u16::from_be_bytes([a[6], a[7]]) != 2 {
                continue;                             // want a reply
            }
            if a[14..18] != dst_ip {
                continue;                             // from the address we asked about
            }
            let mut m = [0u8; 6];
            m.copy_from_slice(&a[8..14]);
            return Ok(m);
        }
    }
    Err(io::Error::new(io::ErrorKind::TimedOut,
                       "no ARP reply - is the TV powered on?"))
}

/// Keep the spoofed identity resolvable for the whole run, on its own socket.
/// `resolve` only warms the TV's cache once, at startup; the entry ages out
/// (Linux neigh gc is ~30-60 s) during the long `--nopoll` watch windows, and
/// then the next control call's SYN/ACK has nowhere to go -> "no SYN/ACK". This
/// thread answers every `who-has <src_ip>` on demand and re-announces
/// periodically, so the TV can always reach us no matter when it asks.
pub fn spawn_arp_responder(sp: &Spoof) {
    let sp = sp.clone();
    std::thread::Builder::new()
        .name("arp".into())
        .stack_size(64 * 1024)
        .spawn(move || {
            let Ok(raw) = Raw::open(&sp.iface) else { return };
            let c = Conn { sp: &sp, dst_ip: [0; 4], sport: 0, dport: 0 };
            let mut buf = vec![0u8; 2048];
            // initial burst so the cache is warm before the first SYN
            for _ in 0..3 {
                raw.send(&c.arp([0xff; 6], sp.src_ip, true));
            }
            let mut last = Instant::now();
            loop {
                if let Some(n) = raw.recv(&mut buf) {
                    c.answer_arp(&raw, &buf[..n]);
                }
                if last.elapsed() >= Duration::from_secs(3) {
                    raw.send(&c.arp([0xff; 6], sp.src_ip, true));
                    last = Instant::now();
                }
            }
        })
        .ok();
}

// ---------------------------------------------------------------- public API

/// One HTTP request/response from the spoofed identity. Same shape as the
/// ordinary client so the caller can swap between them.
pub fn http_post(
    sp: &Spoof,
    dst_ip: &str,
    port: u16,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> io::Result<(u16, String)> {
    let raw = Raw::open(&sp.iface)?;
    // A fresh 4-tuple *and* ISN per call: the port is a pid-seeded base plus a
    // process-wide counter, the sequence number is stepped by the same counter.
    // Two calls in one run can no longer look like a retransmit of each other.
    let seqn = PORT_SEQ.fetch_add(1, Ordering::Relaxed);
    let base = (std::process::id().wrapping_mul(2654435761) >> 16) as u16;
    let c = Conn {
        sp,
        dst_ip: parse_ip(dst_ip),
        sport: 20000 + base.wrapping_add(seqn as u16) % 40000,
        dport: port,
    };
    let mut seq: u32 = 0x1000_0000u32.wrapping_add(seqn.wrapping_mul(0x0001_0000));
    let mut ack: u32 = 0;

    // Warm the TV's neighbour cache before it has to answer the SYN: a broadcast
    // gratuitous ARP (here is my identity) plus a unicast who-has to the TV. The
    // standing responder thread keeps answering later who-has, but the first
    // frame of a cold call still needs this.
    raw.send(&c.arp([0xff; 6], sp.src_ip, true));
    raw.send(&c.arp(sp.dst_mac, c.dst_ip, false));

    let mut buf = vec![0u8; 4096];
    let mut up = false;
    // Retransmit the SYN. An embedded peer with no neighbour entry drops the
    // first SYN while it ARPs for us and never emits a SYN/ACK on its own, so a
    // single wait times out with "no SYN/ACK". Resend a few times, answering any
    // who-has in between, until the cache is warm and the SYN/ACK comes back.
    'hs: for _ in 0..4 {
        raw.send(&c.tcp(seq, 0, SYN, &[]));
        let t = Instant::now();
        while t.elapsed() < Duration::from_millis(750) {
            let Some(n) = raw.recv(&mut buf) else { continue };
            c.answer_arp(&raw, &buf[..n]);
            if let Some((s, fl, _)) = c.parse(&buf[..n]) {
                if fl & RST != 0 {
                    return Err(io::Error::new(io::ErrorKind::ConnectionRefused,
                                              "RST during handshake"));
                }
                if fl & SYN != 0 && fl & ACK != 0 {
                    seq = seq.wrapping_add(1);
                    ack = s.wrapping_add(1);
                    raw.send(&c.tcp(seq, ack, ACK, &[]));
                    up = true;
                    break 'hs;
                }
            }
        }
        // re-announce before the next SYN in case the drop was ARP-driven
        raw.send(&c.arp([0xff; 6], sp.src_ip, true));
    }
    if !up {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "no SYN/ACK"));
    }

    let mut req = format!("POST {path} HTTP/1.1\r\nHost: {dst_ip}:{port}\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()));
    let mut pkt = req.into_bytes();
    pkt.extend_from_slice(body);
    // Segment the request: SetAVTransportURI carries a big DIDL blob (>2 KB), and
    // one frame cannot exceed the ~1460-byte TCP MSS. Sending it whole made the
    // frame oversized and it was dropped -> HTTP 0. Split into MSS-sized segments;
    // the window (64240) is large enough to send them back-to-back, only the last
    // one PSH. GetTransportInfo etc. are one segment, so this is a no-op for them.
    const MSS: usize = 1460;
    let mut off = 0;
    while off < pkt.len() {
        let end = (off + MSS).min(pkt.len());
        let flags = if end == pkt.len() { PSH | ACK } else { ACK };
        raw.send(&c.tcp(seq, ack, flags, &pkt[off..end]));
        seq = seq.wrapping_add((end - off) as u32);
        off = end;
    }

    let mut resp = Vec::new();
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(10) {
        let Some(n) = raw.recv(&mut buf) else { continue };
        c.answer_arp(&raw, &buf[..n]);
        let Some((s, fl, pl)) = c.parse(&buf[..n]) else { continue };
        if fl & RST != 0 {
            break;
        }
        if !pl.is_empty() {
            if s == ack {
                resp.extend_from_slice(&pl);
                ack = ack.wrapping_add(pl.len() as u32);
            }
            raw.send(&c.tcp(seq, ack, ACK, &[]));
        }
        if fl & FIN != 0 {
            ack = ack.wrapping_add(1);
            raw.send(&c.tcp(seq, ack, ACK, &[]));
            break;
        }
    }
    raw.send(&c.tcp(seq, ack, RST, &[]));

    let text = String::from_utf8_lossy(&resp).into_owned();
    let status = text.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let body = match text.find("\r\n\r\n") {
        Some(i) => text[i + 4..].to_string(),
        None => String::new(),
    };
    Ok((status, body))
}
