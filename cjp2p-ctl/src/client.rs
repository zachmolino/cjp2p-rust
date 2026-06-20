//! Loopback HTTP client for the node.
//!
//! Hand-rolled over `TcpStream` rather than a crate because the node speaks
//! HTTP/1.0 and frames request bodies by `Content-Length` only (no chunked
//! decode — see handle_upload/handle_publish_origin in the node). A generic
//! client that emits `Transfer-Encoding: chunked` would corrupt uploads, so we
//! control the framing exactly. This also gives us per-read timeouts (needed:
//! a cold cross-node `/latest` fetch parks the socket with no node-side timeout)
//! and lets us NOT follow the `/?get=` 301 (which points at the homepage).

use crate::types::{is_safe_relative_path, ContentJson, Status};
use anyhow::{anyhow, bail, Context, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

pub struct NodeClient {
    addr: String, // host:port for TcpStream::connect
}

#[derive(Debug, Clone)]
pub struct UploadResult {
    pub sha256: String,
    pub blake3: String,
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl NodeClient {
    /// `--node` flag > `$CJP2P_NODE` > `127.0.0.1:24255` (the node default port).
    pub fn resolve(flag: Option<&str>) -> NodeClient {
        let raw = flag
            .map(str::to_string)
            .or_else(|| std::env::var("CJP2P_NODE").ok())
            .unwrap_or_else(|| "127.0.0.1:24255".to_string());
        let addr = raw
            .trim()
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .to_string();
        NodeClient {
            addr,
        }
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn ws_url(&self) -> String {
        format!("ws://{}/wt", self.addr)
    }

    fn connect(&self, read_timeout: Option<Duration>) -> Result<TcpStream> {
        let stream = TcpStream::connect(&self.addr)
            .with_context(|| format!("connecting to node at {} (is it running?)", self.addr))?;
        stream.set_read_timeout(read_timeout).context("setting read timeout on node socket")?;
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .context("setting write timeout on node socket")?;
        Ok(stream)
    }

    fn get(&self, path: &str, read_timeout: Option<Duration>) -> Result<HttpResponse> {
        let mut stream = self.connect(read_timeout)?;
        let head =
            format!("GET {path} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n", self.addr);
        stream.write_all(head.as_bytes())?;
        stream.flush().ok();
        read_response(stream)
    }

    fn post_stream(
        &self,
        path: &str,
        extra: &[(&str, String)],
        mut body: impl Read,
        len: u64,
        read_timeout: Option<Duration>,
    ) -> Result<HttpResponse> {
        let mut stream = self.connect(read_timeout)?;
        let mut head =
            format!("POST {path} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n", self.addr);
        for (k, v) in extra {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str(&format!("Content-Length: {len}\r\n\r\n"));
        stream.write_all(head.as_bytes())?;
        std::io::copy(&mut body, &mut stream).context("streaming request body")?;
        stream.flush().ok();
        read_response(stream)
    }

    pub fn status(&self) -> Result<Status> {
        let r = self.get("/status.json", Some(Duration::from_secs(10)))?;
        if r.status != 200 {
            bail!("/status.json returned HTTP {}", r.status);
        }
        serde_json::from_slice(&r.body).context("parsing /status.json")
    }

    pub fn content(&self) -> Result<ContentJson> {
        let r = self.get("/content.json", Some(Duration::from_secs(10)))?;
        match r.status {
            200 => serde_json::from_slice(&r.body).context("parsing /content.json"),
            404 => bail!("/content.json not found — the node needs the updated build with the content endpoint"),
            403 => bail!("/content.json is loopback-only (HTTP 403) — run on the node host or tunnel 127.0.0.1:24255"),
            s => bail!("/content.json returned HTTP {s}"),
        }
    }

    pub fn upload(&self, path: &Path) -> Result<UploadResult> {
        let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let len = file.metadata()?.len();
        let r = self.post_stream("/upload", &[], file, len, Some(Duration::from_secs(300)))?;
        if r.status != 200 {
            bail!("/upload returned HTTP {}: {}", r.status, String::from_utf8_lossy(&r.body));
        }
        let v: serde_json::Value =
            serde_json::from_slice(&r.body).context("parsing /upload response")?;
        Ok(UploadResult {
            sha256: v["sha256"]
                .as_str()
                .ok_or_else(|| anyhow!("/upload response missing sha256"))?
                .to_string(),
            blake3: v["blake3"]
                .as_str()
                .ok_or_else(|| anyhow!("/upload response missing blake3"))?
                .to_string(),
        })
    }

    pub fn publish(&self, name: &str, path: &Path) -> Result<String> {
        if !is_safe_relative_path(name) {
            bail!("unsafe publish name {name:?}: no leading dot/slash, trailing slash, '/.' or backslash");
        }
        let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let len = file.metadata()?.len();
        let enc = urlencoding::encode(name).to_string();
        let r = self.post_stream(
            "/publish_origin",
            &[("X-Filename", enc)],
            file,
            len,
            Some(Duration::from_secs(300)),
        )?;
        if r.status != 200 {
            bail!(
                "/publish_origin returned HTTP {}: {}",
                r.status,
                String::from_utf8_lossy(&r.body)
            );
        }
        let v: serde_json::Value =
            serde_json::from_slice(&r.body).context("parsing /publish_origin response")?;
        Ok(v["filename"].as_str().unwrap_or(name).to_string())
    }

    /// Kick a network fetch by sha256. The node 301s to `/`; we do not follow.
    pub fn start_get_sha256(&self, hash: &str) -> Result<()> {
        self.get(&format!("/?get={hash}"), Some(Duration::from_secs(10)))?;
        Ok(())
    }

    /// Kick a network fetch by blake3. The node 301s to `/blake3/<h>`.
    pub fn start_get_blake3(&self, hash: &str) -> Result<()> {
        self.get(&format!("/?getb3={hash}"), Some(Duration::from_secs(10)))?;
        Ok(())
    }

    /// Fetch bytes for a content path (`/<sha256>`, `/blake3/<h>`, `/latest/...`).
    /// A timeout means "not available yet / publisher unreachable", never a hang.
    pub fn fetch_bytes(&self, path: &str, read_timeout: Duration) -> Result<Vec<u8>> {
        let r = self.get(path, Some(read_timeout))?;
        if r.status != 200 {
            bail!(
                "fetch {path} returned HTTP {} (content not available yet / publisher unreachable)",
                r.status
            );
        }
        Ok(r.body)
    }
}

fn read_response(mut stream: TcpStream) -> Result<HttpResponse> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];

    // 1. Read until the full response header block (`...\r\n\r\n`) is buffered.
    let header_end = loop {
        if let Some(end) = find_header_end(&raw) {
            break end;
        }
        match stream.read(&mut chunk) {
            Ok(0) => {
                // Socket closed before the headers were complete.
                return Err(if raw.is_empty() {
                    anyhow!("node closed connection with no response")
                } else {
                    anyhow!("malformed HTTP response (no header terminator)")
                });
            }
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e) if is_timeout(&e) => {
                return Err(if raw.is_empty() {
                    anyhow!("timed out waiting for node response")
                } else {
                    anyhow!("timed out before a full HTTP response header arrived")
                });
            }
            Err(e) => return Err(anyhow!("reading response: {e}")),
        }
    };

    // 2. Frame the body. The module header says the node speaks HTTP/1.0 +
    //    `Connection: close` (EOF-delimited), but in practice it replies
    //    `Connection: keep-alive` + `Content-Length` and holds the socket open.
    //    Honor `Content-Length` so we don't block on a FIN that never arrives —
    //    otherwise every fetch stalls until the read timeout fires (120s for
    //    clone/pull). The read timeout stays as a genuine-stall backstop.
    if let Some(len) = content_length(&raw[..header_end]) {
        let want = header_end
            .checked_add(len)
            .ok_or_else(|| anyhow!("absurd Content-Length {len} in node response"))?;
        while raw.len() < want {
            match stream.read(&mut chunk) {
                Ok(0) => break, // EOF before the full body — parse what we have
                Ok(n) => raw.extend_from_slice(&chunk[..n]),
                Err(e) if is_timeout(&e) => break, // genuine-stall backstop
                Err(e) => return Err(anyhow!("reading response body: {e}")),
            }
        }
        // Never expose bytes past the advertised length (defensive vs. over-read).
        raw.truncate(want);
        return parse_response(&raw);
    }

    // 3. No `Content-Length`: fall back to EOF-delimited read (`Connection: close`).
    match stream.read_to_end(&mut raw) {
        Ok(_) => {}
        Err(e) if is_timeout(&e) => {
            // Partial data before the stall — parse what we have.
        }
        Err(e) => return Err(anyhow!("reading response: {e}")),
    }
    parse_response(&raw)
}

/// Index of the first byte after the `\r\n\r\n` header terminator (where the body
/// begins), if that terminator is present in `buf`.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Parse the `Content-Length` header value (case-insensitive name, whitespace-
/// padded value) from a response header block. `None` if absent or unparseable.
fn content_length(header: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(header);
    for line in text.split("\r\n") {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                if let Ok(n) = value.trim().parse::<usize>() {
                    return Some(n);
                }
            }
        }
    }
    None
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
}

fn parse_response(raw: &[u8]) -> Result<HttpResponse> {
    let body_start = find_header_end(raw)
        .ok_or_else(|| anyhow!("malformed HTTP response (no header terminator)"))?;
    let line_end = raw.iter().position(|&b| b == b'\r' || b == b'\n').unwrap_or(raw.len());
    let line = String::from_utf8_lossy(&raw[..line_end]);
    let status: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("bad status line: {line}"))?;
    Ok(HttpResponse {
        status,
        body: raw[body_start..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn content_length_present_case_insensitive_and_absent() {
        // present
        assert_eq!(content_length(b"HTTP/1.0 200 OK\r\nContent-Length: 42\r\n\r\n"), Some(42));
        // case-insensitive name + whitespace-padded value
        assert_eq!(
            content_length(
                b"HTTP/1.0 200 OK\r\ncontent-length:   7  \r\nConnection: keep-alive\r\n\r\n"
            ),
            Some(7)
        );
        // mixed-case header name, zero-length body
        assert_eq!(content_length(b"HTTP/1.0 200 OK\r\nCoNtEnT-LeNgTh: 0\r\n\r\n"), Some(0));
        // absent
        assert_eq!(content_length(b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n"), None);
    }

    #[test]
    fn find_header_end_locates_body_start() {
        // "A: b\r\n\r\n" is 8 bytes; the body ("BODY") starts at index 8.
        assert_eq!(find_header_end(b"A: b\r\n\r\nBODY"), Some(8));
        assert_eq!(find_header_end(b"partial header, no terminator yet"), None);
    }

    /// Regression: the node replies `Connection: keep-alive` + `Content-Length`
    /// and never closes the socket. `read_response` must honor `Content-Length`
    /// and return as soon as the body is in — NOT wait out the read timeout for an
    /// EOF (a FIN) that never comes. Before the fix this stalled ~timeout-long per
    /// fetch (120s for clone/pull).
    #[test]
    fn read_response_honors_content_length_without_waiting_for_eof() {
        let body: &[u8] = b"keep-alive framed body \x00\x01\x02 binary-safe end";
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");

        // Server: send a keep-alive + Content-Length response, then hold the
        // socket OPEN (block on the release channel) — emulate the node never
        // sending a FIN.
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let header = format!(
                "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            sock.write_all(header.as_bytes()).expect("write header");
            sock.write_all(body).expect("write body");
            sock.flush().ok();
            let _ = release_rx.recv(); // keep the socket open until released
            drop(sock);
        });

        let stream = TcpStream::connect(addr).expect("connect");
        stream.set_read_timeout(Some(Duration::from_secs(3))).expect("set read timeout");

        let start = Instant::now();
        let resp = read_response(stream).expect("read_response");
        let elapsed = start.elapsed();

        let _ = release_tx.send(()); // let the server thread exit promptly
        server.join().ok();

        assert_eq!(resp.status, 200, "status line parsed");
        assert_eq!(resp.body, body.to_vec(), "body matches the Content-Length bytes");
        assert!(
            elapsed < Duration::from_secs(1),
            "read_response returned in {elapsed:?}; it waited out the read timeout for \
             an EOF instead of honoring Content-Length (the keep-alive stall regression)"
        );
    }

    /// A garbage/absurd `Content-Length` must fail cleanly — never panic on a
    /// debug-build overflow of `header_end + len`, never wrap-and-truncate into
    /// the header in release. `usize::MAX` parses as a valid usize, so the
    /// arithmetic must be checked.
    #[test]
    fn read_response_rejects_overflowing_content_length() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            sock.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n")
                .expect("write header");
            sock.flush().ok();
            let _ = release_rx.recv();
            drop(sock);
        });

        let stream = TcpStream::connect(addr).expect("connect");
        stream.set_read_timeout(Some(Duration::from_secs(3))).expect("set read timeout");

        let result = read_response(stream);
        let _ = release_tx.send(());
        server.join().ok();

        assert!(
            result.is_err(),
            "an absurd Content-Length must return an error, not panic or mis-frame"
        );
    }

    /// The body-accumulation loop (the heart of the fix) must reassemble, in
    /// order, a body that spans multiple `read()` calls. The client reads in
    /// 8 KiB chunks, so a >8 KiB body guarantees the `while raw.len() < want`
    /// loop iterates more than once — the real clone/pull case (large bundles
    /// dribbled across many TCP segments). The socket is held open, so this also
    /// proves we return on Content-Length, not on EOF.
    #[test]
    fn read_response_reassembles_body_across_multiple_reads() {
        let body: Vec<u8> = (0..20_000).map(|i| (i % 251) as u8).collect();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let body_for_server = body.clone();
        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let header = format!(
                "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: {}\r\n\r\n",
                body_for_server.len()
            );
            sock.write_all(header.as_bytes()).expect("write header");
            sock.write_all(&body_for_server).expect("write body");
            sock.flush().ok();
            let _ = release_rx.recv(); // hold open: never send a FIN
            drop(sock);
        });

        let stream = TcpStream::connect(addr).expect("connect");
        stream.set_read_timeout(Some(Duration::from_secs(3))).expect("set read timeout");

        let start = Instant::now();
        let resp = read_response(stream).expect("read_response");
        let elapsed = start.elapsed();
        let _ = release_tx.send(());
        server.join().ok();

        assert_eq!(resp.status, 200, "status line parsed");
        assert_eq!(resp.body.len(), body.len(), "full body length reassembled");
        assert_eq!(resp.body, body, "body bytes reassembled in order across reads");
        assert!(
            elapsed < Duration::from_secs(1),
            "returned in {elapsed:?} — must frame on Content-Length, not wait for EOF"
        );
    }

    /// No `Content-Length`: the EOF-delimited fallback (`Connection: close`) must
    /// still deliver the full body once the node closes the socket. This locks in
    /// the path the rewrite preserves for the close-delimited case.
    #[test]
    fn read_response_falls_back_to_eof_when_no_content_length() {
        let body: &[u8] = b"connection-close body, framed by EOF only";
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            sock.write_all(b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n").expect("write header");
            sock.write_all(body).expect("write body");
            sock.flush().ok();
            // Drop the socket -> FIN (EOF), the only frame signal on this path.
        });

        let stream = TcpStream::connect(addr).expect("connect");
        stream.set_read_timeout(Some(Duration::from_secs(3))).expect("set read timeout");

        let resp = read_response(stream).expect("read_response");
        server.join().ok();

        assert_eq!(resp.status, 200, "status line parsed");
        assert_eq!(resp.body, body.to_vec(), "full body delivered via EOF framing");
    }
}
