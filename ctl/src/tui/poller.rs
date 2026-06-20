//! Background producer threads for the TUI: keyboard input, periodic node
//! polling, and the WS activity stream. Each sends `AppEvent`s; none touch the
//! terminal.

use super::AppEvent;
use crate::actions;
use crate::client::NodeClient;
use crate::types::{parse_ws_frames, WsFrame};
use crossterm::event;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;
use tungstenite::stream::MaybeTlsStream;

pub fn spawn_input(tx: Sender<AppEvent>) {
    std::thread::spawn(move || loop {
        match event::poll(Duration::from_millis(200)) {
            Ok(true) => {
                if let Ok(event::Event::Key(k)) = event::read() {
                    if tx.send(AppEvent::Key(k)).is_err() {
                        break;
                    }
                }
            }
            Ok(false) => {}
            Err(_) => break,
        }
    });
}

pub fn spawn_poller(client: &NodeClient, tx: Sender<AppEvent>) {
    let c = NodeClient::resolve(Some(client.addr()));
    std::thread::spawn(move || loop {
        match actions::status(&c) {
            Ok(s) => {
                if tx.send(AppEvent::Status(s)).is_err() {
                    break;
                }
            }
            Err(e) => {
                let _ = tx.send(AppEvent::Error(format!("status: {e}")));
            }
        }
        if let Ok(cj) = actions::content(&c) {
            // 404/403 are tolerated silently (older node / remote)
            if tx.send(AppEvent::Content(cj)).is_err() {
                break;
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    });
}

pub fn spawn_ws(client: &NodeClient, tx: Sender<AppEvent>, ws_rx: Receiver<String>) {
    let url = client.ws_url();
    std::thread::spawn(move || {
        // A frame already pulled off `ws_rx` that has not yet been written (or
        // failed mid-write): retained across reconnects so no message is lost.
        let mut pending: Option<String> = None;
        loop {
            // Reconnect across transient node outages; only give up when the UI
            // is gone (an Activity send fails because the receiver was dropped).
            match tungstenite::connect(url.as_str()) {
                Ok((mut ws, _resp)) => {
                    // A short read timeout turns ws.read() into a poll: it
                    // returns a WouldBlock/TimedOut error instead of parking the
                    // thread, so the same loop can also drain and write outgoing
                    // frames. A write timeout keeps a blocked write from freezing
                    // the read loop.
                    if let MaybeTlsStream::Plain(s) = ws.get_mut() {
                        let _ = s.set_read_timeout(Some(Duration::from_millis(250)));
                        let _ = s.set_write_timeout(Some(Duration::from_millis(2000)));
                    }
                    loop {
                        match ws.read() {
                            Ok(tungstenite::Message::Text(t)) => {
                                for fr in parse_ws_frames(t.as_str()) {
                                    let lines = match fr {
                                        WsFrame::Identity {
                                            ed25519,
                                        } => vec![format!("id {}", short(&ed25519))],
                                        WsFrame::Forwarded {
                                            from,
                                            src,
                                            messages,
                                        } => render_forwarded(from.as_deref(), &src, &messages),
                                        WsFrame::Other(t) => vec![format!("\u{b7} {t}")],
                                    };
                                    for line in lines {
                                        if tx.send(AppEvent::Activity(line)).is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                            Ok(tungstenite::Message::Close(_)) => break,
                            Err(tungstenite::Error::Io(e))
                                if matches!(
                                    e.kind(),
                                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                                ) =>
                            {
                                // read timed out: nothing to receive, fall through
                                // to the outgoing drain below.
                            }
                            Err(_) => break,
                            _ => {}
                        }
                        // Drain queued outgoing frames after every read attempt.
                        // A frame left over from a failed write on the previous
                        // connection (`pending`) is written first; if the write or
                        // flush fails we put the in-flight frame back into `pending`
                        // and reconnect, so nothing is dropped.
                        let mut send_failed = false;
                        while let Some(frame) = pending.take().or_else(|| ws_rx.try_recv().ok()) {
                            if ws.write(tungstenite::Message::Text(frame.clone().into())).is_err()
                                || ws.flush().is_err()
                            {
                                pending = Some(frame);
                                send_failed = true;
                                break;
                            }
                        }
                        if send_failed {
                            break;
                        }
                    }
                }
                Err(_) => {
                    if tx
                        .send(AppEvent::Activity(
                            "(activity: ws unavailable, retrying)".to_string(),
                        ))
                        .is_err()
                    {
                        return;
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(3));
        }
    });
}

/// Parse the `messages` JSON payload of a `Forwarded` frame and render any
/// group-chat messages for the "main" group the way the web client does:
/// `<nick or short(pubkey)>: <text>`. Falls back to the old terse
/// "msg from … via …" line if nothing renderable is found.
fn render_forwarded(from: Option<&str>, src: &str, messages: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(serde_json::Value::Array(arr)) = serde_json::from_str::<serde_json::Value>(messages) {
        for item in &arr {
            let Some(gcm) = item.get("GroupChatMessage") else {
                continue;
            };
            // Only the "main" group is shown in the TUI chat pane.
            if gcm.get("group_name").and_then(|v| v.as_str()) != Some("main") {
                continue;
            }
            let Some(text) = gcm.get("text").and_then(|v| v.as_str()) else {
                continue;
            };
            let who = gcm
                .get("nickname")
                .and_then(|v| v.as_str())
                .filter(|n| !n.is_empty())
                .map(|n| n.to_string())
                .unwrap_or_else(|| short(from.unwrap_or_default()));
            out.push(format!("{who}: {text}"));
        }
    }
    if out.is_empty() {
        out.push(format!("msg from {} via {}", short(from.unwrap_or_default()), src));
    }
    out
}

fn short(s: &str) -> String {
    if s.chars().count() > 10 {
        format!("{}\u{2026}", s.chars().take(10).collect::<String>())
    } else {
        s.to_string()
    }
}
