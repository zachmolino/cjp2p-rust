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
    std::thread::spawn(move || loop {
        // Reconnect across transient node outages; only give up when the UI is
        // gone (an Activity send fails because the receiver was dropped).
        match tungstenite::connect(url.as_str()) {
            Ok((mut ws, _resp)) => {
                // A short read timeout turns ws.read() into a poll: it returns
                // a WouldBlock/TimedOut error instead of parking the thread, so
                // the same loop can also drain and write outgoing frames.
                if let MaybeTlsStream::Plain(s) = ws.get_mut() {
                    let _ = s.set_read_timeout(Some(Duration::from_millis(250)));
                }
                loop {
                    match ws.read() {
                        Ok(tungstenite::Message::Text(t)) => {
                            for fr in parse_ws_frames(t.as_str()) {
                                let line = match fr {
                                    WsFrame::Identity {
                                        ed25519,
                                    } => format!("id {}", short(&ed25519)),
                                    WsFrame::Forwarded {
                                        from,
                                        src,
                                        ..
                                    } => {
                                        format!(
                                            "msg from {} via {}",
                                            short(&from.unwrap_or_default()),
                                            src
                                        )
                                    }
                                    WsFrame::Other(t) => format!("\u{b7} {t}"),
                                };
                                if tx.send(AppEvent::Activity(line)).is_err() {
                                    return;
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
                    let mut send_failed = false;
                    while let Ok(frame) = ws_rx.try_recv() {
                        if ws.write(tungstenite::Message::Text(frame.into())).is_err()
                            || ws.flush().is_err()
                        {
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
                    .send(AppEvent::Activity("(activity: ws unavailable, retrying)".to_string()))
                    .is_err()
                {
                    return;
                }
            }
        }
        std::thread::sleep(Duration::from_secs(3));
    });
}

fn short(s: &str) -> String {
    if s.len() > 10 {
        format!("{}\u{2026}", &s[..10])
    } else {
        s.to_string()
    }
}
