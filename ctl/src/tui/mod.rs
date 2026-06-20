//! Terminal dashboard. Owns the UI thread; three producer threads feed one
//! mpsc channel (input, periodic poll of status+content, WS activity stream).
//! The UI loop never blocks on the network. `ratatui::init()` installs a panic
//! hook that restores the terminal, so a crash won't leave the tty wrecked.

mod poller;
mod widgets;

use crate::client::NodeClient;
use crate::types::{ContentJson, Status};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub enum AppEvent {
    Key(KeyEvent),
    Status(Status),
    Content(ContentJson),
    Activity(String),
    Error(String),
}

#[derive(Clone, Copy, PartialEq)]
pub enum Focus {
    Peers,
    Content,
}

pub struct App {
    pub status: Option<Status>,
    pub content: Option<ContentJson>,
    pub activity: VecDeque<String>,
    pub last_error: Option<String>,
    pub focus: Focus,
    pub selected: usize,
    pub show_activity: bool,
    pub should_quit: bool,
    pub input_mode: bool,
    pub compose: String,
    pub ws_tx: Sender<String>,
    pub nickname: Option<String>,
}

impl App {
    fn new(ws_tx: Sender<String>) -> Self {
        App {
            status: None,
            content: None,
            activity: VecDeque::new(),
            last_error: None,
            focus: Focus::Peers,
            selected: 0,
            show_activity: false,
            should_quit: false,
            input_mode: false,
            compose: String::new(),
            ws_tx,
            nickname: std::env::var("CJP2P_NICK").ok().filter(|s| !s.is_empty()),
        }
    }
}

pub fn run(client: &NodeClient) -> Result<()> {
    let (tx, rx) = mpsc::channel::<AppEvent>();
    let (ws_tx, ws_rx) = mpsc::channel::<String>();
    poller::spawn_input(tx.clone());
    poller::spawn_poller(client, tx.clone());
    poller::spawn_ws(client, tx, ws_rx);

    let mut terminal = ratatui::init();
    let mut app = App::new(ws_tx);
    let res = run_loop(&mut terminal, &mut app, &rx);
    ratatui::restore();
    res
}

fn run_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    rx: &mpsc::Receiver<AppEvent>,
) -> Result<()> {
    loop {
        terminal.draw(|f| widgets::draw(f, app))?;
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(ev) => handle(app, ev),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if app.should_quit {
            break;
        }
    }
    Ok(())
}

fn handle(app: &mut App, ev: AppEvent) {
    match ev {
        AppEvent::Key(k) => {
            if k.kind != KeyEventKind::Press {
                return;
            }
            if app.input_mode {
                match k.code {
                    KeyCode::Char(c) => app.compose.push(c),
                    KeyCode::Backspace => {
                        app.compose.pop();
                    }
                    KeyCode::Esc => {
                        app.compose.clear();
                        app.input_mode = false;
                    }
                    KeyCode::Enter => {
                        send_compose(app);
                        app.compose.clear();
                        app.input_mode = false;
                    }
                    _ => {}
                }
                return;
            }
            match k.code {
                KeyCode::Char('q') => app.should_quit = true,
                KeyCode::Char('i') | KeyCode::Enter => app.input_mode = true,
                KeyCode::Char('w') => app.show_activity = !app.show_activity,
                KeyCode::Tab => {
                    app.focus = match app.focus {
                        Focus::Peers => Focus::Content,
                        Focus::Content => Focus::Peers,
                    };
                    app.selected = 0;
                }
                KeyCode::Down | KeyCode::Char('j') => app.selected = app.selected.saturating_add(1),
                KeyCode::Up | KeyCode::Char('k') => app.selected = app.selected.saturating_sub(1),
                _ => {}
            }
        }
        AppEvent::Status(s) => app.status = Some(s),
        AppEvent::Content(c) => app.content = Some(c),
        AppEvent::Activity(line) => {
            app.activity.push_front(line);
            while app.activity.len() > 200 {
                app.activity.pop_back();
            }
        }
        AppEvent::Error(e) => app.last_error = Some(e),
    }
}

/// Fan-out the composed text to the "main" group chat: one `Forward` frame per
/// active peer, matching the wire format of the web client (group_chat.html).
fn send_compose(app: &mut App) {
    let text = app.compose.trim().to_string();
    if text.is_empty() {
        return;
    }
    let timestamp =
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64;

    let peers = app.status.as_ref().map(|s| s.active_peers.clone()).unwrap_or_default();
    for peer in &peers {
        let to = peer.pubkey.trim_start_matches("0x");
        if to.is_empty() {
            continue;
        }
        let mut msg = serde_json::json!({
            "GroupChatMessage": {
                "group_name": "main",
                "text": text,
                "timestamp": timestamp,
            }
        });
        if let Some(nick) = &app.nickname {
            msg["GroupChatMessage"]["nickname"] = serde_json::json!(nick);
        }
        let frame = serde_json::json!([{
            "Forward": {
                "to_ed25519": to,
                "messages": [msg],
            }
        }])
        .to_string();
        let _ = app.ws_tx.send(frame);
    }

    // Local echo so the sender sees their own line immediately.
    app.activity.push_front(format!("you: {text}"));
    while app.activity.len() > 200 {
        app.activity.pop_back();
    }
}
