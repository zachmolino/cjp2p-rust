//! All rendering. Pure functions of `&App` -> frame; no I/O.

use super::{App, Focus};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Table};
use ratatui::Frame;

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(5),
            Constraint::Length(if app.input_mode {
                3
            } else if app.show_activity {
                8
            } else {
                1
            }),
        ])
        .split(area);

    draw_header(f, app, rows[0]);

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(rows[1]);
    draw_peers(f, app, mid[0]);
    draw_content(f, app, mid[1]);

    draw_footer(f, app, rows[2]);
}

fn block(title: &'static str, focused: bool) -> Block<'static> {
    let border = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    Block::default().borders(Borders::ALL).title(title).border_style(border)
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let text = match &app.status {
        Some(s) => vec![
            Line::from(vec![
                Span::styled(
                    "cjp2p",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("  {}", s.version)),
            ]),
            Line::from(format!("id {}", s.public_key)),
            Line::from(format!(
                "peers {} active / {} total \u{b7} {} fast \u{b7} disk {}",
                s.active_peer_count,
                s.total_peers,
                s.fast_peer_count,
                human_bytes(s.free_disk_bytes)
            )),
        ],
        None => vec![Line::from("connecting to node\u{2026}")],
    };
    f.render_widget(Paragraph::new(text).block(block("node", false)), area);
}

fn draw_peers(f: &mut Frame, app: &App, area: Rect) {
    let focused = app.focus == Focus::Peers;
    let peers = app.status.as_ref().map(|s| s.active_peers.clone()).unwrap_or_default();
    let rows: Vec<Row> = peers
        .iter()
        .map(|p| {
            Row::new(vec![
                Cell::from(p.addr.clone()),
                Cell::from(format!("{}ms", p.delay_ms)),
                Cell::from(short(&p.pubkey)),
            ])
        })
        .collect();
    let table =
        Table::new(rows, [Constraint::Length(22), Constraint::Length(8), Constraint::Min(12)])
            .header(
                Row::new(vec!["addr", "delay", "pub"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .block(block("peers", focused));
    f.render_widget(table, area);
}

fn draw_content(f: &mut Frame, app: &App, area: Rect) {
    let focused = app.focus == Focus::Content;
    let mut items: Vec<ListItem> = Vec::new();
    if let Some(c) = &app.content {
        for o in &c.origin {
            items.push(ListItem::new(format!(
                "origin  {:<22} {:>9}",
                truncate(&o.name, 22),
                human_bytes(o.size)
            )));
        }
        for d in &c.directories {
            items.push(ListItem::new(format!("dir     {}", truncate(&d.name, 30))));
        }
        for p in &c.public {
            let h = p.sha256.clone().or_else(|| p.blake3.clone()).unwrap_or_default();
            let tree = if p.tree {
                "*"
            } else {
                " "
            };
            items.push(ListItem::new(format!(
                "public{} {:>9}  {}",
                tree,
                human_bytes(p.size),
                short(&h)
            )));
        }
    }
    if items.is_empty() {
        items.push(ListItem::new("(no content yet)"));
    }

    let len = items.len();
    let mut state = ListState::default();
    if focused {
        state.select(Some(app.selected.min(len.saturating_sub(1))));
    }
    let list = List::new(items)
        .block(block("content (origin + public)", focused))
        .highlight_symbol("\u{25b8} ")
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    if app.input_mode {
        let line = format!("> {}\u{2588}", app.compose);
        f.render_widget(
            Paragraph::new(line).block(block("message (enter send \u{b7} esc cancel)", true)),
            area,
        );
        return;
    }
    if app.show_activity {
        let cap = area.height.saturating_sub(2) as usize;
        let items: Vec<ListItem> =
            app.activity.iter().take(cap).map(|l| ListItem::new(l.clone())).collect();
        f.render_widget(List::new(items).block(block("activity (w to hide)", false)), area);
    } else {
        let help = app.last_error.clone().map(|e| format!("\u{26a0} {e}")).unwrap_or_else(|| {
            "i compose  \u{b7}  q quit  \u{b7}  tab switch pane  \u{b7}  \u{2191}/\u{2193} move  \u{b7}  w activity"
                .to_string()
        });
        f.render_widget(Paragraph::new(help).style(Style::default().fg(Color::DarkGray)), area);
    }
}

fn short(s: &str) -> String {
    if s.len() > 12 {
        format!("{}\u{2026}", &s[..12])
    } else {
        s.to_string()
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        format!("{}\u{2026}", s.chars().take(n.saturating_sub(1)).collect::<String>())
    } else {
        s.to_string()
    }
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut f = n as f64;
    let mut i = 0;
    while f >= 1024.0 && i < UNITS.len() - 1 {
        f /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{f:.1} {}", UNITS[i])
    }
}
