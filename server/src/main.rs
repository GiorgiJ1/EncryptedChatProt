use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::{accept_async, tungstenite::Message};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
enum Role {
    A,
    B,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum WireIn {
    Hello { room: String, role: Role, pubkey_b64: String },
    Chat { room: String, payload_b64: String, nonce_b64: String },
    Ping,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum WireOut {
    WaitingForPeer { role: Role },
    PeerOnline { role: Role },
    PeerPubKey { role: Role, pubkey_b64: String },
    Chat { from_role: Role, payload_b64: String, nonce_b64: String },
    History { items: Vec<HistoryItem> },
    PeerCount { a: usize, b: usize },
    Error { msg: String },
    Pong,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct HistoryItem {
    from_role: Role,
    payload_b64: String,
    nonce_b64: String,
}

struct RoomState {
    a_senders: Vec<mpsc::UnboundedSender<Message>>,
    b_senders: Vec<mpsc::UnboundedSender<Message>>,
    a_pubkeys: Vec<String>,
    b_pubkeys: Vec<String>,
    history: Vec<HistoryItem>,
}

impl RoomState {
    fn new() -> Self {
        Self {
            a_senders: vec![],
            b_senders: vec![],
            a_pubkeys: vec![],
            b_pubkeys: vec![],
            history: vec![],
        }
    }

    fn counts(&self) -> (usize, usize) {
        (self.a_senders.len(), self.b_senders.len())
    }
}

type Rooms = DashMap<String, RoomState>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = std::env::var("GHOSTCHAT_ADDR").unwrap_or_else(|_| "127.0.0.1:9001".to_string());
    let listener = TcpListener::bind(&addr).await?;
    println!("ghostchat-server listening on ws://{addr}");

    let rooms: Arc<Rooms> = Arc::new(DashMap::new());

    while let Ok((stream, _)) = listener.accept().await {
        let rooms = rooms.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, rooms).await {
                eprintln!("conn error: {e}");
            }
        });
    }

    Ok(())
}

async fn handle_conn(stream: TcpStream, rooms: Arc<Rooms>) -> anyhow::Result<()> {
    let ws = accept_async(stream).await?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();

    let writer = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if ws_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    let mut my_room: Option<String> = None;
    let mut my_role: Option<Role> = None;

    while let Some(item) = ws_rx.next().await {
        let msg = match item {
            Ok(m) => m,
            Err(_) => break,
        };

        if !msg.is_text() {
            continue;
        }

        let text = msg.into_text().unwrap_or_default();
        let parsed: Result<WireIn, _> = serde_json::from_str(&text);
        let incoming = match parsed {
            Ok(v) => v,
            Err(_) => {
                let _ = out_tx.send(Message::Text(
                    serde_json::to_string(&WireOut::Error {
                        msg: "bad_json".into(),
                    })?,
                ));
                continue;
            }
        };

        match incoming {
            WireIn::Ping => {
                let _ = out_tx.send(Message::Text(serde_json::to_string(&WireOut::Pong)?));
            }
            WireIn::Hello {
                room,
                role,
                pubkey_b64,
            } => {
                my_room = Some(room.clone());
                my_role = Some(role);

                rooms.entry(room.clone()).or_insert_with(RoomState::new);

                {
                    let mut st = rooms.get_mut(&room).unwrap();

                    match role {
                        Role::A => {
                            st.a_senders.push(out_tx.clone());
                            st.a_pubkeys.push(pubkey_b64.clone());
                        }
                        Role::B => {
                            st.b_senders.push(out_tx.clone());
                            st.b_pubkeys.push(pubkey_b64.clone());
                        }
                    }

                    let (a_cnt, b_cnt) = st.counts();

                    let _ = out_tx.send(Message::Text(serde_json::to_string(
                        &WireOut::PeerCount { a: a_cnt, b: b_cnt },
                    )?));

                    let peer_online = (a_cnt > 0) && (b_cnt > 0);
                    if !peer_online {
                        let _ = out_tx.send(Message::Text(serde_json::to_string(
                            &WireOut::WaitingForPeer { role },
                        )?));
                    } else {
                        let _ = out_tx.send(Message::Text(serde_json::to_string(
                            &WireOut::PeerOnline { role },
                        )?));
                    }

                    let _ = out_tx.send(Message::Text(serde_json::to_string(&WireOut::History {
                        items: st.history.clone(),
                    })?));

                    if a_cnt > 0 && b_cnt > 0 {
                        for a_pk in st.a_pubkeys.iter() {
                            for tx in st.b_senders.iter() {
                                let _ = tx.send(Message::Text(serde_json::to_string(
                                    &WireOut::PeerPubKey {
                                        role: Role::A,
                                        pubkey_b64: a_pk.clone(),
                                    },
                                )?));
                            }
                        }
                        for b_pk in st.b_pubkeys.iter() {
                            for tx in st.a_senders.iter() {
                                let _ = tx.send(Message::Text(serde_json::to_string(
                                    &WireOut::PeerPubKey {
                                        role: Role::B,
                                        pubkey_b64: b_pk.clone(),
                                    },
                                )?));
                            }
                        }
                    }
                }

                broadcast_counts(&rooms, &room)?;
            }
            WireIn::Chat {
                room,
                payload_b64,
                nonce_b64,
            } => {
                let role = match my_role {
                    Some(r) => r,
                    None => {
                        let _ = out_tx.send(Message::Text(
                            serde_json::to_string(&WireOut::Error {
                                msg: "send_hello_first".into(),
                            })?,
                        ));
                        continue;
                    }
                };

                {
                    if let Some(mut st) = rooms.get_mut(&room) {
                        st.history.push(HistoryItem {
                            from_role: role,
                            payload_b64: payload_b64.clone(),
                            nonce_b64: nonce_b64.clone(),
                        });

                        let out = WireOut::Chat {
                            from_role: role,
                            payload_b64,
                            nonce_b64,
                        };
                        let encoded = Message::Text(serde_json::to_string(&out)?);

                        match role {
                            Role::A => {
                                for tx in st.b_senders.iter() {
                                    let _ = tx.send(encoded.clone());
                                }
                                for tx in st.a_senders.iter() {
                                    let _ = tx.send(encoded.clone());
                                }
                            }
                            Role::B => {
                                for tx in st.a_senders.iter() {
                                    let _ = tx.send(encoded.clone());
                                }
                                for tx in st.b_senders.iter() {
                                    let _ = tx.send(encoded.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if let (Some(room), Some(role)) = (my_room.clone(), my_role) {
        cleanup(&rooms, &room, role);
        let _ = broadcast_counts(&rooms, &room);
    }

    writer.abort();
    Ok(())
}

fn broadcast_counts(rooms: &Arc<Rooms>, room: &str) -> anyhow::Result<()> {
    if let Some(st) = rooms.get(room) {
        let (a_cnt, b_cnt) = st.counts();
        let msg = Message::Text(serde_json::to_string(&WireOut::PeerCount {
            a: a_cnt,
            b: b_cnt,
        })?);

        for tx in st.a_senders.iter() {
            let _ = tx.send(msg.clone());
        }
        for tx in st.b_senders.iter() {
            let _ = tx.send(msg.clone());
        }
    }
    Ok(())
}

fn cleanup(rooms: &Arc<Rooms>, room: &str, role: Role) {
    if let Some(mut st) = rooms.get_mut(room) {
        match role {
            Role::A => {
                if !st.a_senders.is_empty() {
                    st.a_senders.pop();
                }
                if !st.a_pubkeys.is_empty() {
                    st.a_pubkeys.pop();
                }
            }
            Role::B => {
                if !st.b_senders.is_empty() {
                    st.b_senders.pop();
                }
                if !st.b_pubkeys.is_empty() {
                    st.b_pubkeys.pop();
                }
            }
        }

        let (a_cnt, b_cnt) = st.counts();
        if a_cnt == 0 && b_cnt == 0 {
            drop(st);
            rooms.remove(room);
        }
    }
}