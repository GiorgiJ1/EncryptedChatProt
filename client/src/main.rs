use anyhow::Context;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use crossterm::{
    cursor,
    style::{Print, ResetColor, SetAttribute, SetForegroundColor},
    terminal::{self, ClearType},
    ExecutableCommand,
};
use futures_util::{SinkExt, StreamExt};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::io::{stdout, Write};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
enum Role {
    A,
    B,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum WireIn {
    WaitingForPeer { role: Role },
    PeerOnline { role: Role },
    PeerPubKey { role: Role, pubkey_b64: String },
    Chat { from_role: Role, payload_b64: String, nonce_b64: String },
    History { items: Vec<HistoryItem> },
    PeerCount { a: usize, b: usize },
    Error { msg: String },
    Pong,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum WireOut {
    Hello { room: String, role: Role, pubkey_b64: String },
    Chat { room: String, payload_b64: String, nonce_b64: String },
    Ping,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct HistoryItem {
    from_role: Role,
    payload_b64: String,
    nonce_b64: String,
}

struct Crypto {
    role: Role,
    room: String,
    psk: Vec<u8>,
    my_secret: StaticSecret,
    my_pub: PublicKey,
    peer_keys: Vec<[u8; 32]>,
    seen_peers: HashSet<String>,
}

impl Crypto {
    fn new(role: Role, room: String, psk: Vec<u8>) -> Self {
        let my_secret = StaticSecret::random_from_rng(OsRng);
        let my_pub = PublicKey::from(&my_secret);
        Self {
            role,
            room,
            psk,
            my_secret,
            my_pub,
            peer_keys: vec![],
            seen_peers: HashSet::new(),
        }
    }

    fn my_pub_b64(&self) -> String {
        B64.encode(self.my_pub.as_bytes())
    }

    fn add_peer_pub_b64(&mut self, pk_b64: &str) -> anyhow::Result<()> {
        if self.seen_peers.contains(pk_b64) {
            return Ok(());
        }
        let bytes = B64.decode(pk_b64.as_bytes())?;
        if bytes.len() != 32 {
            anyhow::bail!("bad_peer_pubkey_len");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        self.peer_keys.push(arr);
        self.seen_peers.insert(pk_b64.to_string());
        Ok(())
    }

    fn can_chat(&self) -> bool {
        !self.peer_keys.is_empty()
    }

    fn derive_session_key(&self, peer_pub: &[u8; 32]) -> [u8; 32] {
        let peer = PublicKey::from(*peer_pub);
        let shared = self.my_secret.diffie_hellman(&peer);
        let hk = Hkdf::<Sha256>::new(Some(&self.psk), shared.as_bytes());
        let mut out = [0u8; 32];
        hk.expand(b"ghostchat-v1", &mut out).unwrap();
        out
    }

    fn encrypt_to_first_peer(&self, plaintext: &[u8]) -> anyhow::Result<(String, String)> {
        if self.peer_keys.is_empty() {
            anyhow::bail!("no_peer");
        }
        let k = self.derive_session_key(&self.peer_keys[0]);
        let key = Key::from_slice(&k);
        let aead = ChaCha20Poly1305::new(key);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ct = aead
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;

        let payload_b64 = B64.encode(ct);
        let nonce_b64 = B64.encode(nonce_bytes);

        let mut kz = k;
        kz.zeroize();

        Ok((payload_b64, nonce_b64))
    }

    fn try_decrypt_from_any_peer(
        &self,
        payload_b64: &str,
        nonce_b64: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let ct = B64.decode(payload_b64.as_bytes())?;
        let nonce_raw = B64.decode(nonce_b64.as_bytes())?;
        if nonce_raw.len() != 12 {
            anyhow::bail!("bad_nonce_len");
        }
        let mut nb = [0u8; 12];
        nb.copy_from_slice(&nonce_raw);
        let nonce = Nonce::from_slice(&nb);

        for peer in self.peer_keys.iter() {
            let k = self.derive_session_key(peer);
            let key = Key::from_slice(&k);
            let aead = ChaCha20Poly1305::new(key);

            let dec = aead.decrypt(nonce, ct.as_ref());
            let mut kz = k;
            kz.zeroize();

            if let Ok(pt) = dec {
                return Ok(pt);
            }
        }

        anyhow::bail!("decrypt_failed")
    }
}

fn vibe_banner(role: Role, room: &str, server: &str) {
    let mut out = stdout();
    let _ = out.execute(terminal::Clear(ClearType::All));
    let _ = out.execute(cursor::MoveTo(0, 0));
    let _ = out.execute(SetAttribute(crossterm::style::Attribute::Bold));
    let _ = out.execute(SetForegroundColor(crossterm::style::Color::Cyan));
    let _ = out.execute(Print("GHOSTCHAT "));
    let _ = out.execute(SetForegroundColor(crossterm::style::Color::Yellow));
    let _ = out.execute(Print("/// "));
    let _ = out.execute(ResetColor);
    let _ = out.execute(SetAttribute(crossterm::style::Attribute::Reset));
    let _ = out.execute(Print(format!("role={role:?} room={room} server={server}\n")));
    let _ = out.execute(SetForegroundColor(crossterm::style::Color::DarkGrey));
    let _ = out.execute(Print("Type and hit Enter. Ctrl+C to vanish.\n\n"));
    let _ = out.execute(ResetColor);
    let _ = out.flush();
}

fn status_line(s: &str) {
    let mut out = stdout();
    let _ = out.execute(SetForegroundColor(crossterm::style::Color::Magenta));
    let _ = out.execute(Print(format!("{s}\n")));
    let _ = out.execute(ResetColor);
    let _ = out.flush();
}

fn incoming_line(role: Role, s: &str) {
    let mut out = stdout();
    let _ = out.execute(SetForegroundColor(match role {
        Role::A => crossterm::style::Color::Cyan,
        Role::B => crossterm::style::Color::Yellow,
    }));
    let _ = out.execute(Print(format!("{role:?}> ")));
    let _ = out.execute(ResetColor);
    let _ = out.execute(Print(format!("{s}\n")));
    let _ = out.flush();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let server =
        std::env::var("GHOSTCHAT_SERVER").unwrap_or_else(|_| "ws://127.0.0.1:9001".to_string());
    let room = std::env::var("GHOSTCHAT_ROOM").unwrap_or_else(|_| "test-room".to_string());

    let role = match std::env::var("GHOSTCHAT_ROLE")
        .unwrap_or_else(|_| "a".to_string())
        .to_lowercase()
        .as_str()
    {
        "a" => Role::A,
        "b" => Role::B,
        _ => Role::A,
    };

    let psk_str =
        std::env::var("GHOSTCHAT_PSK").unwrap_or_else(|_| "dev-psk-change-me".to_string());
    let psk = psk_str.as_bytes().to_vec();

    let mut crypto = Crypto::new(role, room.clone(), psk);

    vibe_banner(role, &room, &server);

    let (ws, _) = connect_async(&server).await.context("connect_ws_failed")?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    let hello = WireOut::Hello {
        room: room.clone(),
        role,
        pubkey_b64: crypto.my_pub_b64(),
    };
    ws_tx
        .send(Message::Text(serde_json::to_string(&hello)?))
        .await
        .ok();

    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();

    let mut opened = false;

    loop {
        tokio::select! {
            maybe_ws = ws_rx.next() => {
                let Some(res) = maybe_ws else { break; };
                let ws_msg = match res {
                    Ok(m) => m,
                    Err(_) => break,
                };
                if !ws_msg.is_text() { continue; }

                let text = ws_msg.into_text().unwrap_or_default();
                let parsed: Result<WireIn, _> = serde_json::from_str(&text);
                let msg = match parsed {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                match msg {
                    WireIn::WaitingForPeer { .. } => {
                        status_line("waiting for the other side...");
                    }
                    WireIn::PeerOnline { .. } => {
                        status_line("peer online. syncing keys...");
                    }
                    WireIn::PeerCount { a, b } => {
                        status_line(&format!("online: A={a} B={b}"));
                    }
                    WireIn::PeerPubKey { role: peer_role, pubkey_b64 } => {
                        if peer_role != role {
                            let _ = crypto.add_peer_pub_b64(&pubkey_b64);
                            if crypto.can_chat() && !opened {
                                opened = true;
                                status_line("chat unlocked.");
                            }
                        }
                    }
                    WireIn::History { items } => {
                        if !items.is_empty() {
                            status_line("history (encrypted on server, decrypted here):");
                            for it in items {
                                if let Ok(pt) = crypto.try_decrypt_from_any_peer(&it.payload_b64, &it.nonce_b64) {
                                    let s = String::from_utf8_lossy(&pt).to_string();
                                    incoming_line(it.from_role, &s);
                                }
                            }
                            status_line("— end history —");
                        }
                    }
                    WireIn::Chat { from_role, payload_b64, nonce_b64 } => {
                        if let Ok(pt) = crypto.try_decrypt_from_any_peer(&payload_b64, &nonce_b64) {
                            let s = String::from_utf8_lossy(&pt).to_string();
                            incoming_line(from_role, &s);
                        }
                    }
                    WireIn::Error { msg } => {
                        status_line(&format!("server error: {msg}"));
                    }
                    WireIn::Pong => {}
                }
            }

            maybe_line = lines.next_line() => {
                let maybe_line = maybe_line?;
                let Some(line) = maybe_line else { break; };
                if line.trim().is_empty() { continue; }

                if !opened {
                    status_line("still locked. other side not online yet.");
                    continue;
                }

                let (payload_b64, nonce_b64) = crypto.encrypt_to_first_peer(line.as_bytes())?;
                let out = WireOut::Chat { room: room.clone(), payload_b64, nonce_b64 };
                ws_tx.send(Message::Text(serde_json::to_string(&out)?)).await.ok();
            }
        }
    }

    Ok(())
}