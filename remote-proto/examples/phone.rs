//! Консольный «телефон» для проверки Basehub Remote без Android:
//!
//!   cargo run --example phone --features client -- pair <ws-адрес> <код или QR-ссылка> [файл-ключей]
//!   cargo run --example phone --features client -- bases <ws-адрес> <id ПК> <ключ ПК> [файл-ключей] [база] [код]
//!
//! Ключи телефона хранятся в файле (по умолчанию phone.key), чтобы после сопряжения проверить KK.

use std::time::Duration;

use remote_proto::app::App;
use remote_proto::client::{connect, RelayReceiver, RelaySender};
use remote_proto::pair::{self, Invite};
use remote_proto::relay::{decode_data, Relay, Role};
use remote_proto::{identity, Channel, Identity, Out};

fn load(path: &str) -> Identity {
    match std::fs::read_to_string(path).ok().and_then(|s| Identity::from_secret(&s).ok()) {
        Some(i) => i,
        None => {
            let i = Identity::generate();
            std::fs::write(path, i.to_secret()).unwrap();
            i
        }
    }
}

async fn next(rx: &mut RelayReceiver, secs: u64) -> Relay {
    tokio::time::timeout(Duration::from_secs(secs), rx.recv()).await.expect("таймаут").expect("соединение закрыто")
}

/// Крутить канал до прикладного сообщения или окончания рукопожатия.
async fn pump(ch: &mut Channel, tx: &RelaySender, rx: &mut RelayReceiver, pc: &str, secs: u64) -> Option<App> {
    loop {
        match next(rx, secs).await {
            Relay::Recv { from, data } if from == pc => {
                for o in ch.handle(&decode_data(&data).unwrap()).expect("канал") {
                    match o {
                        Out::Frame(f) => tx.send(Relay::send(pc, &f)).unwrap(),
                        Out::Established(k) => {
                            println!("рукопожатие: ключ ПК {}", identity::encode_key(&k));
                            if ch.is_established() {
                                return None;
                            }
                        }
                        Out::Message(m) => return Some(App::from_bytes(&m).unwrap()),
                    }
                }
            }
            Relay::Offline { id } => panic!("{id} не в сети"),
            other => println!("ретранслятор: {other:?}"),
        }
    }
}

fn send(ch: &mut Channel, tx: &RelaySender, pc: &str, m: &App) {
    for f in ch.seal(&m.to_bytes()).unwrap() {
        tx.send(Relay::send(pc, &f)).unwrap();
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let cmd = a.get(1).map(String::as_str).unwrap_or("");
    let url = a.get(2).cloned().unwrap_or_default();
    match cmd {
        "pair" => {
            let me = load(a.get(4).map(String::as_str).unwrap_or("phone.key"));
            let (tx, mut rx) = connect(&url, &me, Role::Client).await.unwrap();
            let input = &a[3];
            let (inv, code) = if input.starts_with("basehub://") {
                Invite::from_uri(input).unwrap()
            } else {
                let code = pair::normalize_code(input).expect("код");
                tx.send(Relay::InviteGet { key: pair::invite_key(&code).into() }).unwrap();
                match next(&mut rx, 10).await {
                    Relay::Invite { invite, .. } => (invite, code),
                    other => panic!("{other:?}"),
                }
            };
            println!("ПК «{}» {}", inv.name, inv.agent);
            let (mut ch, first) = Channel::pair_initiator(&me, &code).unwrap();
            tx.send(Relay::send(&inv.agent, &first)).unwrap();
            pump(&mut ch, &tx, &mut rx, &inv.agent, 15).await;
            assert_eq!(ch.remote_key().map(|k| identity::encode_key(&k)), Some(inv.key.clone()), "ключ ПК не совпал с приглашением");
            send(&mut ch, &tx, &inv.agent, &App::Hello { name: "phone-sim".into(), app: "sim".into(), version: "0".into() });
            println!("ждём подтверждения на ПК…");
            println!("ответ: {:?}", pump(&mut ch, &tx, &mut rx, &inv.agent, 120).await);
            println!("для bases: {} {}", inv.agent, inv.key);
        }
        "bases" => {
            let me = load(a.get(5).map(String::as_str).unwrap_or("phone.key"));
            let (pc, key) = (a[3].clone(), identity::decode_key(&a[4]).unwrap());
            let (tx, mut rx) = connect(&url, &me, Role::Client).await.unwrap();
            let (mut ch, first) = Channel::kk_initiator(&me, &key).unwrap();
            tx.send(Relay::send(&pc, &first)).unwrap();
            pump(&mut ch, &tx, &mut rx, &pc, 15).await;
            send(&mut ch, &tx, &pc, &App::Hello { name: String::new(), app: "sim".into(), version: "0".into() });
            println!("{:?}", pump(&mut ch, &tx, &mut rx, &pc, 15).await);
            send(&mut ch, &tx, &pc, &App::ListBases { req: 1 });
            println!("{:?}", pump(&mut ch, &tx, &mut rx, &pc, 15).await);
            // code: шестой аргумент — база, седьмой — код
            if let (Some(base), Some(code)) = (a.get(6), a.get(7)) {
                // текст с ВЫБРАТЬ — консоль запросов, иначе консоль кода
                let m = if code.trim_start().to_uppercase().starts_with("ВЫБРАТЬ") {
                    App::RunQuery { req: 2, base: base.clone(), text: code.clone(), params: "{}".into(), limit: 50 }
                } else {
                    App::RunCode { req: 2, base: base.clone(), code: code.clone() }
                };
                send(&mut ch, &tx, &pc, &m);
                println!("{:?}", pump(&mut ch, &tx, &mut rx, &pc, 600).await);
            }
        }
        _ => eprintln!("pair <url> <код|QR> | bases <url> <id ПК> <ключ ПК>"),
    }
}
