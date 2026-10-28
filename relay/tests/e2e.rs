//! Сквозная проверка через живой ретранслятор на localhost: приглашение по коду, сопряжение,
//! список баз, повторное подключение по ключам, «не в сети».

use std::time::Duration;

use remote_proto::app::{App, Base};
use remote_proto::client::{connect, RelayReceiver, RelaySender};
use remote_proto::pair::{self, Invite};
use remote_proto::relay::{decode_data, Relay, Role};
use remote_proto::{identity, Channel, Identity, Out};

async fn start() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(basehub_relay::serve(listener, basehub_relay::Config::default(), std::future::pending()));
    format!("ws://{addr}/v1/ws")
}

async fn recv(rx: &mut RelayReceiver) -> Relay {
    tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("таймаут").expect("закрыто")
}

/// Принять кадры канала, пока не придёт прикладное сообщение (ответные кадры — отправить).
async fn read_app(ch: &mut Channel, tx: &RelaySender, rx: &mut RelayReceiver, peer: &str) -> (Option<[u8; 32]>, Option<App>) {
    let mut est = None;
    loop {
        let Relay::Recv { from, data } = recv(rx).await else { continue };
        assert_eq!(from, peer);
        for o in ch.handle(&decode_data(&data).unwrap()).unwrap() {
            match o {
                Out::Frame(f) => tx.send(Relay::send(peer, &f)).unwrap(),
                Out::Established(k) => {
                    est = Some(k);
                    if ch.is_established() {
                        return (est, None);
                    }
                }
                Out::Message(m) => return (est, Some(App::from_bytes(&m).unwrap())),
            }
        }
    }
}

fn send_app(ch: &mut Channel, tx: &RelaySender, peer: &str, m: &App) {
    for f in ch.seal(&m.to_bytes()).unwrap() {
        tx.send(Relay::send(peer, &f)).unwrap();
    }
}

#[tokio::test]
async fn pair_by_code_list_bases_reconnect() {
    let url = start().await;
    let (pc, phone) = (Identity::generate(), Identity::generate());

    // ПК в сети и выложил приглашение
    let (pc_tx, mut pc_rx) = connect(&url, &pc, Role::Agent).await.unwrap();
    let code = pair::new_code();
    let inv = Invite { relay: url.clone(), agent: pc.id(), key: identity::encode_key(&pc.dh_public()), name: "ПК бухгалтерии".into() };
    pc_tx.send(Relay::InvitePut { key: pair::invite_key(&code).into(), invite: inv.clone() }).unwrap();

    // телефон вводит код вручную
    let (ph_tx, mut ph_rx) = connect(&url, &phone, Role::Client).await.unwrap();
    ph_tx.send(Relay::Watch { ids: vec![pc.id()] }).unwrap();
    assert_eq!(recv(&mut ph_rx).await, Relay::Presence { id: pc.id(), online: true });
    let typed = pair::normalize_code(&pair::display_code(&code).to_lowercase()).unwrap();
    ph_tx.send(Relay::InviteGet { key: pair::invite_key(&typed).into() }).unwrap();
    let Relay::Invite { invite, .. } = recv(&mut ph_rx).await else { panic!("нет приглашения") };
    assert_eq!(invite, inv);
    // приглашение одноразовое
    ph_tx.send(Relay::InviteGet { key: pair::invite_key(&typed).into() }).unwrap();
    assert!(matches!(recv(&mut ph_rx).await, Relay::Error { .. }));

    // сопряжение через ретранслятор
    let (mut ph_ch, first) = Channel::pair_initiator(&phone, &typed).unwrap();
    ph_tx.send(Relay::send(&pc.id(), &first)).unwrap();
    let mut pc_ch = Channel::pair_responder(&pc, &code).unwrap();
    let pc_side = async {
        let (k, _) = read_app(&mut pc_ch, &pc_tx, &mut pc_rx, &phone.id()).await;
        assert_eq!(k, Some(phone.dh_public()));
        let (_, hello) = read_app(&mut pc_ch, &pc_tx, &mut pc_rx, &phone.id()).await;
        assert!(matches!(hello, Some(App::Hello { .. })));
        send_app(&mut pc_ch, &pc_tx, &phone.id(), &App::Paired { name: "ПК бухгалтерии".into() });
        let (_, req) = read_app(&mut pc_ch, &pc_tx, &mut pc_rx, &phone.id()).await;
        assert_eq!(req, Some(App::ListBases { req: 1 }));
        send_app(&mut pc_ch, &pc_tx, &phone.id(), &App::Bases { req: 1, items: vec![Base { name: "Бухгалтерия".into(), folder: "".into(), connect: "File=\"C:\\b\";".into(), code: false, query: false }] });
    };
    let phone_side = async {
        let (k, _) = read_app(&mut ph_ch, &ph_tx, &mut ph_rx, &pc.id()).await;
        // телефон сверяет ключ ПК с QR/приглашением
        assert_eq!(k.map(|k| identity::encode_key(&k)), Some(inv.key.clone()));
        send_app(&mut ph_ch, &ph_tx, &pc.id(), &App::Hello { name: "Pixel".into(), app: "releases1c".into(), version: "1".into() });
        let (_, paired) = read_app(&mut ph_ch, &ph_tx, &mut ph_rx, &pc.id()).await;
        assert!(matches!(paired, Some(App::Paired { .. })));
        send_app(&mut ph_ch, &ph_tx, &pc.id(), &App::ListBases { req: 1 });
        let (_, bases) = read_app(&mut ph_ch, &ph_tx, &mut ph_rx, &pc.id()).await;
        let Some(App::Bases { items, .. }) = bases else { panic!("нет списка баз") };
        assert_eq!(items[0].name, "Бухгалтерия");
    };
    tokio::join!(pc_side, phone_side);

    // повторное подключение телефона по сохранённым ключам (KK)
    drop((ph_tx, ph_rx));
    let (ph_tx, mut ph_rx) = connect(&url, &phone, Role::Client).await.unwrap();
    let (mut ph_ch, first) = Channel::kk_initiator(&phone, &pc.dh_public()).unwrap();
    ph_tx.send(Relay::send(&pc.id(), &first)).unwrap();
    let mut pc_ch = Channel::kk_responder(&pc, &phone.dh_public()).unwrap();
    let pc_side = async {
        read_app(&mut pc_ch, &pc_tx, &mut pc_rx, &phone.id()).await;
        let (_, ping) = read_app(&mut pc_ch, &pc_tx, &mut pc_rx, &phone.id()).await;
        assert_eq!(ping, Some(App::Ping { req: 7 }));
        send_app(&mut pc_ch, &pc_tx, &phone.id(), &App::Pong { req: 7 });
    };
    let phone_side = async {
        read_app(&mut ph_ch, &ph_tx, &mut ph_rx, &pc.id()).await;
        send_app(&mut ph_ch, &ph_tx, &pc.id(), &App::Ping { req: 7 });
        let (_, pong) = read_app(&mut ph_ch, &ph_tx, &mut ph_rx, &pc.id()).await;
        assert_eq!(pong, Some(App::Pong { req: 7 }));
    };
    tokio::join!(pc_side, phone_side);

    // ПК вышел — телефон видит это и получает «не в сети» на отправку
    ph_tx.send(Relay::Watch { ids: vec![pc.id()] }).unwrap();
    assert_eq!(recv(&mut ph_rx).await, Relay::Presence { id: pc.id(), online: true });
    drop((pc_tx, pc_rx));
    assert_eq!(recv(&mut ph_rx).await, Relay::Presence { id: pc.id(), online: false });
    ph_tx.send(Relay::send(&pc.id(), b"x")).unwrap();
    assert_eq!(recv(&mut ph_rx).await, Relay::Offline { id: pc.id() });
}

#[tokio::test]
async fn foreign_id_rejected_and_invite_only_from_agent() {
    let url = start().await;
    let phone = Identity::generate();
    let (tx, mut rx) = connect(&url, &phone, Role::Client).await.unwrap();
    let inv = Invite { relay: url.clone(), agent: phone.id(), key: identity::encode_key(&phone.dh_public()), name: "x".into() };
    tx.send(Relay::InvitePut { key: "ABCD".into(), invite: inv }).unwrap();
    assert!(matches!(recv(&mut rx).await, Relay::Error { code, .. } if code == "forbidden"));

    // подделка: чужой id со своим ключом — вход не проходит
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let hello = Relay::Hello { id: Identity::generate().id(), pk: phone.sign_public(), role: Role::Agent, proto: remote_proto::PROTOCOL };
    ws.send(Message::Text(hello.to_text())).await.unwrap();
    let Some(Ok(Message::Text(t))) = ws.next().await else { panic!() };
    let Relay::Challenge { n } = Relay::from_text(&t).unwrap() else { panic!() };
    ws.send(Message::Text(Relay::Auth { sig: phone.sign_challenge(&decode_data(&n).unwrap()) }.to_text())).await.unwrap();
    let Some(Ok(Message::Text(t))) = ws.next().await else { panic!() };
    assert!(matches!(Relay::from_text(&t).unwrap(), Relay::Error { code, .. } if code == "auth"));
}
