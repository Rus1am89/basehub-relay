//! Прикладные сообщения внутри шифра (JSON). Запросы несут `req`, ответ повторяет его.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum App {
    /// Первое сообщение после рукопожатия — с обеих сторон.
    Hello { name: String, app: String, version: String },
    /// ПК подтвердил сопряжение (пользователь нажал «Подключить»).
    Paired { name: String },
    /// ПК отказал: пользователь не подтвердил, телефон отозван, выключен удалённый доступ.
    Denied { reason: String },

    Ping { req: u64 },
    Pong { req: u64 },

    ListBases { req: u64 },
    Bases { req: u64, items: Vec<Base> },

    /// Консоль кода: выполнить код 1С в базе (на ПК — через COM, как консоль Basehub).
    RunCode { req: u64, base: String, code: String },
    CodeResult { req: u64, ms: u64, error: String, output: String },

    /// Консоль запросов: `params` — JSON {имя: значение}, ответ — JSON консоли Basehub
    /// `{ms, total, columns, rows, error}` как есть (в базе нужно расширение Basehub).
    RunQuery { req: u64, base: String, text: String, params: String, limit: u32 },
    QueryResult { req: u64, json: String },

    Error { req: u64, text: String },
}

/// Информационная база из списка ПК (ibases.v8i).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Base {
    pub name: String,
    /// Папка в списке баз 1С, пусто — корень.
    #[serde(default)]
    pub folder: String,
    /// Строка соединения (`File="…";` / `Srvr="…";Ref="…";`).
    pub connect: String,
    /// На ПК разрешена консоль кода для этой базы.
    #[serde(default)]
    pub code: bool,
    /// На ПК разрешена консоль запросов.
    #[serde(default)]
    pub query: bool,
}

impl App {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("app json")
    }

    pub fn from_bytes(b: &[u8]) -> Result<App, String> {
        serde_json::from_slice(b).map_err(|e| format!("непонятное сообщение: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let m = App::Bases { req: 3, items: vec![Base { name: "Бух".into(), folder: "".into(), connect: "File=\"C:\\b\";".into(), code: true, query: true }] };
        assert_eq!(App::from_bytes(&m.to_bytes()).unwrap(), m);
        assert_eq!(App::from_bytes(br#"{"op":"ping","req":1}"#).unwrap(), App::Ping { req: 1 });
        // старый ПК без поля code — консоль кода выключена
        let old = br#"{"op":"bases","req":1,"items":[{"name":"B","connect":""}]}"#;
        let App::Bases { items, .. } = App::from_bytes(old).unwrap() else { panic!() };
        assert!(!items[0].code);
        let r = App::RunCode { req: 2, base: "Бух".into(), code: "Сообщить(1);".into() };
        assert_eq!(App::from_bytes(&r.to_bytes()).unwrap(), r);
        let q = App::RunQuery { req: 3, base: "Бух".into(), text: "ВЫБРАТЬ 1".into(), params: "{}".into(), limit: 500 };
        assert_eq!(App::from_bytes(&q.to_bytes()).unwrap(), q);
    }
}
