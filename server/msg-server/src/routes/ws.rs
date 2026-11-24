//! WebSocket de notification : signale seulement « nouveaux messages »,
//! le contenu est toujours récupéré via `GET /v1/queue`.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use axum::Extension;
use msg_proto::PushEvent;
use tokio::sync::broadcast::error::RecvError;

use crate::auth::AuthContext;
use crate::state::AppState;

pub async fn handler(
    ws: WebSocketUpgrade,
    State(st): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Response {
    ws.max_message_size(4096).on_upgrade(move |socket| run(socket, st, ctx))
}

async fn notify(socket: &mut WebSocket) -> bool {
    let text = serde_json::to_string(&PushEvent::NewMessages).expect("sérialisable");
    socket.send(Message::Text(text.into())).await.is_ok()
}

async fn run(mut socket: WebSocket, st: AppState, ctx: AuthContext) {
    let mut rx = st.inner.hub.subscribe();
    if matches!(crate::routes::messages::has_pending(&st, ctx.device_id).await, Ok(true)) && !notify(&mut socket).await
    {
        return;
    }
    let mut ping = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok(dev) if dev == ctx.device_id => if !notify(&mut socket).await { return },
                Ok(_) => {}
                Err(RecvError::Lagged(_)) => if !notify(&mut socket).await { return },
                Err(RecvError::Closed) => return,
            },
            msg = socket.recv() => match msg {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                _ => {}
            },
            _ = ping.tick() => {
                // Vérifie aussi que la session est toujours valide (révocation, suspension).
                let ok: Result<Option<(i64,)>, _> = sqlx::query_as(
                    "SELECT s.id FROM sessions s JOIN devices d ON d.id = s.device_id JOIN accounts a ON a.id = d.account_id
                      WHERE s.device_id = $1 AND s.session_expires_at > $2 AND a.status = 'active'")
                    .bind(ctx.device_id).bind(crate::now()).fetch_optional(st.db()).await;
                if !matches!(ok, Ok(Some(_))) { let _ = socket.send(Message::Close(None)).await; return; }
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() { return; }
            }
        }
    }
}
