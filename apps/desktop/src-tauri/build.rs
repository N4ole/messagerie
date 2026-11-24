// Les commandes IPC sont déclarées explicitement : chacune doit être
// autorisée par une capability (`capabilities/default.json`).
const COMMANDS: &[&str] = &[
    "activate",
    "enroll",
    "login",
    "logout",
    "conversations",
    "messages",
    "start_conversation",
    "send_message",
    "mark_read",
    "sync",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("échec de la génération Tauri");
}
