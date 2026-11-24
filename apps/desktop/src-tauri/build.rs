// Les commandes IPC sont déclarées explicitement : chacune doit être
// autorisée par une capability (`capabilities/default.json`).
const COMMANDS: &[&str] = &[
    "activate",
    "enroll",
    "login",
    "login_passkey",
    "lock",
    "logout",
    "activity",
    "set_auto_lock",
    "security_status",
    "conversations",
    "conversation",
    "messages",
    "start_conversation",
    "create_group",
    "add_member",
    "remove_member",
    "leave_group",
    "set_ephemeral",
    "send_message",
    "send_file",
    "image_bytes",
    "save_attachment",
    "mark_read",
    "sync",
    "safety_number",
    "verify_safety_number",
    "accept_identity_change",
    "register_passkey",
    "list_passkeys",
    "delete_passkey",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("échec de la génération Tauri");
}
