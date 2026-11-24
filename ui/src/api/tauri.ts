import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { Backend } from "./backend";
import type {
  Activation,
  Conversation,
  Message,
  Passkey,
  SafetyNumber,
  SecurityStatus,
  Session,
  SyncReport,
} from "./types";

/** Base64URL (UTF-8) pour transporter des chaînes dans des en-têtes IPC. */
function b64url(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export const tauriBackend: Backend = {
  activate: (server, username, code, password) =>
    invoke<Activation>("activate", { server, username, code, password }),
  enroll: (server, username, password, totp) => invoke<Session>("enroll", { server, username, password, totp }),
  login: (server, username, password, totp) => invoke<Session>("login", { server, username, password, totp }),
  loginPasskey: (server, username, password) => invoke<Session>("login_passkey", { server, username, password }),
  lock: () => invoke<void>("lock"),
  logout: () => invoke<void>("logout"),
  activity: () => invoke<void>("activity"),
  setAutoLock: (minutes) => invoke<void>("set_auto_lock", { minutes }),
  securityStatus: () => invoke<SecurityStatus>("security_status"),

  conversations: () => invoke<Conversation[]>("conversations"),
  conversation: (conversationId) => invoke<Conversation>("conversation", { conversationId }),
  messages: (conversationId) => invoke<Message[]>("messages", { conversationId }),
  startConversation: (peer) => invoke<Conversation>("start_conversation", { peer }),
  createGroup: (name, members) => invoke<Conversation>("create_group", { name, members }),
  addMember: (conversationId, username) => invoke<Conversation>("add_member", { conversationId, username }),
  removeMember: (conversationId, username) => invoke<Conversation>("remove_member", { conversationId, username }),
  leaveGroup: (conversationId) => invoke<void>("leave_group", { conversationId }),
  setEphemeral: (conversationId, ttlS) => invoke<void>("set_ephemeral", { conversationId, ttlS }),
  send: (conversationId, text) => invoke<Message>("send_message", { conversationId, text }),
  sendFile: (conversationId, name, data, caption) => {
    const headers: Record<string, string> = { "x-conversation": conversationId, "x-file-name": b64url(name) };
    if (caption) headers["x-caption"] = b64url(caption);
    return invoke<Message>("send_file", data, { headers });
  },
  imageBytes: (messageId) => invoke<ArrayBuffer>("image_bytes", { messageId }),
  saveAttachment: (messageId) => invoke<boolean>("save_attachment", { messageId }),
  markRead: (conversationId) => invoke<void>("mark_read", { conversationId }),
  sync: () => invoke<SyncReport>("sync"),

  safetyNumber: (username) => invoke<SafetyNumber>("safety_number", { username }),
  verifySafetyNumber: (username, scanned) => invoke<boolean>("verify_safety_number", { username, scanned }),
  acceptIdentityChange: (username) => invoke<void>("accept_identity_change", { username }),

  registerPasskey: (name) => invoke<Passkey>("register_passkey", { name }),
  listPasskeys: () => invoke<Passkey[]>("list_passkeys"),
  deletePasskey: (id) => invoke<void>("delete_passkey", { id }),

  onUpdate: async (cb) => listen<SyncReport>("messages-updated", (e) => cb(e.payload)),
  onLocked: async (cb) => listen("locked", () => cb()),
};
