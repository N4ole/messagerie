import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { Backend } from "./backend";
import type { Activation, Conversation, Message, Session, SyncReport } from "./types";

export const tauriBackend: Backend = {
  activate: (server, username, code, password) =>
    invoke<Activation>("activate", { server, username, code, password }),
  enroll: (server, username, password, totp) => invoke<Session>("enroll", { server, username, password, totp }),
  login: (server, username, password, totp) => invoke<Session>("login", { server, username, password, totp }),
  logout: () => invoke<void>("logout"),
  conversations: () => invoke<Conversation[]>("conversations"),
  messages: (conversationId) => invoke<Message[]>("messages", { conversationId }),
  startConversation: (peer) => invoke<Conversation>("start_conversation", { peer }),
  send: (conversationId, text) => invoke<Message>("send_message", { conversationId, text }),
  markRead: (conversationId) => invoke<void>("mark_read", { conversationId }),
  sync: () => invoke<SyncReport>("sync"),
  onUpdate: async (cb) => listen<SyncReport>("messages-updated", (e) => cb(e.payload)),
};
