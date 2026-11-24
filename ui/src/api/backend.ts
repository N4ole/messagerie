import type { Activation, Conversation, Message, Session, SyncReport } from "./types";

/**
 * Interface entre l'UI et le cœur cryptographique. Desktop : commandes Tauri
 * (les clés restent dans le processus Rust). Web (Phase 3) : module WASM.
 */
export interface Backend {
  activate(server: string, username: string, code: string, password: string): Promise<Activation>;
  enroll(server: string, username: string, password: string, totp: string): Promise<Session>;
  login(server: string, username: string, password: string, totp: string | null): Promise<Session>;
  logout(): Promise<void>;
  conversations(): Promise<Conversation[]>;
  messages(conversationId: string): Promise<Message[]>;
  startConversation(peer: string): Promise<Conversation>;
  send(conversationId: string, text: string): Promise<Message>;
  markRead(conversationId: string): Promise<void>;
  sync(): Promise<SyncReport>;
  /** Abonnement aux mises à jour poussées ; retourne la fonction de désabonnement. */
  onUpdate(cb: (r: SyncReport) => void): Promise<() => void>;
}
