import type {
  Activation,
  Conversation,
  Device,
  LinkPoll,
  LinkRequest,
  LinkStart,
  Message,
  Passkey,
  SafetyNumber,
  SecurityStatus,
  Session,
  SyncReport,
} from "./types";

/**
 * Interface entre l'UI et le cœur cryptographique. Desktop : commandes Tauri
 * (les clés restent dans le processus Rust). Web : le même cœur Rust compilé
 * en WebAssembly (les clés restent dans la mémoire du module).
 */
export interface Backend {
  readonly platform: "desktop" | "web";
  activate(server: string, username: string, code: string, password: string): Promise<Activation>;
  enroll(server: string, username: string, password: string, totp: string): Promise<Session>;
  login(server: string, username: string, password: string, totp: string | null): Promise<Session>;
  loginPasskey(server: string, username: string, password: string): Promise<Session>;
  /** Efface les clés de la mémoire (déverrouillage par mot de passe). */
  lock(): Promise<void>;
  /** Ferme la session serveur (TOTP ou clé requis ensuite). */
  logout(): Promise<void>;
  activity(): Promise<void>;
  setAutoLock(minutes: number): Promise<void>;
  securityStatus(): Promise<SecurityStatus>;

  conversations(): Promise<Conversation[]>;
  conversation(id: string): Promise<Conversation>;
  messages(conversationId: string): Promise<Message[]>;
  startConversation(peer: string): Promise<Conversation>;
  createGroup(name: string, members: string[]): Promise<Conversation>;
  addMember(conversationId: string, username: string): Promise<Conversation>;
  removeMember(conversationId: string, username: string): Promise<Conversation>;
  leaveGroup(conversationId: string): Promise<void>;
  setEphemeral(conversationId: string, ttlSeconds: number | null): Promise<void>;
  send(conversationId: string, text: string): Promise<Message>;
  sendFile(conversationId: string, name: string, data: Uint8Array, caption: string | null): Promise<Message>;
  imageBytes(messageId: string): Promise<ArrayBuffer>;
  saveAttachment(messageId: string): Promise<boolean>;
  markRead(conversationId: string): Promise<void>;
  sync(): Promise<SyncReport>;

  safetyNumber(username: string): Promise<SafetyNumber>;
  verifySafetyNumber(username: string, scanned: string | null): Promise<boolean>;
  acceptIdentityChange(username: string): Promise<void>;

  /** Liaison de cet appareil à un compte existant (approuvée par l'appareil principal). */
  linkStart(server: string, username: string, password: string, totp: string): Promise<LinkStart>;
  linkPoll(): Promise<LinkPoll>;
  devices(): Promise<Device[]>;
  revokeDevice(deviceId: string): Promise<void>;
  linkRequests(): Promise<LinkRequest[]>;
  /** Approuve un nouvel appareil à partir du code (ou QR code) qu'il affiche. */
  approveLink(code: string): Promise<void>;
  rejectLink(linkId: string): Promise<void>;

  registerPasskey(name: string): Promise<Passkey>;
  listPasskeys(): Promise<Passkey[]>;
  deletePasskey(id: number): Promise<void>;

  /** Abonnement aux mises à jour poussées ; retourne la fonction de désabonnement. */
  onUpdate(cb: (r: SyncReport) => void): Promise<() => void>;
  /** Verrouillage automatique déclenché par le cœur. */
  onLocked(cb: () => void): Promise<() => void>;
  /** Cet appareil a été révoqué : ses données locales ont été effacées. */
  onRevoked(cb: () => void): Promise<() => void>;
}
