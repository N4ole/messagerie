/** Types échangés avec le cœur Rust (miroir de `msg-client-core`). */

export interface Session {
  username: string;
  deviceId: string;
  fingerprint: string;
  /** Protection du coffre local : `tpm+dpapi`, `dpapi`, `none`… */
  vaultProtection: string;
  /** Protection contre la capture d'écran appliquée à la fenêtre. */
  captureProtection: string;
  /** Appareil principal (détient la clé d'identité, approuve les nouveaux appareils). */
  primary: boolean;
}

/** Liaison de cet appareil à un compte existant (affiché par le nouvel appareil). */
export interface LinkStart {
  code: string;
  fingerprint: string;
  qr_data_uri: string;
  expires_at: number;
}

export interface LinkPoll {
  status: "pending" | "linked" | "rejected" | "expired";
  session: Session | null;
}

/** Appareil du compte courant. */
export interface Device {
  device_id: string;
  created_at: number;
  last_seen_at: number | null;
  current: boolean;
}

/** Demande de liaison en attente (vue par l'appareil principal). */
export interface LinkRequest {
  link_id: string;
  device_id: string;
  fingerprint: string;
  created_at: number;
  expires_at: number;
}

export type ConversationStatus = "ok" | "identity_changed" | "removed" | "left";

export interface Conversation {
  id: string;
  kind: "direct" | "group";
  title: string;
  peer: string;
  members: string[];
  admin: string | null;
  is_admin: boolean;
  status: ConversationStatus;
  identity_changed: string[];
  last_activity_ms: number;
  unread: number;
  verified: boolean;
  peer_fingerprint: string;
  ttl_s: number | null;
}

/** Nœuds de l'AST Markdown sûr produit par `msg-markdown`. */
export type MdNode =
  | { t: "paragraph"; c: MdNode[] }
  | { t: "heading"; level: number; c: MdNode[] }
  | { t: "block_quote"; c: MdNode[] }
  | { t: "code_block"; lang: string | null; text: string }
  | { t: "list"; ordered: boolean; start: number | null; c: MdNode[] }
  | { t: "item"; c: MdNode[] }
  | { t: "emphasis"; c: MdNode[] }
  | { t: "strong"; c: MdNode[] }
  | { t: "strikethrough"; c: MdNode[] }
  | { t: "link"; url: string | null; c: MdNode[] }
  | { t: "image"; url: string; alt: string }
  | { t: "code"; text: string }
  | { t: "text"; text: string }
  | { t: "soft_break" }
  | { t: "hard_break" }
  | { t: "rule" };

export interface Attachment {
  name: string;
  mime: string;
  size: number;
  metadata_cleaned: boolean;
  /** Miniature générée localement (data URI), jamais distante. */
  thumbnail_data_uri: string | null;
}

export interface Message {
  id: string;
  conversation_id: string;
  sender: string;
  outgoing: boolean;
  sent_at_ms: number;
  received_at_ms: number;
  kind: "text" | "attachment";
  text: string;
  ast: MdNode[];
  attachment: Attachment | null;
  expires_at_ms: number | null;
}

export interface SyncReport {
  processed: number;
  new_messages: number;
  changed_conversations: string[];
  rejected: number;
  identity_changes: string[];
  removed_from: string[];
  expired: number;
  rotations: number;
  reconciled?: number;
}

export interface Activation {
  totp_secret_base32: string;
  otpauth_uri: string;
  /** QR code SVG généré localement (data URI). */
  qr_data_uri: string;
}

export interface SafetyNumber {
  username: string;
  /** 60 chiffres par groupes de 5. */
  number: string;
  qr_payload: string;
  qr_data_uri: string;
  verified: boolean;
  identity_changed: boolean;
}

export interface Passkey {
  id: number;
  name: string;
  created_at: number;
  last_used_at: number | null;
}

export interface SecurityStatus {
  captureProtection: string;
  autoLockMinutes: number;
  passkeysSupported: boolean;
  /** Empreinte SHA-256 de l'exécutable (desktop) ; vide dans un navigateur. */
  executableSha256: string;
  /** État de la signature Authenticode, en clair. */
  signature: string;
}

/** Erreur structurée renvoyée par le cœur. */
export interface BackendError {
  kind: string;
  message: string;
}

export function isBackendError(e: unknown): e is BackendError {
  return typeof e === "object" && e !== null && "kind" in e && "message" in e;
}

export function errorMessage(e: unknown): string {
  if (isBackendError(e)) return e.message;
  if (e instanceof Error) return e.message;
  return String(e);
}
