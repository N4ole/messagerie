/** Types échangés avec le cœur Rust (miroir de `msg-client-core`). */

export interface Session {
  username: string;
  deviceId: string;
  fingerprint: string;
}

export interface Conversation {
  id: string;
  peer: string;
  last_activity_ms: number;
  unread: number;
  peer_fingerprint: string;
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

export interface Message {
  id: string;
  conversation_id: string;
  sender: string;
  outgoing: boolean;
  sent_at_ms: number;
  received_at_ms: number;
  text: string;
  ast: MdNode[];
}

export interface SyncReport {
  processed: number;
  new_messages: number;
  changed_conversations: string[];
  rejected: number;
}

export interface Activation {
  totp_secret_base32: string;
  otpauth_uri: string;
  /** QR code SVG généré localement (data URI). */
  qr_data_uri: string;
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
