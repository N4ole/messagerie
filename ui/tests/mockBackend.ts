import { vi } from "vitest";
import type { Backend } from "../src/api/backend";
import type { Conversation, Message, SyncReport } from "../src/api/types";

export function mockBackend(over: Partial<Backend> = {}): Backend & { emit: (r: SyncReport) => void } {
  let listener: ((r: SyncReport) => void) | null = null;
  const conv: Conversation = { id: "aa", peer: "bob", last_activity_ms: 0, unread: 0, peer_fingerprint: "ABCD" };
  const b: Backend = {
    activate: vi.fn(async () => ({ totp_secret_base32: "JBSWY3DP", otpauth_uri: "otpauth://x", qr_data_uri: "data:image/svg+xml;base64,PHN2Zy8+" })),
    enroll: vi.fn(async (_s, username) => ({ username, deviceId: "d", fingerprint: "FP" })),
    login: vi.fn(async (_s, username) => ({ username, deviceId: "d", fingerprint: "FP" })),
    logout: vi.fn(async () => undefined),
    conversations: vi.fn(async () => [conv]),
    messages: vi.fn(async (): Promise<Message[]> => []),
    startConversation: vi.fn(async () => conv),
    send: vi.fn(async (id: string, text: string): Promise<Message> => ({
      id: "m1",
      conversation_id: id,
      sender: "alice",
      outgoing: true,
      sent_at_ms: 0,
      received_at_ms: 0,
      text,
      ast: [{ t: "paragraph", c: [{ t: "text", text }] }],
    })),
    markRead: vi.fn(async () => undefined),
    sync: vi.fn(async () => ({ processed: 0, new_messages: 0, changed_conversations: [], rejected: 0 })),
    onUpdate: vi.fn(async (cb) => {
      listener = cb;
      return () => {
        listener = null;
      };
    }),
    ...over,
  };
  return Object.assign(b, { emit: (r: SyncReport) => listener?.(r) });
}
