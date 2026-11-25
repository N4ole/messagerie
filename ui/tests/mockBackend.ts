import { vi } from "vitest";
import type { Backend } from "../src/api/backend";
import type { Conversation, Message, Session, SyncReport } from "../src/api/types";

export const session: Session = {
  username: "alice",
  deviceId: "d",
  fingerprint: "FP",
  vaultProtection: "tpm+dpapi",
  captureProtection: "exclue des captures",
  primary: true,
};

export function report(over: Partial<SyncReport> = {}): SyncReport {
  return {
    processed: 0,
    new_messages: 0,
    changed_conversations: [],
    rejected: 0,
    identity_changes: [],
    removed_from: [],
    expired: 0,
    rotations: 0,
    ...over,
  };
}

export function conversation(over: Partial<Conversation> = {}): Conversation {
  return {
    id: "aa",
    kind: "direct",
    title: "bob",
    peer: "bob",
    members: ["alice", "bob"],
    admin: "alice",
    is_admin: true,
    status: "ok",
    identity_changed: [],
    last_activity_ms: 0,
    unread: 0,
    verified: false,
    peer_fingerprint: "ABCD",
    ttl_s: null,
    ...over,
  };
}

export function message(over: Partial<Message> = {}): Message {
  const text = over.text ?? "salut";
  return {
    id: "m1",
    conversation_id: "aa",
    sender: "alice",
    outgoing: true,
    sent_at_ms: 0,
    received_at_ms: 0,
    kind: "text",
    text,
    ast: [{ t: "paragraph", c: [{ t: "text", text }] }],
    attachment: null,
    expires_at_ms: null,
    ...over,
  };
}

export function mockBackend(
  over: Partial<Backend> = {},
): Backend & { emit: (r: SyncReport) => void; lockNow: () => void; revokeNow: () => void } {
  let listener: ((r: SyncReport) => void) | null = null;
  let locked: (() => void) | null = null;
  let revoked: (() => void) | null = null;
  const conv = conversation();
  const b: Backend = {
    platform: "desktop",
    activate: vi.fn(async () => ({
      totp_secret_base32: "JBSWY3DP",
      otpauth_uri: "otpauth://x",
      qr_data_uri: "data:image/svg+xml;base64,PHN2Zy8+",
    })),
    enroll: vi.fn(async (_s: string, username: string) => ({ ...session, username })),
    login: vi.fn(async (_s: string, username: string) => ({ ...session, username })),
    loginPasskey: vi.fn(async (_s: string, username: string) => ({ ...session, username })),
    lock: vi.fn(async () => undefined),
    logout: vi.fn(async () => undefined),
    activity: vi.fn(async () => undefined),
    setAutoLock: vi.fn(async () => undefined),
    securityStatus: vi.fn(async () => ({ captureProtection: "exclue des captures", autoLockMinutes: 5, passkeysSupported: true })),
    conversations: vi.fn(async () => [conv]),
    conversation: vi.fn(async () => conv),
    messages: vi.fn(async (): Promise<Message[]> => []),
    startConversation: vi.fn(async () => conv),
    createGroup: vi.fn(async (name: string, members: string[]) =>
      conversation({ id: "gg", kind: "group", title: name, members: ["alice", ...members] }),
    ),
    addMember: vi.fn(async () => conv),
    removeMember: vi.fn(async () => conv),
    leaveGroup: vi.fn(async () => undefined),
    setEphemeral: vi.fn(async () => undefined),
    send: vi.fn(async (id: string, text: string): Promise<Message> => message({ conversation_id: id, text })),
    sendFile: vi.fn(async (id: string, name: string) =>
      message({
        id: "f1",
        conversation_id: id,
        kind: "attachment",
        text: "",
        ast: [],
        attachment: { name, mime: "application/pdf", size: 10, metadata_cleaned: false, thumbnail_data_uri: null },
      }),
    ),
    imageBytes: vi.fn(async () => new ArrayBuffer(4)),
    saveAttachment: vi.fn(async () => true),
    markRead: vi.fn(async () => undefined),
    sync: vi.fn(async () => report()),
    safetyNumber: vi.fn(async (username: string) => ({
      username,
      number: "12345 ".repeat(12).trim(),
      qr_payload: "messagerie-sn:1:" + "12345".repeat(12),
      qr_data_uri: "data:image/svg+xml;base64,PHN2Zy8+",
      verified: false,
      identity_changed: false,
    })),
    verifySafetyNumber: vi.fn(async () => true),
    acceptIdentityChange: vi.fn(async () => undefined),
    linkStart: vi.fn(async () => ({
      code: "messagerie-link:1:00000000-0000-0000-0000-000000000001:ABCDEF0123456789ABCD",
      fingerprint: "ABCD EF01 2345 6789 ABCD",
      qr_data_uri: "data:image/svg+xml;base64,PHN2Zy8+",
      expires_at: 0,
    })),
    linkPoll: vi.fn(async () => ({ status: "pending" as const, session: null })),
    devices: vi.fn(async () => [
      { device_id: "d", created_at: 1, last_seen_at: null, current: true },
      { device_id: "d2", created_at: 2, last_seen_at: 3600, current: false },
    ]),
    revokeDevice: vi.fn(async () => undefined),
    linkRequests: vi.fn(async () => []),
    approveLink: vi.fn(async () => undefined),
    rejectLink: vi.fn(async () => undefined),
    registerPasskey: vi.fn(async (name: string) => ({ id: 1, name, created_at: 0, last_used_at: null })),
    listPasskeys: vi.fn(async () => []),
    deletePasskey: vi.fn(async () => undefined),
    onUpdate: vi.fn(async (cb) => {
      listener = cb;
      return () => {
        listener = null;
      };
    }),
    onLocked: vi.fn(async (cb) => {
      locked = cb;
      return () => {
        locked = null;
      };
    }),
    onRevoked: vi.fn(async (cb) => {
      revoked = cb;
      return () => {
        revoked = null;
      };
    }),
    ...over,
  };
  return Object.assign(b, {
    emit: (r: SyncReport) => listener?.(r),
    lockNow: () => locked?.(),
    revokeNow: () => revoked?.(),
  });
}
