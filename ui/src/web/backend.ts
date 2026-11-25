import type { Backend } from "../api/backend";
import type {
  Activation,
  BackendError,
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
} from "../api/types";
import { isBackendError } from "../api/types";
import type { SyncKv } from "./kv";

/** Sous-ensemble du module WASM utilisé ici (facilite les tests). */
export interface WebAppApi {
  activate(username: string, code: string, password: string): Promise<unknown>;
  enroll(username: string, password: string, totp: string): Promise<unknown>;
  login(username: string, password: string, totp?: string | null): Promise<unknown>;
  lock(): Promise<unknown>;
  logout(): Promise<unknown>;
  wipe(username: string): Promise<unknown>;
  linkStart(username: string, password: string, totp: string): Promise<unknown>;
  linkPoll(): Promise<unknown>;
  conversations(): Promise<unknown>;
  conversation(id: string): Promise<unknown>;
  messages(id: string): Promise<unknown>;
  startConversation(peer: string): Promise<unknown>;
  createGroup(name: string, members: string[]): Promise<unknown>;
  addMember(id: string, username: string): Promise<unknown>;
  removeMember(id: string, username: string): Promise<unknown>;
  leaveGroup(id: string): Promise<unknown>;
  setEphemeral(id: string, ttl: number | null): Promise<unknown>;
  send(id: string, text: string): Promise<unknown>;
  sendFile(id: string, name: string, data: Uint8Array, caption: string | null): Promise<unknown>;
  downloadFile(messageId: string): Promise<unknown>;
  markRead(id: string): Promise<unknown>;
  sync(): Promise<unknown>;
  wsUrl(): Promise<unknown>;
  safetyNumber(username: string): Promise<unknown>;
  verifySafetyNumber(username: string, scanned: string | null): Promise<unknown>;
  acceptIdentityChange(username: string): Promise<unknown>;
  devices(): Promise<unknown>;
  revokeDevice(id: string): Promise<unknown>;
  linkRequests(): Promise<unknown>;
  approveLink(code: string): Promise<unknown>;
  rejectLink(id: string): Promise<unknown>;
}

interface DownloadedFile {
  name: string;
  mime: string;
  data: Uint8Array;
}

export interface WebOptions {
  /** Ouverture du WebSocket de notification (injectable pour les tests). */
  openSocket?: (url: string) => WebSocket;
  /** Intervalle de synchronisation de secours (ms). */
  pollMs?: number;
  /** Période de vérification du verrouillage automatique (ms). */
  lockCheckMs?: number;
}

const unsupported = (what: string): BackendError => ({
  kind: "unsupported",
  message: `${what} : non disponible dans le client web.`,
});

/**
 * Backend du client web : délègue au module WASM (cryptographie, stockage
 * chiffré, réseau) et gère ici les notifications, le verrouillage
 * automatique et la révocation.
 */
export function createWebBackend(app: WebAppApi, kv: SyncKv, opts: WebOptions = {}): Backend {
  const openSocket = opts.openSocket ?? ((url: string) => new WebSocket(url));
  const pollMs = opts.pollMs ?? 30_000;
  const updateListeners = new Set<(r: SyncReport) => void>();
  const lockListeners = new Set<() => void>();
  const revokeListeners = new Set<() => void>();
  let username: string | null = null;
  let socket: WebSocket | null = null;
  let pollTimer: ReturnType<typeof setInterval> | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let backoff = 1000;
  let syncing = false;
  let autoLockMinutes = 5;
  let lastActivity = Date.now();
  let generation = 0;

  const persist = async <T>(p: Promise<unknown>): Promise<T> => {
    const r = (await p) as T;
    await kv.flush();
    return r;
  };

  async function handleRevoked() {
    const name = username;
    stop();
    if (name) await app.wipe(name);
    await kv.flush();
    revokeListeners.forEach((cb) => cb());
  }

  async function syncAndEmit() {
    if (!username || syncing) return;
    syncing = true;
    try {
      const r = await persist<SyncReport>(app.sync());
      updateListeners.forEach((cb) => cb(r));
    } catch (e) {
      if (isBackendError(e) && e.kind === "device_revoked") await handleRevoked();
    } finally {
      syncing = false;
    }
  }

  async function connect(gen: number) {
    if (gen !== generation || !username) return;
    try {
      const url = (await app.wsUrl()) as string;
      if (gen !== generation) return;
      const ws = openSocket(url);
      socket = ws;
      ws.onopen = () => {
        backoff = 1000;
        void syncAndEmit();
      };
      ws.onmessage = () => void syncAndEmit();
      ws.onclose = () => {
        if (gen !== generation) return;
        socket = null;
        reconnectTimer = setTimeout(() => void connect(gen), backoff);
        backoff = Math.min(backoff * 2, 60_000);
      };
    } catch (e) {
      if (isBackendError(e) && e.kind === "device_revoked") return handleRevoked();
      reconnectTimer = setTimeout(() => void connect(gen), backoff);
      backoff = Math.min(backoff * 2, 60_000);
    }
  }

  function start(s: Session): Session {
    stop();
    username = s.username;
    lastActivity = Date.now();
    const gen = ++generation;
    void connect(gen);
    pollTimer = setInterval(() => {
      if (Date.now() - lastActivity >= autoLockMinutes * 60_000) {
        void doLock().then(() => lockListeners.forEach((cb) => cb()));
        return;
      }
      void syncAndEmit();
    }, Math.min(pollMs, opts.lockCheckMs ?? pollMs));
    return s;
  }

  function stop() {
    generation++;
    username = null;
    if (pollTimer) clearInterval(pollTimer);
    if (reconnectTimer) clearTimeout(reconnectTimer);
    pollTimer = null;
    reconnectTimer = null;
    if (socket) {
      socket.onclose = null;
      socket.close();
      socket = null;
    }
  }

  async function doLock() {
    stop();
    await app.lock();
  }

  async function download(messageId: string): Promise<DownloadedFile> {
    return (await app.downloadFile(messageId)) as DownloadedFile;
  }

  return {
    platform: "web",
    activate: (_server, u, code, pw) => app.activate(u, code, pw) as Promise<Activation>,
    enroll: async (_server, u, pw, totp) => start(await persist<Session>(app.enroll(u, pw, totp))),
    login: async (_server, u, pw, totp) => start(await persist<Session>(app.login(u, pw, totp))),
    loginPasskey: async () => Promise.reject(unsupported("Les clés de sécurité")),
    lock: doLock,
    logout: async () => {
      stop();
      await persist(app.logout());
    },
    activity: async () => {
      lastActivity = Date.now();
    },
    setAutoLock: async (minutes) => {
      if (minutes < 1 || minutes > 240) throw { kind: "error", message: "délai de verrouillage invalide" };
      autoLockMinutes = minutes;
    },
    securityStatus: async (): Promise<SecurityStatus> => ({
      captureProtection: "indisponible dans un navigateur",
      autoLockMinutes,
      passkeysSupported: false,
    }),

    conversations: () => app.conversations() as Promise<Conversation[]>,
    conversation: (id) => app.conversation(id) as Promise<Conversation>,
    messages: (id) => app.messages(id) as Promise<Message[]>,
    startConversation: (peer) => persist<Conversation>(app.startConversation(peer)),
    createGroup: (name, members) => persist<Conversation>(app.createGroup(name, members)),
    addMember: (id, u) => persist<Conversation>(app.addMember(id, u)),
    removeMember: (id, u) => persist<Conversation>(app.removeMember(id, u)),
    leaveGroup: (id) => persist<void>(app.leaveGroup(id)),
    setEphemeral: (id, ttl) => persist<void>(app.setEphemeral(id, ttl)),
    send: (id, text) => persist<Message>(app.send(id, text)),
    sendFile: (id, name, data, caption) => persist<Message>(app.sendFile(id, name, data, caption)),
    imageBytes: async (messageId) => {
      const f = await download(messageId);
      if (f.mime !== "image/jpeg" && f.mime !== "image/png") throw { kind: "error", message: "aperçu réservé aux images" };
      return f.data.slice().buffer;
    },
    saveAttachment: async (messageId) => {
      const f = await download(messageId);
      const url = URL.createObjectURL(new Blob([f.data.slice()], { type: "application/octet-stream" }));
      try {
        const a = document.createElement("a");
        a.href = url;
        a.download = f.name;
        a.rel = "noopener";
        a.click();
      } finally {
        setTimeout(() => URL.revokeObjectURL(url), 10_000);
      }
      return true;
    },
    markRead: (id) => persist<void>(app.markRead(id)),
    sync: async () => {
      try {
        return await persist<SyncReport>(app.sync());
      } catch (e) {
        if (isBackendError(e) && e.kind === "device_revoked") await handleRevoked();
        throw e;
      }
    },

    safetyNumber: (u) => app.safetyNumber(u) as Promise<SafetyNumber>,
    verifySafetyNumber: (u, scanned) => persist<boolean>(app.verifySafetyNumber(u, scanned)),
    acceptIdentityChange: (u) => persist<void>(app.acceptIdentityChange(u)),

    linkStart: (_server, u, pw, totp) => app.linkStart(u, pw, totp) as Promise<LinkStart>,
    linkPoll: async () => {
      const r = await persist<LinkPoll>(app.linkPoll());
      if (r.status === "linked" && r.session) start(r.session);
      return r;
    },
    devices: () => app.devices() as Promise<Device[]>,
    revokeDevice: (id) => persist<void>(app.revokeDevice(id)),
    linkRequests: () => app.linkRequests() as Promise<LinkRequest[]>,
    approveLink: (code) => persist<void>(app.approveLink(code)),
    rejectLink: (id) => persist<void>(app.rejectLink(id)),

    registerPasskey: async (): Promise<Passkey> => Promise.reject(unsupported("Les clés de sécurité")),
    listPasskeys: async () => [],
    deletePasskey: async () => Promise.reject(unsupported("Les clés de sécurité")),

    onUpdate: async (cb) => {
      updateListeners.add(cb);
      return () => void updateListeners.delete(cb);
    },
    onLocked: async (cb) => {
      lockListeners.add(cb);
      return () => void lockListeners.delete(cb);
    },
    onRevoked: async (cb) => {
      revokeListeners.add(cb);
      return () => void revokeListeners.delete(cb);
    },
  };
}
