/**
 * Module WASM du client web (généré par `wasm-bindgen` à partir de
 * `crates/msg-wasm` ; alias Vite `msg-wasm` → `src/wasm-pkg/msg_wasm.js`).
 * Déclaration minimale pour que l'interface se vérifie sans le module généré.
 */
declare module "msg-wasm" {
  export default function init(): Promise<unknown>;
  export class WebApp {
    constructor(server: string, kv: unknown);
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
}
