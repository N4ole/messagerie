import { describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "../src/App";
import { BackendContext } from "../src/api/context";
import type { Backend } from "../src/api/backend";
import { DevicesSection } from "../src/components/DevicesSection";
import { Auth } from "../src/views/Auth";
import { createWebBackend, type WebAppApi } from "../src/web/backend";
import { memoryKv } from "../src/web/kv";
import { mockBackend, report, session } from "./mockBackend";

function withBackend(b: Backend, ui: React.ReactNode) {
  return render(<BackendContext.Provider value={b}>{ui}</BackendContext.Provider>);
}

describe("Appareils", () => {
  it("liste les appareils et révoque un autre appareil", async () => {
    const b = mockBackend();
    withBackend(b, <DevicesSection session={session} />);
    expect(await screen.findByText(/Cet appareil/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Révoquer" }));
    await waitFor(() => expect(b.revokeDevice).toHaveBeenCalledWith("d2"));
    expect(await screen.findByText(/Appareil révoqué/)).toBeInTheDocument();
  });

  it("l'appareil principal approuve avec le code du nouvel appareil", async () => {
    const b = mockBackend({
      linkRequests: vi.fn(async () => [
        { link_id: "L1", device_id: "n", fingerprint: "ABCD EF01 2345 6789 ABCD", created_at: 1, expires_at: 2 },
      ]),
    });
    withBackend(b, <DevicesSection session={session} />);
    expect(await screen.findByText("ABCD EF01 2345 6789 ABCD")).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText(/Code affiché/), "messagerie-link:1:abc:ABCD");
    await userEvent.click(screen.getByRole("button", { name: "Approuver" }));
    await waitFor(() => expect(b.approveLink).toHaveBeenCalledWith("messagerie-link:1:abc:ABCD"));
    await userEvent.click(screen.getByRole("button", { name: "Refuser" }));
    await waitFor(() => expect(b.rejectLink).toHaveBeenCalledWith("L1"));
  });

  it("un appareil secondaire ne propose pas d'approbation", async () => {
    const b = mockBackend();
    withBackend(b, <DevicesSection session={{ ...session, primary: false }} />);
    expect(await screen.findByText(/Appareil secondaire/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approuver" })).toBeNull();
    expect(b.linkRequests).not.toHaveBeenCalled();
  });
});

describe("Liaison d'un nouvel appareil", () => {
  it("affiche le code puis ouvre la session une fois approuvé", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const poll = vi
        .fn()
        .mockResolvedValueOnce({ status: "pending", session: null })
        .mockResolvedValueOnce({ status: "linked", session: { ...session, primary: false } });
      const b = mockBackend({ linkPoll: poll });
      const onSession = vi.fn();
      withBackend(b, <Auth onSession={onSession} />);
      await userEvent.click(screen.getByRole("tab", { name: "Lier cet appareil" }));
      await userEvent.type(screen.getByLabelText("Identifiant"), "alice");
      await userEvent.type(screen.getByLabelText("Mot de passe"), "motdepasse-long");
      await userEvent.type(screen.getByLabelText("Code TOTP"), "123456");
      await userEvent.click(screen.getByRole("button", { name: "Demander la liaison" }));
      expect(await screen.findByAltText("QR code de liaison")).toBeInTheDocument();
      expect(screen.getByText("ABCD EF01 2345 6789 ABCD")).toBeInTheDocument();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(4100);
      });
      await waitFor(() => expect(onSession).toHaveBeenCalledWith(expect.objectContaining({ primary: false })));
    } finally {
      vi.useRealTimers();
    }
  });

  it("le client web n'affiche pas le champ serveur ni la connexion par clé", async () => {
    const b = mockBackend({ platform: "web" });
    withBackend(b, <Auth onSession={vi.fn()} />);
    expect(screen.queryByLabelText("Serveur")).toBeNull();
    expect(screen.queryByRole("button", { name: /clé de sécurité/ })).toBeNull();
  });
});

describe("Révocation", () => {
  it("revient à l'écran de connexion avec un avertissement", async () => {
    const b = mockBackend();
    withBackend(b, <App />);
    await userEvent.type(screen.getByLabelText("Serveur"), "https://srv");
    await userEvent.type(screen.getByLabelText("Identifiant"), "alice");
    await userEvent.type(screen.getByLabelText("Mot de passe"), "motdepasse-long");
    await userEvent.click(screen.getByRole("button", { name: "Se connecter" }));
    await screen.findByRole("button", { name: /Sécurité/ });
    act(() => b.revokeNow());
    expect(await screen.findByText(/a été révoqué/)).toBeInTheDocument();
  });
});

/** Module WASM simulé : seules les réponses utiles au test sont fournies. */
function fakeApp(over: Partial<WebAppApi> = {}): WebAppApi {
  const nop = vi.fn(async () => undefined);
  return new Proxy(
    {
      login: vi.fn(async () => ({ ...session, vaultProtection: "password" })),
      sync: vi.fn(async () => report({ processed: 1, new_messages: 1 })),
      wsUrl: vi.fn(async () => "ws://test/v1/ws/connect?ticket=t"),
      wipe: nop,
      lock: nop,
      ...over,
    } as Record<string, unknown>,
    { get: (t, k: string) => t[k] ?? nop },
  ) as unknown as WebAppApi;
}

class FakeSocket {
  onopen: (() => void) | null = null;
  onmessage: (() => void) | null = null;
  onclose: (() => void) | null = null;
  close = vi.fn();
}

describe("Backend web", () => {
  it("synchronise à chaque notification du WebSocket (ticket) et persiste", async () => {
    const sockets: FakeSocket[] = [];
    const app = fakeApp();
    const kv = memoryKv();
    const flush = vi.spyOn(kv, "flush");
    const b = createWebBackend(app, kv, {
      openSocket: (url) => {
        expect(url).toContain("ticket=");
        const s = new FakeSocket();
        sockets.push(s);
        return s as unknown as WebSocket;
      },
    });
    const updates = vi.fn();
    await b.onUpdate(updates);
    await b.login("", "alice", "pw", null);
    await waitFor(() => expect(sockets).toHaveLength(1));
    sockets[0]!.onmessage?.();
    await waitFor(() => expect(updates).toHaveBeenCalledWith(expect.objectContaining({ new_messages: 1 })));
    expect(flush).toHaveBeenCalled();
    await b.logout();
    expect(sockets[0]!.close).toHaveBeenCalled();
  });

  it("efface le compte local et prévient l'interface si l'appareil est révoqué", async () => {
    const app = fakeApp({
      sync: vi.fn(async () => Promise.reject({ kind: "device_revoked", message: "cet appareil a été révoqué" })),
    });
    const b = createWebBackend(app, memoryKv(), { openSocket: () => new FakeSocket() as unknown as WebSocket });
    const revoked = vi.fn();
    await b.onRevoked(revoked);
    await b.login("", "alice", "pw", null);
    await expect(b.sync()).rejects.toMatchObject({ kind: "device_revoked" });
    expect(app.wipe).toHaveBeenCalledWith("alice");
    expect(revoked).toHaveBeenCalled();
  });

  it("les passkeys sont refusées proprement dans le navigateur", async () => {
    const b = createWebBackend(fakeApp(), memoryKv());
    await expect(b.loginPasskey("", "alice", "pw")).rejects.toMatchObject({ kind: "unsupported" });
    expect((await b.securityStatus()).passkeysSupported).toBe(false);
  });
});
