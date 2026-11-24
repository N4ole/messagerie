import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BackendContext } from "../src/api/context";
import { Auth } from "../src/views/Auth";
import { mockBackend } from "./mockBackend";

describe("Authentification", () => {
  it("demande le TOTP quand la session a expiré", async () => {
    const login = vi
      .fn()
      .mockRejectedValueOnce({ kind: "totp_required", message: "code TOTP requis" })
      .mockResolvedValueOnce({ username: "alice", deviceId: "d", fingerprint: "FP" });
    const b = mockBackend({ login });
    const onSession = vi.fn();
    render(
      <BackendContext.Provider value={b}>
        <Auth onSession={onSession} />
      </BackendContext.Provider>,
    );
    await userEvent.type(screen.getByLabelText("Serveur"), "http://127.0.0.1:8080");
    await userEvent.type(screen.getByLabelText("Identifiant"), "alice");
    await userEvent.type(screen.getByLabelText("Mot de passe"), "une phrase de passe");
    await userEvent.click(screen.getByRole("button", { name: "Se connecter" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Session expirée");
    await userEvent.type(screen.getByLabelText(/Code TOTP/), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Se connecter" }));
    expect(login).toHaveBeenLastCalledWith("http://127.0.0.1:8080", "alice", "une phrase de passe", "123456");
    expect(onSession).toHaveBeenCalledWith({ username: "alice", deviceId: "d", fingerprint: "FP" });
  });

  it("enchaîne activation puis configuration du TOTP", async () => {
    const b = mockBackend();
    const onSession = vi.fn();
    render(
      <BackendContext.Provider value={b}>
        <Auth onSession={onSession} />
      </BackendContext.Provider>,
    );
    await userEvent.type(screen.getByLabelText("Serveur"), "https://s");
    await userEvent.click(screen.getByRole("tab", { name: "Activer un compte" }));
    await userEvent.type(screen.getByLabelText("Identifiant"), "bob");
    await userEvent.type(screen.getByLabelText(/Code d'activation/), "abcd-1234");
    await userEvent.type(screen.getByLabelText(/Nouveau mot de passe/), "une phrase de passe");
    await userEvent.type(screen.getByLabelText("Confirmation"), "une phrase de passe");
    await userEvent.click(screen.getByRole("button", { name: "Activer" }));
    expect(await screen.findByAltText("QR code du secret TOTP")).toBeInTheDocument();
    expect(screen.getByText("JBSWY3DP")).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Code TOTP"), "654321");
    await userEvent.click(screen.getByRole("button", { name: "Terminer l'activation" }));
    expect(b.enroll).toHaveBeenCalledWith("https://s", "bob", "une phrase de passe", "654321");
    expect(onSession).toHaveBeenCalled();
  });

  it("refuse des mots de passe différents", async () => {
    const b = mockBackend();
    render(
      <BackendContext.Provider value={b}>
        <Auth onSession={vi.fn()} />
      </BackendContext.Provider>,
    );
    await userEvent.click(screen.getByRole("tab", { name: "Activer un compte" }));
    await userEvent.type(screen.getByLabelText("Serveur"), "https://s");
    await userEvent.type(screen.getByLabelText("Identifiant"), "bob");
    await userEvent.type(screen.getByLabelText(/Code d'activation/), "x");
    await userEvent.type(screen.getByLabelText(/Nouveau mot de passe/), "une phrase de passe");
    await userEvent.type(screen.getByLabelText("Confirmation"), "une autre phrase !!");
    await userEvent.click(screen.getByRole("button", { name: "Activer" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("ne correspondent pas");
    expect(b.activate).not.toHaveBeenCalled();
  });
});
