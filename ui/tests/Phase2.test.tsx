import { describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "../src/App";
import { BackendContext } from "../src/api/context";
import { Chat } from "../src/views/Chat";
import { SafetyDialog } from "../src/components/SafetyDialog";
import { Auth } from "../src/views/Auth";
import { conversation, message, mockBackend, report, session } from "./mockBackend";

function renderChat(b = mockBackend()) {
  render(
    <BackendContext.Provider value={b}>
      <Chat session={session} onLogout={vi.fn()} />
    </BackendContext.Provider>,
  );
  return b;
}

describe("Groupes", () => {
  it("crée un groupe depuis la boîte de dialogue", async () => {
    const b = renderChat();
    await userEvent.click(screen.getByRole("button", { name: "+ Nouveau groupe" }));
    const dialog = screen.getByRole("dialog", { name: "Nouveau groupe" });
    await userEvent.type(within(dialog).getByLabelText("Nom du groupe"), "Équipe");
    await userEvent.type(within(dialog).getByLabelText(/Membres/), "Bob, carol dave");
    await userEvent.click(within(dialog).getByRole("button", { name: "Créer le groupe" }));
    await waitFor(() => expect(b.createGroup).toHaveBeenCalledWith("Équipe", ["bob", "carol", "dave"]));
  });

  it("l'administrateur ajoute et retire des membres", async () => {
    const g = conversation({ id: "gg", kind: "group", title: "Équipe", members: ["alice", "bob", "carol"] });
    const b = renderChat(mockBackend({ conversations: vi.fn(async () => [g]) }));
    await userEvent.click(await screen.findByRole("button", { name: /Équipe/ }));
    await userEvent.type(screen.getByLabelText("Ajouter un membre"), "dave");
    await userEvent.click(screen.getByRole("button", { name: "Ajouter" }));
    await waitFor(() => expect(b.addMember).toHaveBeenCalledWith("gg", "dave"));
    await userEvent.click(screen.getByRole("button", { name: "Retirer bob" }));
    await waitFor(() => expect(b.removeMember).toHaveBeenCalledWith("gg", "bob"));
    expect(screen.queryByRole("button", { name: "Quitter" })).toBeNull();
  });

  it("un membre peut quitter mais pas administrer", async () => {
    const g = conversation({ id: "gg", kind: "group", title: "Équipe", admin: "bob", is_admin: false });
    const b = renderChat(mockBackend({ conversations: vi.fn(async () => [g]) }));
    await userEvent.click(await screen.findByRole("button", { name: /Équipe/ }));
    expect(screen.queryByLabelText("Ajouter un membre")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "Quitter" }));
    await waitFor(() => expect(b.leaveGroup).toHaveBeenCalledWith("gg"));
  });
});

describe("Changement de clé et vérification", () => {
  it("masque la conversation et bloque l'envoi tant que la clé n'est pas vérifiée", async () => {
    const c = conversation({ status: "identity_changed", identity_changed: ["bob"] });
    renderChat(mockBackend({ conversations: vi.fn(async () => [c]) }));
    await userEvent.click(await screen.findByRole("button", { name: /bob/ }));
    expect(await screen.findByText(/clé de sécurité de bob a changé/)).toBeInTheDocument();
    expect(screen.getByLabelText("Message (Markdown)")).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Vérifier bob" }));
    expect(await screen.findByRole("dialog", { name: "Vérifier bob" })).toBeInTheDocument();
  });

  it("vérifie par comparaison des chiffres et signale une discordance", async () => {
    const verify = vi.fn().mockResolvedValueOnce(false).mockResolvedValueOnce(true);
    const b = mockBackend({ verifySafetyNumber: verify });
    const onChanged = vi.fn();
    render(
      <BackendContext.Provider value={b}>
        <SafetyDialog username="bob" onClose={vi.fn()} onChanged={onChanged} />
      </BackendContext.Provider>,
    );
    expect(await screen.findByAltText("QR code du numéro de sécurité")).toBeInTheDocument();
    const input = screen.getByLabelText(/Ou saisissez les chiffres/);
    await userEvent.type(input, "9".repeat(60));
    await userEvent.click(screen.getByRole("button", { name: "Comparer" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("ne correspondent PAS");
    expect(onChanged).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Les chiffres correspondent" }));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    expect(verify).toHaveBeenLastCalledWith("bob", null);
  });

  it("alerte quand le cœur signale un changement de clé", async () => {
    const b = renderChat();
    await waitFor(() => expect(b.onUpdate).toHaveBeenCalled());
    await act(async () => b.emit(report({ processed: 1, identity_changes: ["bob"] })));
    expect(await screen.findByRole("alert")).toHaveTextContent("La clé de sécurité a changé pour : bob");
  });
});

describe("Pièces jointes et éphémères", () => {
  it("affiche une miniature locale, jamais une ressource distante, et signale les métadonnées non nettoyées", async () => {
    const msgs = [
      message({
        id: "p",
        outgoing: false,
        sender: "bob",
        kind: "attachment",
        text: "",
        ast: [],
        attachment: { name: "photo.jpg", mime: "image/jpeg", size: 2048, metadata_cleaned: true, thumbnail_data_uri: "data:image/jpeg;base64,AA==" },
      }),
      message({
        id: "d",
        outgoing: false,
        sender: "bob",
        kind: "attachment",
        text: "",
        ast: [],
        attachment: { name: "rapport.pdf", mime: "application/pdf", size: 10, metadata_cleaned: false, thumbnail_data_uri: null },
      }),
    ];
    const b = renderChat(mockBackend({ messages: vi.fn(async () => msgs) }));
    await userEvent.click(await screen.findByRole("button", { name: /bob/ }));
    const img = await screen.findByAltText("photo.jpg");
    expect(img.getAttribute("src")).toMatch(/^data:image\/jpeg;base64,/);
    document.querySelectorAll("img").forEach((i) => expect(i.getAttribute("src") ?? "").not.toMatch(/^https?:/));
    expect(screen.getByText(/métadonnées internes non nettoyées/)).toBeInTheDocument();
    await userEvent.click(screen.getAllByRole("button", { name: "Enregistrer…" })[1]!);
    await waitFor(() => expect(b.saveAttachment).toHaveBeenCalledWith("d"));
  });

  it("envoie un fichier choisi", async () => {
    const b = renderChat();
    await userEvent.click(await screen.findByRole("button", { name: /bob/ }));
    const file = new File([new Uint8Array([1, 2, 3])], "notes.pdf", { type: "application/pdf" });
    await userEvent.upload(screen.getByLabelText("Fichier à envoyer"), file);
    await waitFor(() => expect(b.sendFile).toHaveBeenCalled());
    const [id, name, data] = (b.sendFile as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect([id, name, Array.from(data as Uint8Array)]).toEqual(["aa", "notes.pdf", [1, 2, 3]]);
  });

  it("règle la durée des messages éphémères", async () => {
    const b = renderChat();
    await userEvent.click(await screen.findByRole("button", { name: /bob/ }));
    await userEvent.selectOptions(screen.getByLabelText("Messages éphémères"), "300");
    await waitFor(() => expect(b.setEphemeral).toHaveBeenCalledWith("aa", 300));
  });
});

describe("Verrouillage et clé de sécurité", () => {
  it("revient à l'écran de connexion lors du verrouillage automatique", async () => {
    const b = mockBackend();
    render(
      <BackendContext.Provider value={b}>
        <App />
      </BackendContext.Provider>,
    );
    await userEvent.type(screen.getByLabelText("Serveur"), "https://s");
    await userEvent.type(screen.getByLabelText("Identifiant"), "alice");
    await userEvent.type(screen.getByLabelText("Mot de passe"), "une phrase de passe");
    await userEvent.click(screen.getByRole("button", { name: "Se connecter" }));
    expect(await screen.findByRole("button", { name: "Verrouiller" })).toBeInTheDocument();
    await act(async () => b.lockNow());
    expect(await screen.findByText(/Session verrouillée après inactivité/)).toBeInTheDocument();
  });

  it("se connecte avec une clé de sécurité", async () => {
    const b = mockBackend();
    const onSession = vi.fn();
    render(
      <BackendContext.Provider value={b}>
        <Auth onSession={onSession} />
      </BackendContext.Provider>,
    );
    await userEvent.type(screen.getByLabelText("Serveur"), "https://s");
    await userEvent.type(screen.getByLabelText("Identifiant"), "alice");
    await userEvent.type(screen.getByLabelText("Mot de passe"), "une phrase de passe");
    await userEvent.click(screen.getByRole("button", { name: /clé de sécurité/ }));
    await waitFor(() => expect(b.loginPasskey).toHaveBeenCalledWith("https://s", "alice", "une phrase de passe"));
    expect(onSession).toHaveBeenCalled();
  });
});
