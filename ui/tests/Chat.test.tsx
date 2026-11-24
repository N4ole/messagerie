import { describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BackendContext } from "../src/api/context";
import { Chat } from "../src/views/Chat";
import { mockBackend, report, session } from "./mockBackend";


describe("Conversation", () => {
  it("ouvre une conversation et envoie un message avec Entrée", async () => {
    const b = mockBackend();
    render(
      <BackendContext.Provider value={b}>
        <Chat session={session} onLogout={vi.fn()} />
      </BackendContext.Provider>,
    );
    await userEvent.click(await screen.findByRole("button", { name: "bob" }));
    const box = await screen.findByLabelText("Message (Markdown)");
    await userEvent.type(box, "salut{Enter}");
    await waitFor(() => expect(b.send).toHaveBeenCalledWith("aa", "salut"));
    expect(await screen.findByText("salut")).toBeInTheDocument();
    expect(box).toHaveValue("");
  });

  it("Maj+Entrée insère un saut de ligne sans envoyer", async () => {
    const b = mockBackend();
    render(
      <BackendContext.Provider value={b}>
        <Chat session={session} onLogout={vi.fn()} />
      </BackendContext.Provider>,
    );
    await userEvent.click(await screen.findByRole("button", { name: "bob" }));
    const box = await screen.findByLabelText("Message (Markdown)");
    await userEvent.type(box, "a{Shift>}{Enter}{/Shift}b");
    expect(b.send).not.toHaveBeenCalled();
    expect(box).toHaveValue("a\nb");
  });

  it("signale les messages rejetés par la vérification cryptographique", async () => {
    const b = mockBackend();
    render(
      <BackendContext.Provider value={b}>
        <Chat session={session} onLogout={vi.fn()} />
      </BackendContext.Provider>,
    );
    await waitFor(() => expect(b.onUpdate).toHaveBeenCalled());
    await act(async () => b.emit(report({ processed: 1, rejected: 1 })));
    expect(await screen.findByRole("alert")).toHaveTextContent("rejeté");
  });

  it("verrouille la session", async () => {
    const b = mockBackend();
    const onLogout = vi.fn();
    render(
      <BackendContext.Provider value={b}>
        <Chat session={session} onLogout={onLogout} />
      </BackendContext.Provider>,
    );
    await userEvent.click(screen.getByRole("button", { name: "Verrouiller" }));
    await waitFor(() => expect(onLogout).toHaveBeenCalled());
    expect(b.lock).toHaveBeenCalled();
    expect(b.logout).not.toHaveBeenCalled();
  });
});

describe("Mises à jour poussées", () => {
  it("marque lue la conversation affichée avant de rafraîchir la liste", async () => {
    const order: string[] = [];
    const b = mockBackend();
    const markRead = b.markRead as ReturnType<typeof vi.fn>;
    const conversations = b.conversations as ReturnType<typeof vi.fn>;
    markRead.mockImplementation(async () => {
      order.push("markRead");
    });
    render(
      <BackendContext.Provider value={b}>
        <Chat session={session} onLogout={vi.fn()} />
      </BackendContext.Provider>,
    );
    await userEvent.click(await screen.findByRole("button", { name: "bob" }));
    await waitFor(() => expect(markRead).toHaveBeenCalled());
    order.length = 0;
    conversations.mockImplementation(async () => {
      order.push("conversations");
      return [];
    });
    await act(async () => b.emit(report({ processed: 1, new_messages: 1, changed_conversations: ["aa"] })));
    expect(order).toEqual(["markRead", "conversations"]);
  });
});
