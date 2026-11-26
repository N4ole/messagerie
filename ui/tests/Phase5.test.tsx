import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "../src/App";
import { BackendContext } from "../src/api/context";
import { mockBackend } from "./mockBackend";

describe("Intégrité de l'application", () => {
  it("affiche l'état de la signature et l'empreinte de l'exécutable", async () => {
    const b = mockBackend();
    render(
      <BackendContext.Provider value={b}>
        <App />
      </BackendContext.Provider>,
    );
    await userEvent.type(screen.getByLabelText("Serveur"), "https://srv");
    await userEvent.type(screen.getByLabelText("Identifiant"), "alice");
    await userEvent.type(
      screen.getByLabelText("Mot de passe"),
      "motdepasse-long",
    );
    await userEvent.click(screen.getByRole("button", { name: "Se connecter" }));
    await userEvent.click(
      await screen.findByRole("button", { name: /Sécurité/ }),
    );
    expect(
      await screen.findByText(/comparez l'empreinte avec SHA256SUMS/),
    ).toBeInTheDocument();
    expect(screen.getByTestId("exe-sha256")).toHaveTextContent("ab".repeat(32));
  });
});
