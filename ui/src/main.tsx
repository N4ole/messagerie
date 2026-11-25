import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import type { Backend } from "./api/backend";
import { BackendContext } from "./api/context";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("élément #root manquant");
const reactRoot = createRoot(root);

function render(backend: Backend) {
  reactRoot.render(
    <StrictMode>
      <BackendContext.Provider value={backend}>
        <App />
      </BackendContext.Provider>
    </StrictMode>,
  );
}

function fatal(message: string) {
  reactRoot.render(
    <main className="auth">
      <div className="auth-card">
        <h1>Messagerie</h1>
        <p role="alert" className="error">
          {message}
        </p>
      </div>
    </main>,
  );
}

// La branche inutilisée est éliminée à la compilation : le client desktop
// n'embarque pas le module WASM, le client web n'embarque pas Tauri.
if (import.meta.env.MODE === "web") {
  import("./web/start")
    .then((m) => m.startWeb())
    .then(render)
    .catch((e: unknown) => fatal(e instanceof Error ? e.message : String(e)));
} else {
  import("./api/tauri").then((m) => render(m.tauriBackend)).catch((e: unknown) => fatal(String(e)));
}
