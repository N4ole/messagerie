import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { BackendContext } from "./api/context";
import { tauriBackend } from "./api/tauri";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("élément #root manquant");
createRoot(root).render(
  <StrictMode>
    <BackendContext.Provider value={tauriBackend}>
      <App />
    </BackendContext.Provider>
  </StrictMode>,
);
