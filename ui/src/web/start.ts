import type { Backend } from "../api/backend";
import { createWebBackend } from "./backend";
import { openIndexedDbKv } from "./kv";

/** Erreur affichée quand le mode Tor strict interdit l'accès hors `.onion`. */
export class OnionRequired extends Error {}

/**
 * Démarrage du client web : vérifie le mode Tor strict, charge le module
 * WASM (servi par le même site) et le stockage IndexedDB.
 */
export async function startWeb(): Promise<Backend> {
  const resp = await fetch("/web-config.json", { cache: "no-store", credentials: "omit" });
  const cfg = (await resp.json()) as { onion_only: boolean };
  if (cfg.onion_only && !window.location.hostname.endsWith(".onion")) {
    throw new OnionRequired(
      "Ce site n'accepte que les connexions via Tor : ouvrez son adresse .onion dans Tor Browser.",
    );
  }
  const wasm = await import("msg-wasm");
  await wasm.default();
  const kv = await openIndexedDbKv();
  return createWebBackend(new wasm.WebApp(window.location.origin, kv), kv);
}
