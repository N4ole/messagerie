/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Aucune ressource externe : tout est empaqueté localement.
// `vite build` : interface du desktop (Tauri) ; `vite build --mode web` :
// client web (module WASM `msg-wasm`, servi par le serveur).
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  clearScreen: false,
  server: { port: 5173, strictPort: true },
  resolve: {
    // Chemin relatif à la racine du projet Vite (fichiers générés par scripts/build-wasm.mjs).
    alias: (mode === "web" ? { "msg-wasm": "/src/wasm-pkg/msg_wasm.js" } : {}) as Record<string, string>,
  },
  build: {
    outDir: mode === "web" ? "dist-web" : "dist",
    target: "es2021",
    sourcemap: false,
    // Pas d'images en ligne (data:) : la CSP n'autorise data: que pour le QR code TOTP.
    assetsInlineLimit: 0,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./tests/setup.ts"],
    globals: false,
  },
}));
