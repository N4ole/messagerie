# ADR-0003 — Tauri v2 + React/TypeScript

- **Statut** : Acceptée (validation de la Phase 0)
- **Date** : 2026-11-24

## Contexte

Il faut un `.exe` Windows léger et une interface web partageant le même code UI.

## Décision

Tauri v2 (WebView2) pour le desktop, React 18 + TypeScript + Vite pour l'UI, partagée entre `apps/desktop` et `apps/web`. Sur desktop, l'UI n'accède à aucun secret : elle appelle des commandes IPC Tauri restreintes par les *capabilities* v2. CSP stricte, pas d'updater réseau automatique (zéro télémétrie), polices embarquées.

## Conséquences

+ Binaire de quelques Mo ; installeurs MSI et NSIS natifs.
− Dépend de WebView2 (présent sur Windows 10 à jour / 11 ; bootstrapper sinon).
− WebAuthn dans WebView2 incertain → API native `webauthn.dll`.
