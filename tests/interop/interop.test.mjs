// Interopérabilité desktop ↔ web, de bout en bout :
// - un serveur réel (msg-server) qui sert aussi le client web (ui/dist-web) ;
// - un client natif (même cœur Rust que l'application de bureau) ;
// - le client web (cœur Rust compilé en WASM) dans un vrai Chromium.
//
// Prérequis (voir la CI) : `pnpm build:web`, `cargo build -p msg-server
// --bin msg-server --example interop_peer`, PostgreSQL (DATABASE_URL).

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHmac, randomBytes } from "node:crypto";
import { createInterface } from "node:readline";
import { createServer } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const target = process.env.CARGO_TARGET_DIR ?? path.join(root, "target");
const BASE_DB = process.env.DATABASE_URL ?? "postgres://postgres:postgres@127.0.0.1:5432/postgres";

/** TOTP RFC 6238 (SHA-1, 6 chiffres, 30 s) pour saisir les codes du navigateur. */
function totp(base32, offset = 0) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of base32.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + offset));
  const h = createHmac("sha1", key).update(counter).digest();
  const o = h[h.length - 1] & 0xf;
  const n = (h.readUInt32BE(o) & 0x7fffffff) % 1_000_000;
  return String(n).padStart(6, "0");
}

const freePort = () =>
  new Promise((resolve) => {
    const s = createServer().listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });

async function waitHealth(url) {
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`${url}/v1/health`)).ok) return;
    } catch {
      /* pas encore prêt */
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("serveur indisponible");
}

let server, peer, browser, url, dbUrl, peerLines, setup;

/** Captures d'écran facultatives (documentation) : SCREENSHOT_DIR=… */
async function shot(page, name) {
  if (process.env.SCREENSHOT_DIR) await page.screenshot({ path: path.join(process.env.SCREENSHOT_DIR, `${name}.png`) });
}
const logs = [];

async function call(cmd) {
  peer.stdin.write(JSON.stringify(cmd) + "\n");
  const { value } = await peerLines.next();
  const r = JSON.parse(value);
  if (!r.ok) throw new Error(`pair natif : ${r.error}`);
  return r.result;
}

before(async () => {
  // Base dédiée au test.
  const db = `interop_${randomBytes(6).toString("hex")}`;
  const admin = spawn("psql", [BASE_DB, "-c", `CREATE DATABASE ${db}`], { stdio: "inherit" });
  await new Promise((r, j) => admin.on("exit", (c) => (c === 0 ? r() : j(new Error("psql")))));
  const u = new URL(BASE_DB);
  u.pathname = `/${db}`;
  dbUrl = u.toString();

  const port = await freePort();
  url = `http://127.0.0.1:${port}`;
  server = spawn(path.join(target, "debug", "msg-server"), ["serve"], {
    env: {
      ...process.env,
      DATABASE_URL: dbUrl,
      MSG_BIND: `127.0.0.1:${port}`,
      MSG_SERVER_SECRET: randomBytes(32).toString("hex"),
      MSG_WEB_DIR: path.join(root, "ui", "dist-web"),
      MSG_ARGON2_M_KIB: "1024",
      MSG_ARGON2_T: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  server.stdout.on("data", (d) => logs.push(d.toString()));
  server.stderr.on("data", (d) => logs.push(d.toString()));
  await waitHealth(url);

  peer = spawn(path.join(target, "debug", "examples", "interop_peer"), [], {
    env: { ...process.env, MSG_URL: url, DATABASE_URL: dbUrl },
    stdio: ["pipe", "pipe", "inherit"],
  });
  peerLines = createInterface({ input: peer.stdout })[Symbol.asyncIterator]();
  browser = await chromium.launch();
});

after(async () => {
  await browser?.close();
  peer?.kill();
  server?.kill();
});

test("desktop (natif) et web (WASM) échangent des messages chiffrés", async () => {
  setup = await call({ cmd: "setup" });
  const { bob_code: bobCode, password } = setup;

  // --- Bob active son compte dans le navigateur ---
  const ctx = await browser.newContext({ viewport: { width: 1100, height: 720 }, deviceScaleFactor: 2 });
  const page = await ctx.newPage();
  const cspViolations = [];
  page.on("console", (m) => {
    if (m.text().includes("Content Security Policy")) cspViolations.push(m.text());
  });
  const external = [];
  page.on("request", (r) => {
    if (!r.url().startsWith(url) && !r.url().startsWith("data:") && !r.url().startsWith("blob:")) external.push(r.url());
  });
  await page.goto(url);
  await page.getByRole("tab", { name: "Activer un compte" }).click();
  await page.getByLabel("Identifiant").fill("bob");
  await page.getByLabel("Code d'activation").fill(bobCode);
  await page.getByLabel("Nouveau mot de passe").fill(password);
  await page.getByLabel("Confirmation").fill(password);
  await page.getByRole("button", { name: "Activer" }).click();
  const secret = (await page.locator(".secret code").textContent()).trim();
  await page.getByLabel("Code TOTP").fill(totp(secret));
  await page.getByRole("button", { name: "Terminer l'activation" }).click();
  await page.getByRole("button", { name: "Sécurité et paramètres" }).waitFor({ timeout: 60_000 });

  // --- Le desktop écrit, le web lit ---
  await call({ cmd: "send", to: "bob", text: "Bonjour depuis le desktop" });
  await page.getByRole("button", { name: /alice/ }).first().click({ timeout: 30_000 });
  await page.getByText("Bonjour depuis le desktop").waitFor({ timeout: 30_000 });

  // --- Le web répond, le desktop lit ---
  await page.getByLabel("Message (Markdown)").fill("Bonjour depuis le **web**");
  await page.getByRole("button", { name: "Envoyer" }).click();
  assert.equal((await call({ cmd: "wait", text: "Bonjour depuis le **web**" })).found, true);
  await shot(page, "p3-web-conversation");

  // --- Le stockage du navigateur ne contient que du chiffré ---
  const idbLeak = await page.evaluate(async () => {
    const db = await new Promise((res, rej) => {
      const r = indexedDB.open("messagerie");
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
    const values = await new Promise((res) => {
      const r = db.transaction("kv").objectStore("kv").getAll();
      r.onsuccess = () => res(r.result);
    });
    const text = values.map((v) => new TextDecoder("latin1").decode(v)).join("\n");
    // Marqueurs longs : un nom de 3 lettres apparaît par hasard dans des
    // centaines de Kio d'octets chiffrés (faux positif). Les clés de
    // métadonnées et les textes figureraient en clair dans un instantané
    // non chiffré.
    return ["Bonjour depuis", "identity_secret", "conversations", "mls_state"].filter((n) => text.includes(n));
  });
  assert.deepEqual(idbLeak, [], "aucun clair dans IndexedDB");

  // --- Rechargement : déverrouillage par mot de passe, historique conservé ---
  await page.reload();
  await page.getByLabel("Identifiant").fill("bob");
  await page.getByLabel("Mot de passe").fill(password);
  await page.getByRole("button", { name: "Se connecter" }).click();
  await page.getByRole("button", { name: /alice/ }).first().click({ timeout: 60_000 });
  await page.getByText("Bonjour depuis le desktop").waitFor();

  // --- Aucun clair côté serveur, aucune requête tierce, CSP respectée ---
  const { leaked } = await call({
    cmd: "leaks",
    needles: ["Bonjour depuis le desktop", "Bonjour depuis le **web**"],
  });
  assert.deepEqual(leaked, []);
  assert.deepEqual(external, [], "aucune requête vers un tiers");
  assert.deepEqual(cspViolations, []);
  await ctx.close();
});

test("le navigateur devient un appareil lié d'Alice et rejoint sa conversation", async () => {
  const ctx = await browser.newContext({ viewport: { width: 1100, height: 720 }, deviceScaleFactor: 2 });
  const page = await ctx.newPage();
  await page.goto(url);
  await page.getByRole("tab", { name: "Lier cet appareil" }).click();
  await page.getByLabel("Identifiant").fill("alice");
  await page.getByLabel("Mot de passe").fill(setup.password);
  // Pas TOTP suivant : le pas courant a déjà servi (anti-rejeu).
  await page.getByLabel("Code TOTP").fill((await call({ cmd: "totp", offset: 1 })).code);
  await page.getByRole("button", { name: "Demander la liaison" }).click();
  const code = (await page.locator(".secret code").first().textContent()).trim();
  assert.match(code, /^messagerie-link:1:/);
  await shot(page, "p3-web-liaison");

  // L'appareil principal (client natif) approuve après comparaison du code.
  assert.equal((await call({ cmd: "approve", code })).approved, true);
  await page.getByRole("button", { name: "Sécurité et paramètres" }).waitFor({ timeout: 60_000 });

  // Il ajoute l'appareil lié à la conversation avec Bob, puis écrit.
  assert.equal((await call({ cmd: "reconcile" })).reconciled, 1);
  await call({ cmd: "send", to: "bob", text: "Vu aussi sur mon navigateur" });
  await page.getByRole("button", { name: /bob/ }).first().click({ timeout: 30_000 });
  await page.getByText("Vu aussi sur mon navigateur").waitFor({ timeout: 30_000 });
  await page.getByRole("button", { name: "Sécurité et paramètres" }).click();
  await page.getByRole("heading", { name: "Appareils" }).waitFor();
  await shot(page, "p3-web-appareils");
  await ctx.close();
});
