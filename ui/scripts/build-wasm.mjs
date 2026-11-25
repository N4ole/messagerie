// Compile le module WASM du client web (crates/msg-wasm) puis génère ses
// liaisons JavaScript dans src/wasm-pkg (fichiers générés, non versionnés).
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const ui = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const root = path.dirname(ui);
const env = { ...process.env, RUSTFLAGS: `${process.env.RUSTFLAGS ?? ""} --cfg getrandom_backend="wasm_js"`.trim() };
const run = (cmd, args) => execFileSync(cmd, args, { cwd: root, env, stdio: "inherit" });

run("cargo", ["build", "--locked", "--release", "--target", "wasm32-unknown-unknown", "-p", "msg-wasm"]);
run("wasm-bindgen", [
  "--target",
  "web",
  "--out-dir",
  path.join(ui, "src", "wasm-pkg"),
  "--out-name",
  "msg_wasm",
  path.join(root, "target", "wasm32-unknown-unknown", "release", "msg_wasm.wasm"),
]);
