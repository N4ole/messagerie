#!/bin/sh
# Construction reproductible du serveur et du module WebAssembly.
# Deux constructions du même commit — dans des répertoires, avec des
# horodatages et des utilisateurs différents — doivent produire des
# fichiers identiques octet pour octet.
#
#   sh scripts/reproducible-build.sh build <sources> <sortie>   # une construction
#   sh scripts/reproducible-build.sh check                      # deux constructions + comparaison
#
# Leviers : chaîne Rust épinglée (rust-toolchain.toml), dépendances
# verrouillées (--locked), chemins absolus remplacés (--remap-path-prefix),
# SOURCE_DATE_EPOCH = date du commit, profil release déterministe
# (lto, codegen-units = 1, strip).
set -eu

build() {
  src=$(cd "$1" && pwd); out=$2
  mkdir -p "$out"; out=$(cd "$out" && pwd)
  cargo_home=${CARGO_HOME:-$HOME/.cargo}
  export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$src" log -1 --format=%ct 2>/dev/null || echo 0)}"
  remap="--remap-path-prefix=$src=/build --remap-path-prefix=$cargo_home=/cargo"
  if [ -n "${RUSTUP_HOME:-}" ]; then remap="$remap --remap-path-prefix=$RUSTUP_HOME=/rustup"; fi
  remap="$remap --remap-path-prefix=$HOME/.rustup=/rustup"
  cd "$src"
  RUSTFLAGS="$remap" CARGO_TARGET_DIR="$src/target-repro" \
    cargo build --release --locked -p msg-server
  RUSTFLAGS="$remap --cfg getrandom_backend=\"wasm_js\"" CARGO_TARGET_DIR="$src/target-repro" \
    cargo build --release --locked --target wasm32-unknown-unknown -p msg-wasm
  cp target-repro/release/msg-server "$out/msg-server"
  cp target-repro/wasm32-unknown-unknown/release/msg_wasm.wasm "$out/msg_wasm.wasm"
  (cd "$out" && sha256sum msg-server msg_wasm.wasm > SHA256SUMS)
  cat "$out/SHA256SUMS"
}

check() {
  root=$(git rev-parse --show-toplevel)
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  for n in premiere seconde-construction; do
    mkdir -p "$work/$n/src"
    git -C "$root" archive HEAD | tar -x -C "$work/$n/src"
  done
  # Horodatages de fichiers différents entre les deux copies.
  find "$work/seconde-construction/src" -exec touch -d "2001-01-01" {} +
  SOURCE_DATE_EPOCH=$(git -C "$root" log -1 --format=%ct)
  export SOURCE_DATE_EPOCH
  build "$work/premiere/src" "$work/premiere/out" > /dev/null
  build "$work/seconde-construction/src" "$work/seconde-construction/out" > /dev/null
  if diff "$work/premiere/out/SHA256SUMS" "$work/seconde-construction/out/SHA256SUMS"; then
    echo "constructions identiques :"
    cat "$work/premiere/out/SHA256SUMS"
  else
    echo "ÉCHEC : constructions différentes" >&2
    exit 1
  fi
}

case "${1:-}" in
  build) build "$2" "$3" ;;
  check) check ;;
  *) echo "usage : $0 build <sources> <sortie> | check" >&2; exit 2 ;;
esac
