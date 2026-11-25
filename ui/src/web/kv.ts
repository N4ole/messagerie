/**
 * Stockage clé-valeur du client web. Le module WASM n'y écrit que des
 * octets **déjà chiffrés** (coffre Argon2id, instantané chiffré de la base).
 *
 * L'interface est synchrone (exigence du cœur Rust) : les données sont
 * chargées en mémoire à l'ouverture, puis chaque écriture est répercutée
 * dans IndexedDB dans l'ordre (écriture différée, `flush` pour attendre).
 */
export interface SyncKv {
  get(key: string): Uint8Array | undefined;
  set(key: string, value: Uint8Array): void;
  delete(key: string): void;
  flush(): Promise<void>;
}

/** Variante en mémoire (tests). */
export function memoryKv(): SyncKv {
  const m = new Map<string, Uint8Array>();
  return {
    get: (k) => m.get(k),
    set: (k, v) => void m.set(k, v.slice()),
    delete: (k) => void m.delete(k),
    flush: async () => {},
  };
}

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

const STORE = "kv";

export async function openIndexedDbKv(name = "messagerie"): Promise<SyncKv> {
  const open = indexedDB.open(name, 1);
  open.onupgradeneeded = () => open.result.createObjectStore(STORE);
  const db = await req(open);
  const read = db.transaction(STORE, "readonly").objectStore(STORE);
  const [keys, values] = await Promise.all([req(read.getAllKeys()), req(read.getAll())]);
  const m = new Map<string, Uint8Array>();
  keys.forEach((k, i) => {
    const v = values[i];
    if (typeof k === "string" && v instanceof Uint8Array) m.set(k, v);
  });
  let queue: Promise<void> = Promise.resolve();
  const write = (op: (s: IDBObjectStore) => IDBRequest) => {
    queue = queue
      .then(() => req(op(db.transaction(STORE, "readwrite").objectStore(STORE))).then(() => undefined))
      .catch((e) => console.error("IndexedDB", e));
  };
  return {
    get: (k) => m.get(k),
    set: (k, v) => {
      const copy = v.slice();
      m.set(k, copy);
      write((s) => s.put(copy, k));
    },
    delete: (k) => {
      m.delete(k);
      write((s) => s.delete(k));
    },
    flush: () => queue,
  };
}
