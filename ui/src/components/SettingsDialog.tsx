import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useBackend } from "../api/context";
import { errorMessage, type Passkey, type SecurityStatus, type Session } from "../api/types";
import { Modal } from "./Modal";

export const AUTO_LOCK_KEY = "messagerie.autoLock";

const vaultLabel: Record<string, string> = {
  "tpm+dpapi": "TPM + DPAPI (clé scellée par la puce de sécurité)",
  tpm: "TPM",
  dpapi: "DPAPI (session Windows)",
  none: "mot de passe uniquement",
};

export function SettingsDialog({ session, onClose }: { session: Session; onClose: () => void }) {
  const backend = useBackend();
  const [status, setStatus] = useState<SecurityStatus | null>(null);
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    setStatus(await backend.securityStatus());
    setPasskeys(await backend.listPasskeys().catch(() => []));
  }, [backend]);
  useEffect(() => {
    let active = true;
    Promise.all([backend.securityStatus(), backend.listPasskeys().catch(() => [])])
      .then(([s, p]) => {
        if (!active) return;
        setStatus(s);
        setPasskeys(p);
      })
      .catch((e) => {
        if (active) setError(errorMessage(e));
      });
    return () => {
      active = false;
    };
  }, [backend]);

  async function changeLock(minutes: number) {
    try {
      await backend.setAutoLock(minutes);
      try {
        window.localStorage.setItem(AUTO_LOCK_KEY, String(minutes));
      } catch {
        /* ignoré */
      }
      await refresh();
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  async function addPasskey(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setInfo("Suivez les instructions de Windows (insérez et touchez votre clé de sécurité)…");
    try {
      await backend.registerPasskey(name.trim());
      setName("");
      setInfo("Clé enregistrée. Vous pourrez l'utiliser à la place du code TOTP.");
      await refresh();
    } catch (err) {
      setInfo(null);
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function removePasskey(id: number) {
    try {
      await backend.deletePasskey(id);
      await refresh();
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  return (
    <Modal title="Sécurité" onClose={onClose}>
      <dl className="facts">
        <dt>Base locale</dt>
        <dd>{vaultLabel[session.vaultProtection] ?? session.vaultProtection}</dd>
        <dt>Captures d'écran</dt>
        <dd>{status?.captureProtection ?? session.captureProtection}</dd>
        <dt>Empreinte de votre identité</dt>
        <dd className="fingerprint">{session.fingerprint}</dd>
      </dl>
      <label>
        Verrouillage automatique après
        <select value={status?.autoLockMinutes ?? 5} onChange={(e) => void changeLock(Number(e.target.value))}>
          {[1, 2, 5, 10, 15, 30, 60].map((m) => (
            <option key={m} value={m}>
              {m} min d'inactivité
            </option>
          ))}
        </select>
      </label>
      <h3>Clés de sécurité et passkeys</h3>
      {status && !status.passkeysSupported && <p className="hint">Non disponible sur ce système (Windows requis).</p>}
      <ul className="plain">
        {passkeys.map((p) => (
          <li key={p.id} className="row">
            <span>
              🔑 {p.name}
              <span className="hint"> — ajoutée le {new Date(p.created_at * 1000).toLocaleDateString("fr-FR")}</span>
            </span>
            <button type="button" className="ghost" onClick={() => void removePasskey(p.id)} aria-label={`Supprimer ${p.name}`}>
              Supprimer
            </button>
          </li>
        ))}
        {passkeys.length === 0 && <li className="hint">Aucune clé enregistrée.</li>}
      </ul>
      <form onSubmit={addPasskey} className="actions-row">
        <label className="grow">
          Nom de la nouvelle clé
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={64} required placeholder="YubiKey bureau" />
        </label>
        <button type="submit" disabled={busy || !status?.passkeysSupported}>
          Ajouter une clé
        </button>
      </form>
      {info && <p className="hint">{info}</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
    </Modal>
  );
}
