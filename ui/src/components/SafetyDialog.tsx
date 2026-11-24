import { useCallback, useEffect, useState } from "react";
import { useBackend } from "../api/context";
import { errorMessage, type SafetyNumber } from "../api/types";
import { Modal } from "./Modal";
import { QrScanner } from "./QrScanner";

/**
 * Vérification d'un correspondant : QR code à scanner mutuellement, ou
 * comparaison des 60 chiffres (de vive voix, en personne).
 */
export function SafetyDialog({ username, onClose, onChanged }: { username: string; onClose: () => void; onChanged: () => void }) {
  const backend = useBackend();
  const [sn, setSn] = useState<SafetyNumber | null>(null);
  const [scanning, setScanning] = useState(false);
  const [typed, setTyped] = useState("");
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);

  const load = useCallback(() => {
    backend
      .safetyNumber(username)
      .then(setSn)
      .catch((e) => setResult({ ok: false, text: errorMessage(e) }));
  }, [backend, username]);
  useEffect(load, [load]);

  async function verify(scanned: string | null) {
    setScanning(false);
    try {
      const ok = await backend.verifySafetyNumber(username, scanned);
      setResult(
        ok
          ? { ok: true, text: `${username} est vérifié.` }
          : { ok: false, text: "Les numéros ne correspondent PAS. Ne poursuivez pas la conversation : la communication est peut-être interceptée." },
      );
      if (ok) {
        onChanged();
        load();
      }
    } catch (e) {
      setResult({ ok: false, text: errorMessage(e) });
    }
  }

  async function acceptWithoutVerifying() {
    try {
      await backend.acceptIdentityChange(username);
      onChanged();
      onClose();
    } catch (e) {
      setResult({ ok: false, text: errorMessage(e) });
    }
  }

  return (
    <Modal title={`Vérifier ${username}`} onClose={onClose}>
      {sn?.identity_changed && (
        <p role="alert" className="error">
          La clé de sécurité de {username} a changé. Cela arrive après une réinstallation ou une réinitialisation de son
          compte, mais peut aussi signaler une interception. Vérifiez avant d'accepter.
        </p>
      )}
      {sn && (
        <div className="safety">
          <p>
            Scannez mutuellement vos QR codes, ou comparez ces chiffres avec {username} en personne ou de vive voix.
            {sn.verified && <strong className="verified"> ✓ Vérifié</strong>}
          </p>
          <img className="qr" src={sn.qr_data_uri} alt="QR code du numéro de sécurité" width={200} height={200} />
          <p className="safety-number" aria-label="Numéro de sécurité">
            {sn.number}
          </p>
          {scanning ? (
            <QrScanner onResult={(p) => void verify(p)} />
          ) : (
            <div className="actions-row">
              <button type="button" onClick={() => setScanning(true)}>
                Scanner son QR code
              </button>
              <button type="button" className="ghost" onClick={() => void verify(null)}>
                Les chiffres correspondent
              </button>
            </div>
          )}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void verify(typed);
            }}
            className="actions-row"
          >
            <label className="grow">
              Ou saisissez les chiffres lus par {username}
              <input value={typed} onChange={(e) => setTyped(e.target.value)} inputMode="numeric" />
            </label>
            <button type="submit" disabled={typed.replace(/\D/g, "").length !== 60}>
              Comparer
            </button>
          </form>
          {sn.identity_changed && (
            <button type="button" className="ghost danger" onClick={() => void acceptWithoutVerifying()}>
              Accepter la nouvelle clé sans vérifier
            </button>
          )}
        </div>
      )}
      {result && (
        <p role="alert" className={result.ok ? "success" : "error"}>
          {result.text}
        </p>
      )}
    </Modal>
  );
}
