import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useBackend } from "../api/context";
import { errorMessage, type Device, type LinkRequest, type Session } from "../api/types";
import { QrScanner } from "./QrScanner";

const date = (s: number) => new Date(s * 1000).toLocaleString("fr-FR");

/**
 * Appareils du compte : liste, révocation, et (sur l'appareil principal)
 * approbation des nouveaux appareils par leur code ou leur QR code.
 */
export function DevicesSection({ session }: { session: Session }) {
  const backend = useBackend();
  const [devices, setDevices] = useState<Device[]>([]);
  const [requests, setRequests] = useState<LinkRequest[]>([]);
  const [code, setCode] = useState("");
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  const load = useCallback(async () => {
    const [d, r] = await Promise.all([backend.devices(), session.primary ? backend.linkRequests() : Promise.resolve([])]);
    return { d, r };
  }, [backend, session.primary]);

  const refresh = useCallback(async () => {
    const { d, r } = await load();
    setDevices(d);
    setRequests(r);
  }, [load]);

  useEffect(() => {
    let active = true;
    load()
      .then(({ d, r }) => {
        if (!active) return;
        setDevices(d);
        setRequests(r);
      })
      .catch((e) => {
        if (active) setError(errorMessage(e));
      });
    return () => {
      active = false;
    };
  }, [load]);

  async function approve(value: string) {
    setError(null);
    setInfo(null);
    try {
      await backend.approveLink(value.trim());
      setCode("");
      setInfo("Appareil approuvé. Il sera ajouté à vos conversations lors de la prochaine synchronisation.");
      await refresh();
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    await approve(code);
  }

  async function act(f: () => Promise<void>, done: string) {
    setError(null);
    setInfo(null);
    try {
      await f();
      setInfo(done);
      await refresh();
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  return (
    <section aria-label="Appareils">
      <h3>Appareils</h3>
      <ul className="plain">
        {devices.map((d) => (
          <li key={d.device_id} className="row">
            <span>
              {d.current ? "💻 Cet appareil" : "📱 Autre appareil"}
              <span className="hint">
                {" "}
                — ajouté le {date(d.created_at)}
                {d.last_seen_at ? `, actif vers ${date(d.last_seen_at)}` : ""}
              </span>
            </span>
            {!d.current && (
              <button
                type="button"
                className="ghost"
                onClick={() =>
                  void act(
                    () => backend.revokeDevice(d.device_id),
                    "Appareil révoqué : il est retiré de vos conversations et effacera ses données à sa prochaine connexion.",
                  )
                }
              >
                Révoquer
              </button>
            )}
          </li>
        ))}
      </ul>
      {session.primary ? (
        <>
          <h4>Lier un nouvel appareil</h4>
          <p className="hint">
            Sur le nouvel appareil, choisissez « Lier cet appareil » puis comparez l'empreinte ou scannez le QR code
            affiché. L'approbation signe son certificat avec votre clé d'identité, qui ne quitte jamais cet appareil.
          </p>
          <ul className="plain">
            {requests.map((r) => (
              <li key={r.link_id} className="row">
                <span>
                  Demande en attente — empreinte <code>{r.fingerprint}</code>
                </span>
                <button
                  type="button"
                  className="ghost"
                  onClick={() => void act(() => backend.rejectLink(r.link_id), "Demande refusée.")}
                >
                  Refuser
                </button>
              </li>
            ))}
            {requests.length === 0 && <li className="hint">Aucune demande en attente.</li>}
          </ul>
          <form onSubmit={submit} className="actions-row" aria-label="Approuver un appareil">
            <label className="grow">
              Code affiché par le nouvel appareil
              <input value={code} onChange={(e) => setCode(e.target.value)} placeholder="messagerie-link:1:…" required />
            </label>
            <button type="submit">Approuver</button>
            <button type="button" className="ghost" onClick={() => setScanning((s) => !s)}>
              {scanning ? "Arrêter le scan" : "Scanner le QR code"}
            </button>
          </form>
          {scanning && (
            <QrScanner
              onResult={(payload) => {
                setScanning(false);
                void approve(payload);
              }}
            />
          )}
        </>
      ) : (
        <p className="hint">
          Appareil secondaire : les nouveaux appareils s'approuvent depuis l'appareil principal (celui qui a créé votre
          identité).
        </p>
      )}
      {info && <p className="hint">{info}</p>}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
    </section>
  );
}
