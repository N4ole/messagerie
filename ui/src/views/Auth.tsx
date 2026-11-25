import { useEffect, useState, type FormEvent } from "react";
import { useBackend } from "../api/context";
import {
  errorMessage,
  isBackendError,
  type Activation,
  type LinkStart,
  type Session,
} from "../api/types";
import { ThemeToggle } from "../components/ThemeToggle";

const SERVER_KEY = "messagerie.server";
const NETWORK_KEY = "messagerie.network";

interface NetworkPrefs {
  mode: "direct" | "tor";
  pins: string;
}

function loadNetwork(): NetworkPrefs {
  try {
    const v = JSON.parse(
      window.localStorage.getItem(NETWORK_KEY) ?? "null",
    ) as NetworkPrefs | null;
    if (v && (v.mode === "direct" || v.mode === "tor"))
      return { mode: v.mode, pins: String(v.pins ?? "") };
  } catch {
    /* ignoré */
  }
  return { mode: "direct", pins: "" };
}

function saveNetwork(n: NetworkPrefs) {
  try {
    window.localStorage.setItem(NETWORK_KEY, JSON.stringify(n));
  } catch {
    /* ignoré */
  }
}

/** Prépare l'itinéraire réseau avant toute requête (Tor : amorçage). */
type Prepare = () => Promise<void>;

function loadServer(): string {
  try {
    return window.localStorage.getItem(SERVER_KEY) ?? "";
  } catch {
    return "";
  }
}

function saveServer(s: string) {
  try {
    window.localStorage.setItem(SERVER_KEY, s);
  } catch {
    /* ignoré */
  }
}

export function Auth({
  onSession,
  notice = null,
}: {
  onSession: (s: Session) => void;
  notice?: string | null;
}) {
  const backend = useBackend();
  const web = backend.platform === "web";
  const [mode, setMode] = useState<"login" | "activate" | "link">("login");
  // Client web : le serveur est celui qui a servi la page (même origine).
  const [server, setServer] = useState(() =>
    web ? window.location.origin : loadServer(),
  );
  const [net, setNet] = useState<NetworkPrefs>(loadNetwork);
  const [netStatus, setNetStatus] = useState<string | null>(null);
  const prepare: Prepare = async () => {
    if (web) return;
    saveNetwork(net);
    if (net.mode === "tor")
      setNetStatus("Démarrage de Tor… (jusqu'à deux minutes la première fois)");
    const pins = net.pins
      .split(/[\s,;]+/)
      .map((p) => p.trim())
      .filter(Boolean);
    setNetStatus(await backend.configureNetwork(net.mode, pins));
  };
  return (
    <main className="auth">
      <div className="auth-card">
        <header className="auth-header">
          <h1>Messagerie</h1>
          <ThemeToggle />
        </header>
        {notice && (
          <p role="status" className="hint">
            {notice}
          </p>
        )}
        {!web && (
          <label>
            Serveur
            <input
              value={server}
              onChange={(e) => setServer(e.target.value)}
              onBlur={() => saveServer(server.trim())}
              placeholder="https://messagerie.exemple.org"
              autoComplete="url"
              required
            />
          </label>
        )}
        {!web && (
          <fieldset className="network">
            <legend>Réseau</legend>
            <label className="inline">
              <input
                type="radio"
                name="network"
                checked={net.mode === "direct"}
                onChange={() => setNet({ ...net, mode: "direct" })}
              />
              Connexion directe (HTTPS)
            </label>
            <label className="inline">
              <input
                type="radio"
                name="network"
                checked={net.mode === "tor"}
                onChange={() => setNet({ ...net, mode: "tor" })}
              />
              Tor, mode strict (aucune connexion directe)
            </label>
            <label>
              Empreinte TLS épinglée (facultative, SHA-256 de la clé publique du
              serveur)
              <input
                value={net.pins}
                onChange={(e) => setNet({ ...net, pins: e.target.value })}
                placeholder="64 caractères hexadécimaux"
                spellCheck={false}
              />
            </label>
            {netStatus && (
              <p className="hint" role="status">
                Réseau : {netStatus}
              </p>
            )}
          </fieldset>
        )}
        <div role="tablist" className="tabs" aria-label="Mode">
          <button
            role="tab"
            aria-selected={mode === "login"}
            onClick={() => setMode("login")}
            type="button"
          >
            Se connecter
          </button>
          <button
            role="tab"
            aria-selected={mode === "activate"}
            onClick={() => setMode("activate")}
            type="button"
          >
            Activer un compte
          </button>
          <button
            role="tab"
            aria-selected={mode === "link"}
            onClick={() => setMode("link")}
            type="button"
          >
            Lier cet appareil
          </button>
        </div>
        {mode === "login" && (
          <LoginForm
            server={server.trim()}
            onSession={onSession}
            prepare={prepare}
          />
        )}
        {mode === "activate" && (
          <ActivateForm
            server={server.trim()}
            onSession={onSession}
            prepare={prepare}
          />
        )}
        {mode === "link" && (
          <LinkForm
            server={server.trim()}
            onSession={onSession}
            prepare={prepare}
          />
        )}
      </div>
    </main>
  );
}

function LoginForm({
  server,
  onSession,
  prepare,
}: {
  server: string;
  onSession: (s: Session) => void;
  prepare: Prepare;
}) {
  const backend = useBackend();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [needTotp, setNeedTotp] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function withPasskey() {
    if (!username.trim() || !password) {
      setError(
        "Saisissez votre identifiant et votre mot de passe, puis utilisez votre clé de sécurité.",
      );
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await prepare();
      const s = await backend.loginPasskey(server, username.trim(), password);
      setPassword("");
      onSession(s);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await prepare();
      const s = await backend.login(
        server,
        username.trim(),
        password,
        totp.trim() || null,
      );
      setPassword("");
      onSession(s);
    } catch (err) {
      if (isBackendError(err) && err.kind === "totp_required") {
        setNeedTotp(true);
        setError(
          "Session expirée : saisissez le code de votre application d'authentification.",
        );
      } else {
        setError(errorMessage(err));
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} aria-label="Connexion">
      <label>
        Identifiant
        <input
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete="username"
          required
        />
      </label>
      <label>
        Mot de passe
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
          required
        />
      </label>
      <label>
        Code TOTP {needTotp ? "(requis)" : "(si demandé)"}
        <input
          value={totp}
          onChange={(e) => setTotp(e.target.value)}
          inputMode="numeric"
          autoComplete="one-time-code"
          pattern="[0-9]{6}"
          required={needTotp}
        />
      </label>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <button type="submit" disabled={busy}>
        {busy ? "Connexion…" : "Se connecter"}
      </button>
      {backend.platform === "desktop" && (
        <button
          type="button"
          className="ghost"
          disabled={busy}
          onClick={() => void withPasskey()}
        >
          🔑 Se connecter avec une clé de sécurité
        </button>
      )}
    </form>
  );
}

function ActivateForm({
  server,
  onSession,
  prepare,
}: {
  server: string;
  onSession: (s: Session) => void;
  prepare: Prepare;
}) {
  const backend = useBackend();
  const [username, setUsername] = useState("");
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [activation, setActivation] = useState<Activation | null>(null);
  const [totp, setTotp] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function activate(e: FormEvent) {
    e.preventDefault();
    if (password !== confirm) {
      setError("Les mots de passe ne correspondent pas.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await prepare();
      setActivation(
        await backend.activate(server, username.trim(), code.trim(), password),
      );
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function enroll(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const s = await backend.enroll(
        server,
        username.trim(),
        password,
        totp.trim(),
      );
      setPassword("");
      setConfirm("");
      onSession(s);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (activation) {
    return (
      <form onSubmit={enroll} aria-label="Configuration du TOTP">
        <p>
          Scannez ce QR code avec votre application d'authentification, puis
          saisissez le code affiché.
        </p>
        <img
          className="qr"
          src={activation.qr_data_uri}
          alt="QR code du secret TOTP"
          width={200}
          height={200}
        />
        <p className="secret">
          Ou saisissez la clé : <code>{activation.totp_secret_base32}</code>
        </p>
        <label>
          Code TOTP
          <input
            value={totp}
            onChange={(e) => setTotp(e.target.value)}
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            required
          />
        </label>
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        <button type="submit" disabled={busy}>
          {busy ? "Création des clés…" : "Terminer l'activation"}
        </button>
      </form>
    );
  }

  return (
    <form onSubmit={activate} aria-label="Activation">
      <label>
        Identifiant
        <input
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete="username"
          required
        />
      </label>
      <label>
        Code d'activation (fourni par l'administrateur)
        <input
          value={code}
          onChange={(e) => setCode(e.target.value)}
          autoComplete="off"
          required
        />
      </label>
      <label>
        Nouveau mot de passe (12 caractères minimum)
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
          minLength={12}
          required
        />
      </label>
      <label>
        Confirmation
        <input
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          autoComplete="new-password"
          minLength={12}
          required
        />
      </label>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <button type="submit" disabled={busy}>
        {busy ? "Activation…" : "Activer"}
      </button>
    </form>
  );
}

/** Intervalle de consultation de l'état d'une liaison. */
export const LINK_POLL_MS = 2000;

/**
 * Liaison de cet appareil à un compte existant : après authentification,
 * l'appareil affiche un code (et un QR code) à faire approuver depuis
 * l'appareil principal. Aucune clé privée n'est transférée.
 */
function LinkForm({
  server,
  onSession,
  prepare,
}: {
  server: string;
  onSession: (s: Session) => void;
  prepare: Prepare;
}) {
  const backend = useBackend();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [link, setLink] = useState<LinkStart | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!link) return;
    let active = true;
    const timer = setInterval(() => {
      backend
        .linkPoll()
        .then((r) => {
          if (!active) return;
          if (r.status === "linked" && r.session) {
            clearInterval(timer);
            onSession(r.session);
          } else if (r.status === "rejected" || r.status === "expired") {
            clearInterval(timer);
            setLink(null);
            setError(
              r.status === "rejected"
                ? "Liaison refusée par l'appareil principal."
                : "Demande expirée : recommencez.",
            );
          }
        })
        .catch((e) => {
          if (!active) return;
          clearInterval(timer);
          setLink(null);
          setError(errorMessage(e));
        });
    }, LINK_POLL_MS);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [backend, link, onSession]);

  async function start(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await prepare();
      setLink(
        await backend.linkStart(server, username.trim(), password, totp.trim()),
      );
      setPassword("");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (link) {
    return (
      <div aria-label="Liaison en attente">
        <p>
          Sur votre <strong>appareil principal</strong>, ouvrez Sécurité →
          Appareils, puis scannez ce QR code ou saisissez le code ci-dessous.
          Vérifiez que l'empreinte affichée là-bas est identique.
        </p>
        <img
          className="qr"
          src={link.qr_data_uri}
          alt="QR code de liaison"
          width={200}
          height={200}
        />
        <p className="secret">
          Code : <code>{link.code}</code>
        </p>
        <p className="secret">
          Empreinte : <code className="fingerprint">{link.fingerprint}</code>
        </p>
        <p className="hint" role="status">
          En attente d'approbation…
        </p>
      </div>
    );
  }

  return (
    <form onSubmit={start} aria-label="Liaison">
      <p className="hint">
        Ajoute cet appareil à un compte déjà utilisé ailleurs. Les messages
        antérieurs à la liaison ne sont pas transférés.
      </p>
      <label>
        Identifiant
        <input
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoComplete="username"
          required
        />
      </label>
      <label>
        Mot de passe
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
          required
        />
      </label>
      <label>
        Code TOTP
        <input
          value={totp}
          onChange={(e) => setTotp(e.target.value)}
          inputMode="numeric"
          autoComplete="one-time-code"
          pattern="[0-9]{6}"
          required
        />
      </label>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <button type="submit" disabled={busy}>
        {busy ? "Demande…" : "Demander la liaison"}
      </button>
    </form>
  );
}
