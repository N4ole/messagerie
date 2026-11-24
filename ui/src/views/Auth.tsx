import { useState, type FormEvent } from "react";
import { useBackend } from "../api/context";
import { errorMessage, isBackendError, type Activation, type Session } from "../api/types";
import { ThemeToggle } from "../components/ThemeToggle";

const SERVER_KEY = "messagerie.server";

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

export function Auth({ onSession }: { onSession: (s: Session) => void }) {
  const [mode, setMode] = useState<"login" | "activate">("login");
  const [server, setServer] = useState(loadServer);
  return (
    <main className="auth">
      <div className="auth-card">
        <header className="auth-header">
          <h1>Messagerie</h1>
          <ThemeToggle />
        </header>
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
        <div role="tablist" className="tabs" aria-label="Mode">
          <button role="tab" aria-selected={mode === "login"} onClick={() => setMode("login")} type="button">
            Se connecter
          </button>
          <button role="tab" aria-selected={mode === "activate"} onClick={() => setMode("activate")} type="button">
            Activer un compte
          </button>
        </div>
        {mode === "login" ? (
          <LoginForm server={server.trim()} onSession={onSession} />
        ) : (
          <ActivateForm server={server.trim()} onSession={onSession} />
        )}
      </div>
    </main>
  );
}

function LoginForm({ server, onSession }: { server: string; onSession: (s: Session) => void }) {
  const backend = useBackend();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [needTotp, setNeedTotp] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const s = await backend.login(server, username.trim(), password, totp.trim() || null);
      setPassword("");
      onSession(s);
    } catch (err) {
      if (isBackendError(err) && err.kind === "totp_required") {
        setNeedTotp(true);
        setError("Session expirée : saisissez le code de votre application d'authentification.");
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
        <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
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
    </form>
  );
}

function ActivateForm({ server, onSession }: { server: string; onSession: (s: Session) => void }) {
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
      setActivation(await backend.activate(server, username.trim(), code.trim(), password));
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
      const s = await backend.enroll(server, username.trim(), password, totp.trim());
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
        <p>Scannez ce QR code avec votre application d'authentification, puis saisissez le code affiché.</p>
        <img className="qr" src={activation.qr_data_uri} alt="QR code du secret TOTP" width={200} height={200} />
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
        <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
      </label>
      <label>
        Code d'activation (fourni par l'administrateur)
        <input value={code} onChange={(e) => setCode(e.target.value)} autoComplete="off" required />
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
