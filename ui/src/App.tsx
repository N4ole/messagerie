import { useEffect, useState } from "react";
import { useBackend } from "./api/context";
import type { Session } from "./api/types";
import { AUTO_LOCK_KEY } from "./components/SettingsDialog";
import { Auth } from "./views/Auth";
import { Chat } from "./views/Chat";

/** Intervalle minimal entre deux signaux d'activité envoyés au cœur. */
const ACTIVITY_THROTTLE_MS = 15_000;

export function App() {
  const backend = useBackend();
  const [session, setSession] = useState<Session | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let active = true;
    backend
      .onLocked(() => {
        setSession(null);
        setNotice("Session verrouillée après inactivité. Saisissez votre mot de passe pour continuer.");
      })
      .then((u) => (active ? (unlisten = u) : u()))
      .catch(() => undefined);
    return () => {
      active = false;
      unlisten?.();
    };
  }, [backend]);

  useEffect(() => {
    if (!session) return;
    try {
      const m = Number(window.localStorage.getItem(AUTO_LOCK_KEY));
      if (m > 0) void backend.setAutoLock(m).catch(() => undefined);
    } catch {
      /* ignoré */
    }
    let last = 0;
    const ping = () => {
      const n = Date.now();
      if (n - last > ACTIVITY_THROTTLE_MS) {
        last = n;
        void backend.activity().catch(() => undefined);
      }
    };
    const events = ["keydown", "pointerdown", "pointermove", "wheel"] as const;
    events.forEach((e) => window.addEventListener(e, ping, { passive: true }));
    return () => events.forEach((e) => window.removeEventListener(e, ping));
  }, [backend, session]);

  return session ? (
    <Chat session={session} onLogout={() => setSession(null)} />
  ) : (
    <Auth
      notice={notice}
      onSession={(s) => {
        setNotice(null);
        setSession(s);
      }}
    />
  );
}
