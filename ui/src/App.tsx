import { useState } from "react";
import type { Session } from "./api/types";
import { Auth } from "./views/Auth";
import { Chat } from "./views/Chat";

export function App() {
  const [session, setSession] = useState<Session | null>(null);
  return session ? (
    <Chat session={session} onLogout={() => setSession(null)} />
  ) : (
    <Auth onSession={setSession} />
  );
}
