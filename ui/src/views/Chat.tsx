import { useCallback, useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { useBackend } from "../api/context";
import { errorMessage, type Conversation, type Message, type Session } from "../api/types";
import { ThemeToggle } from "../components/ThemeToggle";
import { Markdown } from "../markdown/Markdown";

function time(ms: number): string {
  return new Date(ms).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
}

export function Chat({ session, onLogout }: { session: Session; onLogout: () => void }) {
  const backend = useBackend();
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [current, setCurrent] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [peer, setPeer] = useState("");
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);
  const currentRef = useRef<string | null>(null);
  currentRef.current = current;

  const refreshList = useCallback(async () => {
    setConversations(await backend.conversations());
  }, [backend]);

  const refreshMessages = useCallback(
    async (id: string) => {
      setMessages(await backend.messages(id));
      await backend.markRead(id);
    },
    [backend],
  );

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let active = true;
    (async () => {
      try {
        await backend.sync();
      } catch (e) {
        setError(errorMessage(e));
      }
      await refreshList();
      const u = await backend.onUpdate(async (report) => {
        // Marquer d'abord comme lue la conversation affichée, puis rafraîchir la liste.
        const cur = currentRef.current;
        if (cur && report.changed_conversations.includes(cur)) await refreshMessages(cur);
        await refreshList();
        if (report.rejected > 0) {
          setError(
            `${report.rejected} message(s) rejeté(s) : vérification cryptographique échouée (rejeu, signature invalide ou changement de clé).`,
          );
        }
      });
      if (active) unlisten = u;
      else u();
    })().catch((e) => setError(errorMessage(e)));
    return () => {
      active = false;
      unlisten?.();
    };
  }, [backend, refreshList, refreshMessages]);

  useEffect(() => {
    if (current) refreshMessages(current).then(refreshList).catch((e) => setError(errorMessage(e)));
    else setMessages([]);
  }, [current, refreshMessages, refreshList]);

  useEffect(() => {
    endRef.current?.scrollIntoView?.({ block: "end" });
  }, [messages]);

  async function startConversation(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const c = await backend.startConversation(peer.trim().toLowerCase());
      setPeer("");
      await refreshList();
      setCurrent(c.id);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function send(e?: FormEvent) {
    e?.preventDefault();
    if (!current || !draft.trim() || sending) return;
    setSending(true);
    setError(null);
    try {
      const m = await backend.send(current, draft);
      setDraft("");
      setMessages((prev) => [...prev, m]);
      await refreshList();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSending(false);
    }
  }

  function onKey(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void send();
    }
  }

  async function logout() {
    try {
      await backend.logout();
    } finally {
      onLogout();
    }
  }

  const conv = conversations.find((c) => c.id === current) ?? null;

  return (
    <div className="chat">
      <aside className="sidebar" aria-label="Conversations">
        <header className="me">
          <div>
            <strong>{session.username}</strong>
            <div className="fingerprint" title="Empreinte de votre clé d'identité">
              {session.fingerprint}
            </div>
          </div>
          <div className="actions">
            <ThemeToggle />
            <button type="button" className="ghost" onClick={logout}>
              Verrouiller
            </button>
          </div>
        </header>
        <form onSubmit={startConversation} className="new-conv" aria-label="Nouvelle conversation">
          <label className="sr-only" htmlFor="peer">
            Identifiant du correspondant
          </label>
          <input
            id="peer"
            value={peer}
            onChange={(e) => setPeer(e.target.value)}
            placeholder="Identifiant du correspondant"
            required
          />
          <button type="submit">Ouvrir</button>
        </form>
        <ul className="conv-list">
          {conversations.length === 0 && <li className="empty">Aucune conversation</li>}
          {conversations.map((c) => (
            <li key={c.id}>
              <button
                type="button"
                className={c.id === current ? "conv active" : "conv"}
                aria-current={c.id === current ? "true" : undefined}
                onClick={() => setCurrent(c.id)}
              >
                <span className="peer">{c.peer}</span>
                {c.unread > 0 && (
                  <span className="badge" aria-label={`${c.unread} non lu(s)`}>
                    {c.unread}
                  </span>
                )}
              </button>
            </li>
          ))}
        </ul>
      </aside>
      <section className="thread" aria-label={conv ? `Conversation avec ${conv.peer}` : "Aucune conversation"}>
        {error && (
          <p role="alert" className="error banner">
            {error}{" "}
            <button type="button" className="ghost" onClick={() => setError(null)} aria-label="Fermer l'alerte">
              ✕
            </button>
          </p>
        )}
        {conv ? (
          <>
            <header className="thread-header">
              <h2>{conv.peer}</h2>
              <span className="fingerprint" title="Empreinte de la clé d'identité du correspondant">
                🔒 {conv.peer_fingerprint}
              </span>
            </header>
            <ol className="messages" aria-live="polite">
              {messages.map((m) => (
                <li key={m.id} className={m.outgoing ? "msg out" : "msg in"}>
                  <Markdown ast={m.ast} />
                  <time dateTime={new Date(m.sent_at_ms).toISOString()}>{time(m.sent_at_ms)}</time>
                </li>
              ))}
              <div ref={endRef} />
            </ol>
            <form className="composer" onSubmit={send} aria-label="Écrire un message">
              <label className="sr-only" htmlFor="draft">
                Message (Markdown)
              </label>
              <textarea
                id="draft"
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={onKey}
                placeholder="Message chiffré de bout en bout — Entrée pour envoyer, Maj+Entrée pour un saut de ligne"
                rows={3}
              />
              <button type="submit" disabled={sending || !draft.trim()}>
                Envoyer
              </button>
            </form>
          </>
        ) : (
          <div className="placeholder">Sélectionnez ou ouvrez une conversation.</div>
        )}
      </section>
    </div>
  );
}
