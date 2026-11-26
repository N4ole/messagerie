import { useCallback, useEffect, useRef, useState, type ChangeEvent, type FormEvent, type KeyboardEvent } from "react";
import { useBackend } from "../api/context";
import { errorMessage, type Conversation, type Message, type Session } from "../api/types";
import { AttachmentView } from "../components/AttachmentView";
import { GroupDialog } from "../components/GroupDialog";
import { SafetyDialog } from "../components/SafetyDialog";
import { SettingsDialog } from "../components/SettingsDialog";
import { ThemeToggle } from "../components/ThemeToggle";
import { Markdown } from "../markdown/Markdown";

function time(ms: number): string {
  return new Date(ms).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
}

/** Durées proposées pour les messages éphémères. */
export const EPHEMERAL_CHOICES: { label: string; seconds: number | null }[] = [
  { label: "Désactivés", seconds: null },
  { label: "30 secondes", seconds: 30 },
  { label: "5 minutes", seconds: 300 },
  { label: "1 heure", seconds: 3600 },
  { label: "1 jour", seconds: 86400 },
  { label: "1 semaine", seconds: 604800 },
];

/** Lecture d'un fichier local (avec repli `FileReader` pour les environnements anciens). */
export function readFile(file: File): Promise<Uint8Array> {
  if (typeof file.arrayBuffer === "function") return file.arrayBuffer().then((b) => new Uint8Array(b));
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(new Uint8Array(r.result as ArrayBuffer));
    r.onerror = () => reject(r.error ?? new Error("lecture du fichier impossible"));
    r.readAsArrayBuffer(file);
  });
}

function remaining(expiresAt: number, now: number): string {
  const s = Math.max(0, Math.round((expiresAt - now) / 1000));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86400) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86400)} j`;
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
  const [dialog, setDialog] = useState<null | "group" | "settings" | { verify: string }>(null);
  const [newMember, setNewMember] = useState("");
  const [now, setNow] = useState(() => Date.now());
  const endRef = useRef<HTMLDivElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const currentRef = useRef<string | null>(null);
  useEffect(() => {
    currentRef.current = current;
  }, [current]);

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

  const refreshAll = useCallback(async () => {
    const cur = currentRef.current;
    if (cur) await refreshMessages(cur);
    await refreshList();
  }, [refreshList, refreshMessages]);

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
        if (cur && (report.changed_conversations.includes(cur) || report.expired > 0)) await refreshMessages(cur);
        await refreshList();
        if (report.identity_changes.length > 0) {
          setError(`La clé de sécurité a changé pour : ${report.identity_changes.join(", ")}. Vérifiez avant de poursuivre.`);
        } else if (report.rejected > 0) {
          setError(
            `${report.rejected} message(s) rejeté(s) : vérification cryptographique échouée (rejeu, signature invalide ou commit non autorisé).`,
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

  // Changement de conversation : une réponse arrivée après un nouveau changement est ignorée.
  useEffect(() => {
    if (!current) return;
    let active = true;
    backend
      .messages(current)
      .then(async (list) => {
        if (!active) return;
        setMessages(list);
        await backend.markRead(current);
        await refreshList();
      })
      .catch((e) => {
        if (active) setError(errorMessage(e));
      });
    return () => {
      active = false;
    };
  }, [backend, current, refreshList]);

  useEffect(() => {
    endRef.current?.scrollIntoView?.({ block: "end" });
  }, [messages]);

  // Décompte des messages éphémères et retrait à expiration.
  const hasEphemeral = messages.some((m) => m.expires_at_ms !== null);
  useEffect(() => {
    if (!hasEphemeral) return;
    const t = setInterval(() => {
      const n = Date.now();
      setNow(n);
      setMessages((prev) => prev.filter((m) => m.expires_at_ms === null || m.expires_at_ms > n));
    }, 1000);
    return () => clearInterval(t);
  }, [hasEphemeral]);

  async function run(action: () => Promise<unknown>) {
    setError(null);
    try {
      await action();
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  async function startConversation(e: FormEvent) {
    e.preventDefault();
    await run(async () => {
      const c = await backend.startConversation(peer.trim().toLowerCase());
      setPeer("");
      await refreshList();
      setCurrent(c.id);
    });
  }

  async function send(e?: FormEvent) {
    e?.preventDefault();
    if (!current || !draft.trim() || sending) return;
    setSending(true);
    await run(async () => {
      const m = await backend.send(current, draft);
      setDraft("");
      setMessages((prev) => [...prev, m]);
      await refreshList();
    });
    setSending(false);
  }

  async function sendFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file || !current) return;
    if (file.size > 25 * 1024 * 1024) {
      setError("Fichier trop volumineux (25 Mo maximum).");
      return;
    }
    setSending(true);
    await run(async () => {
      const data = await readFile(file);
      const m = await backend.sendFile(current, file.name, data, draft.trim() || null);
      setDraft("");
      setMessages((prev) => [...prev, m]);
      await refreshList();
    });
    setSending(false);
  }

  function onKey(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void send();
    }
  }

  async function lock() {
    try {
      await backend.lock();
    } finally {
      onLogout();
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
  const canWrite = conv?.status === "ok";

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
            <button type="button" className="ghost" onClick={() => setDialog("settings")} aria-label="Sécurité et paramètres">
              ⚙
            </button>
            <button type="button" className="ghost" onClick={() => void lock()}>
              Verrouiller
            </button>
          </div>
        </header>
        <form onSubmit={startConversation} className="new-conv" aria-label="Nouvelle conversation">
          <label className="sr-only" htmlFor="peer">
            Identifiant du correspondant
          </label>
          <input id="peer" value={peer} onChange={(e) => setPeer(e.target.value)} placeholder="Identifiant du correspondant" required />
          <button type="submit">Ouvrir</button>
        </form>
        <button type="button" className="ghost new-group" onClick={() => setDialog("group")}>
          + Nouveau groupe
        </button>
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
                <span className="peer">
                  {c.kind === "group" ? "👥 " : ""}
                  {c.title}
                  {c.verified && <span className="verified" aria-label="vérifié"> ✓</span>}
                  {c.status === "identity_changed" && <span className="warn" aria-label="clé changée"> ⚠</span>}
                </span>
                {c.unread > 0 && (
                  <span className="badge" aria-label={`${c.unread} non lu(s)`}>
                    {c.unread}
                  </span>
                )}
              </button>
            </li>
          ))}
        </ul>
        <button type="button" className="ghost logout" onClick={() => void logout()}>
          Se déconnecter
        </button>
      </aside>
      <section className="thread" aria-label={conv ? `Conversation : ${conv.title}` : "Aucune conversation"}>
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
              <div>
                <h2>{conv.title}</h2>
                {conv.kind === "group" ? (
                  <span className="hint">
                    {conv.members.join(", ")}
                    {conv.admin && ` — administrateur : ${conv.admin}`}
                  </span>
                ) : (
                  <span className="fingerprint" title="Empreinte de la clé d'identité du correspondant">
                    🔒 {conv.peer_fingerprint}
                  </span>
                )}
              </div>
              <div className="actions">
                {conv.kind === "direct" && (
                  <button type="button" className="ghost" onClick={() => setDialog({ verify: conv.peer })}>
                    {conv.verified ? "✓ Vérifié" : "Vérifier"}
                  </button>
                )}
                <label className="inline">
                  <span className="sr-only">Messages éphémères</span>
                  <select
                    aria-label="Messages éphémères"
                    value={conv.ttl_s ?? ""}
                    disabled={!canWrite}
                    onChange={(e) =>
                      void run(async () => {
                        await backend.setEphemeral(conv.id, e.target.value ? Number(e.target.value) : null);
                        await refreshList();
                      })
                    }
                  >
                    {EPHEMERAL_CHOICES.map((c) => (
                      <option key={c.label} value={c.seconds ?? ""}>
                        ⏱ {c.label}
                      </option>
                    ))}
                  </select>
                </label>
                {conv.kind === "group" && conv.status === "ok" && !conv.is_admin && (
                  <button
                    type="button"
                    className="ghost"
                    onClick={() =>
                      void run(async () => {
                        await backend.leaveGroup(conv.id);
                        await refreshList();
                      })
                    }
                  >
                    Quitter
                  </button>
                )}
              </div>
            </header>
            {conv.kind === "group" && conv.is_admin && conv.status === "ok" && (
              <div className="admin-bar">
                <form
                  className="actions-row"
                  onSubmit={(e) => {
                    e.preventDefault();
                    void run(async () => {
                      await backend.addMember(conv.id, newMember.trim().toLowerCase());
                      setNewMember("");
                      await refreshList();
                    });
                  }}
                >
                  <label className="sr-only" htmlFor="new-member">
                    Ajouter un membre
                  </label>
                  <input id="new-member" value={newMember} onChange={(e) => setNewMember(e.target.value)} placeholder="Ajouter un membre" required />
                  <button type="submit">Ajouter</button>
                </form>
                <span className="members">
                  {conv.members
                    .filter((m) => m !== session.username)
                    .map((m) => (
                      <span key={m} className="member">
                        <button
                          type="button"
                          className="ghost small"
                          aria-label={`Retirer ${m}`}
                          onClick={() =>
                            void run(async () => {
                              await backend.removeMember(conv.id, m);
                              await refreshList();
                            })
                          }
                        >
                          {m} ✕
                        </button>
                        <button
                          type="button"
                          className="ghost small"
                          aria-label={`Nommer ${m} administrateur`}
                          title="Transférer l'administration (vous ne pourrez plus gérer le groupe)"
                          onClick={() =>
                            void run(async () => {
                              if (!window.confirm(`Transférer l'administration du groupe à ${m} ? Vous ne pourrez plus gérer les membres.`)) return;
                              await backend.transferAdmin(conv.id, m);
                              await refreshList();
                            })
                          }
                        >
                          ★
                        </button>
                      </span>
                    ))}
                </span>
              </div>
            )}
            {conv.status === "identity_changed" && (
              <div role="alert" className="error banner">
                La clé de sécurité de {conv.identity_changed.join(", ")} a changé. Le contenu est masqué et l'envoi bloqué
                jusqu'à vérification.{" "}
                {conv.identity_changed.map((u) => (
                  <button key={u} type="button" onClick={() => setDialog({ verify: u })}>
                    Vérifier {u}
                  </button>
                ))}
              </div>
            )}
            {(conv.status === "removed" || conv.status === "left") && (
              <p className="hint banner">
                {conv.status === "removed" ? "Vous avez été retiré de ce groupe." : "Vous avez quitté ce groupe."}
              </p>
            )}
            <ol className="messages" aria-live="polite">
              {messages.map((m) => (
                <li key={m.id} className={m.outgoing ? "msg out" : "msg in"}>
                  {conv.kind === "group" && !m.outgoing && <span className="sender">{m.sender}</span>}
                  {m.attachment && <AttachmentView messageId={m.id} attachment={m.attachment} />}
                  {m.text && <Markdown ast={m.ast} />}
                  <time dateTime={new Date(m.sent_at_ms).toISOString()}>
                    {time(m.sent_at_ms)}
                    {m.expires_at_ms !== null && <span title="Message éphémère"> ⏱ {remaining(m.expires_at_ms, now)}</span>}
                  </time>
                </li>
              ))}
              <div ref={endRef} />
            </ol>
            <form className="composer" onSubmit={send} aria-label="Écrire un message">
              <input ref={fileRef} type="file" hidden onChange={(e) => void sendFile(e)} aria-label="Fichier à envoyer" />
              <button
                type="button"
                className="ghost"
                disabled={!canWrite || sending}
                onClick={() => fileRef.current?.click()}
                aria-label="Joindre un fichier"
                title="Joindre un fichier (les métadonnées des images sont supprimées)"
              >
                📎
              </button>
              <label className="sr-only" htmlFor="draft">
                Message (Markdown)
              </label>
              <textarea
                id="draft"
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={onKey}
                disabled={!canWrite}
                placeholder={
                  canWrite
                    ? "Message chiffré de bout en bout — Entrée pour envoyer, Maj+Entrée pour un saut de ligne"
                    : "Envoi impossible dans cette conversation"
                }
                rows={3}
              />
              <button type="submit" disabled={sending || !draft.trim() || !canWrite}>
                Envoyer
              </button>
            </form>
          </>
        ) : (
          <div className="placeholder">Sélectionnez ou ouvrez une conversation.</div>
        )}
      </section>
      {dialog === "group" && (
        <GroupDialog
          onClose={() => setDialog(null)}
          onCreated={(c) => {
            setDialog(null);
            void refreshList().then(() => setCurrent(c.id));
          }}
        />
      )}
      {dialog === "settings" && <SettingsDialog session={session} onClose={() => setDialog(null)} />}
      {dialog !== null && typeof dialog === "object" && (
        <SafetyDialog username={dialog.verify} onClose={() => setDialog(null)} onChanged={() => void refreshAll()} />
      )}
    </div>
  );
}
