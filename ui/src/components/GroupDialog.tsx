import { useState, type FormEvent } from "react";
import { useBackend } from "../api/context";
import { errorMessage, type Conversation } from "../api/types";
import { Modal } from "./Modal";

export function GroupDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (c: Conversation) => void }) {
  const backend = useBackend();
  const [name, setName] = useState("");
  const [members, setMembers] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const list = members
      .split(/[\s,;]+/)
      .map((m) => m.trim().toLowerCase())
      .filter(Boolean);
    setBusy(true);
    setError(null);
    try {
      onCreated(await backend.createGroup(name.trim(), list));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title="Nouveau groupe" onClose={onClose}>
      <form onSubmit={submit} className="stack">
        <label>
          Nom du groupe
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={255} required />
        </label>
        <label>
          Membres (identifiants séparés par des virgules ou des espaces)
          <input value={members} onChange={(e) => setMembers(e.target.value)} required />
        </label>
        <p className="hint">Vous serez l'administrateur du groupe : vous seul pourrez ajouter ou retirer des membres.</p>
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
        <button type="submit" disabled={busy}>
          {busy ? "Création…" : "Créer le groupe"}
        </button>
      </form>
    </Modal>
  );
}
