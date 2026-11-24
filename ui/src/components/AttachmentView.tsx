import { useEffect, useState } from "react";
import { useBackend } from "../api/context";
import { errorMessage, type Attachment } from "../api/types";
import { Modal } from "./Modal";

export function humanSize(n: number): string {
  if (n < 1024) return `${n} o`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} Ko`;
  return `${(n / 1024 / 1024).toFixed(1)} Mo`;
}

export function AttachmentView({ messageId, attachment }: { messageId: string; attachment: Attachment }) {
  const backend = useBackend();
  const [preview, setPreview] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => () => {
    if (preview) URL.revokeObjectURL(preview);
  }, [preview]);

  async function open() {
    try {
      const bytes = await backend.imageBytes(messageId);
      setPreview(URL.createObjectURL(new Blob([bytes], { type: attachment.mime })));
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  async function save() {
    try {
      await backend.saveAttachment(messageId);
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  return (
    <div className="attachment">
      {attachment.thumbnail_data_uri && (
        <button type="button" className="thumb" onClick={() => void open()} aria-label={`Afficher ${attachment.name}`}>
          <img src={attachment.thumbnail_data_uri} alt={attachment.name} />
        </button>
      )}
      <div className="attachment-meta">
        <span className="name">📎 {attachment.name}</span>
        <span className="hint">
          {humanSize(attachment.size)}
          {!attachment.metadata_cleaned && " — métadonnées internes non nettoyées"}
        </span>
        <button type="button" className="ghost small" onClick={() => void save()}>
          Enregistrer…
        </button>
      </div>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {preview && (
        <Modal title={attachment.name} onClose={() => setPreview(null)}>
          <img className="preview" src={preview} alt={attachment.name} />
        </Modal>
      )}
    </div>
  );
}
