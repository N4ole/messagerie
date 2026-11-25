import { useEffect, useRef, useState } from "react";
import jsQR from "jsqr";

/**
 * Lecture d'un QR code par la caméra (traitement 100 % local : jsQR décode
 * les images dans la WebView, rien n'est envoyé).
 */
export function QrScanner({ onResult }: { onResult: (payload: string) => void }) {
  const video = useRef<HTMLVideoElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  // Disponibilité de la caméra connue dès le rendu : pas d'état à mettre à jour dans l'effet.
  const supported = typeof navigator !== "undefined" && !!navigator.mediaDevices?.getUserMedia;
  const [error, setError] = useState<string | null>(
    supported ? null : "Caméra indisponible : comparez les chiffres à la place.",
  );

  useEffect(() => {
    if (!supported) return;
    let stream: MediaStream | null = null;
    let frame = 0;
    let done = false;
    const tick = () => {
      const v = video.current;
      const c = canvas.current;
      if (done || !v || !c) return;
      if (v.readyState >= 2 && v.videoWidth > 0) {
        c.width = v.videoWidth;
        c.height = v.videoHeight;
        const ctx = c.getContext("2d", { willReadFrequently: true });
        if (ctx) {
          ctx.drawImage(v, 0, 0, c.width, c.height);
          const img = ctx.getImageData(0, 0, c.width, c.height);
          const code = jsQR(img.data, img.width, img.height);
          if (code?.data) {
            done = true;
            onResult(code.data);
            return;
          }
        }
      }
      frame = requestAnimationFrame(tick);
    };
    navigator.mediaDevices
      .getUserMedia({ video: { facingMode: "environment" }, audio: false })
      .then((s) => {
        stream = s;
        if (video.current) {
          video.current.srcObject = s;
          void video.current.play();
        }
        frame = requestAnimationFrame(tick);
      })
      .catch(() => setError("Accès à la caméra refusé ou impossible : comparez les chiffres à la place."));
    return () => {
      done = true;
      cancelAnimationFrame(frame);
      stream?.getTracks().forEach((t) => t.stop());
    };
  }, [onResult, supported]);

  return (
    <div className="qr-scanner">
      {error ? (
        <p role="alert" className="error">
          {error}
        </p>
      ) : (
        <video ref={video} muted playsInline aria-label="Aperçu de la caméra" />
      )}
      <canvas ref={canvas} hidden />
    </div>
  );
}
