import { Fragment, type ReactNode } from "react";
import type { MdNode } from "../api/types";

/**
 * Rendu de l'AST Markdown sûr. Aucun HTML brut n'est jamais interprété
 * (React échappe tout texte) et AUCUNE ressource distante n'est chargée :
 * - les images sont affichées sous forme de texte ;
 * - les liens ne sont pas cliquables (texte + adresse visible), ce qui
 *   empêche toute ouverture involontaire et tout pistage.
 */
function render(nodes: MdNode[], keyPrefix: string): ReactNode[] {
  return nodes.map((n, i) => {
    const k = `${keyPrefix}.${i}`;
    switch (n.t) {
      case "paragraph":
        return <p key={k}>{render(n.c, k)}</p>;
      case "heading": {
        // Titres réduits à h3-h6 pour ne pas casser la hiérarchie de la page.
        const level = Math.min(6, Math.max(3, n.level + 2));
        const Tag = `h${level}` as "h3" | "h4" | "h5" | "h6";
        return <Tag key={k}>{render(n.c, k)}</Tag>;
      }
      case "block_quote":
        return <blockquote key={k}>{render(n.c, k)}</blockquote>;
      case "code_block":
        return (
          <pre key={k} data-lang={n.lang ?? undefined}>
            <code>{n.text}</code>
          </pre>
        );
      case "list":
        return n.ordered ? (
          <ol key={k} start={n.start ?? undefined}>
            {render(n.c, k)}
          </ol>
        ) : (
          <ul key={k}>{render(n.c, k)}</ul>
        );
      case "item":
        return <li key={k}>{render(n.c, k)}</li>;
      case "emphasis":
        return <em key={k}>{render(n.c, k)}</em>;
      case "strong":
        return <strong key={k}>{render(n.c, k)}</strong>;
      case "strikethrough":
        return <del key={k}>{render(n.c, k)}</del>;
      case "link":
        return (
          <span key={k} className="md-link" title={n.url ?? "lien bloqué"}>
            {render(n.c, k)}
            {n.url ? <span className="md-url"> ({n.url})</span> : <span className="md-url"> (lien bloqué)</span>}
          </span>
        );
      case "image":
        return (
          <span key={k} className="md-image" title="Image distante non chargée">
            [image non chargée : {n.alt || "sans description"} — {n.url}]
          </span>
        );
      case "code":
        return <code key={k}>{n.text}</code>;
      case "text":
        return <Fragment key={k}>{n.text}</Fragment>;
      case "soft_break":
        return <Fragment key={k}>{"\n"}</Fragment>;
      case "hard_break":
        return <br key={k} />;
      case "rule":
        return <hr key={k} />;
      default:
        return null;
    }
  });
}

export function Markdown({ ast }: { ast: MdNode[] }) {
  return <div className="md">{render(ast, "n")}</div>;
}
