import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import { Markdown } from "../src/markdown/Markdown";
import type { MdNode } from "../src/api/types";

describe("Markdown", () => {
  it("rend le formatage sans HTML brut", () => {
    const ast: MdNode[] = [
      { t: "paragraph", c: [{ t: "strong", c: [{ t: "text", text: "gras" }] }, { t: "text", text: " <script>alert(1)</script>" }] },
    ];
    const { container } = render(<Markdown ast={ast} />);
    expect(container.querySelector("strong")?.textContent).toBe("gras");
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain("<script>alert(1)</script>");
  });

  it("ne charge jamais d'image distante", () => {
    const ast: MdNode[] = [{ t: "paragraph", c: [{ t: "image", url: "https://tracker.example/p.gif", alt: "pixel" }] }];
    const { container } = render(<Markdown ast={ast} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain("image non chargée");
  });

  it("n'émet aucun lien cliquable", () => {
    const ast: MdNode[] = [
      { t: "paragraph", c: [{ t: "link", url: "https://example.org", c: [{ t: "text", text: "site" }] }] },
      { t: "paragraph", c: [{ t: "link", url: null, c: [{ t: "text", text: "piège" }] }] },
    ];
    const { container } = render(<Markdown ast={ast} />);
    expect(container.querySelector("a")).toBeNull();
    expect(container.textContent).toContain("(https://example.org)");
    expect(container.textContent).toContain("lien bloqué");
  });

  it("rend listes, citations et blocs de code", () => {
    const ast: MdNode[] = [
      { t: "list", ordered: true, start: 3, c: [{ t: "item", c: [{ t: "text", text: "un" }] }] },
      { t: "block_quote", c: [{ t: "paragraph", c: [{ t: "text", text: "cite" }] }] },
      { t: "code_block", lang: "rust", text: "fn main() {}" },
      { t: "heading", level: 1, c: [{ t: "text", text: "Titre" }] },
    ];
    const { container } = render(<Markdown ast={ast} />);
    expect(container.querySelector("ol")?.getAttribute("start")).toBe("3");
    expect(container.querySelector("blockquote")?.textContent).toBe("cite");
    expect(container.querySelector("pre code")?.textContent).toBe("fn main() {}");
    expect(container.querySelector("h3")?.textContent).toBe("Titre");
  });
});
