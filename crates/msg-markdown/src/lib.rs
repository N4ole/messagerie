//! Conversion Markdown → AST restreint.
//!
//! Garanties :
//! - le HTML brut n'est **jamais** interprété : il devient du texte littéral ;
//! - les images ne sont **jamais** chargées : elles deviennent un nœud
//!   `Image` que l'interface affiche comme texte (anti-pixels espions) ;
//! - les liens ne gardent que les schémas `http`, `https` et `mailto` ;
//! - la profondeur d'imbrication et le nombre de nœuds sont bornés.
//!
//! L'interface construit des éléments DOM à partir de cet AST sans jamais
//! utiliser `innerHTML`.
#![forbid(unsafe_code)]

use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use serde::Serialize;

/// Profondeur maximale d'imbrication ; au-delà, le contenu est aplati.
pub const MAX_DEPTH: usize = 16;
/// Nombre maximal de nœuds produits ; au-delà, le texte restant est tronqué.
pub const MAX_NODES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Node {
    Paragraph {
        c: Vec<Node>,
    },
    Heading {
        level: u8,
        c: Vec<Node>,
    },
    BlockQuote {
        c: Vec<Node>,
    },
    CodeBlock {
        lang: Option<String>,
        text: String,
    },
    List {
        ordered: bool,
        start: Option<u64>,
        c: Vec<Node>,
    },
    Item {
        c: Vec<Node>,
    },
    Emphasis {
        c: Vec<Node>,
    },
    Strong {
        c: Vec<Node>,
    },
    Strikethrough {
        c: Vec<Node>,
    },
    /// Lien : `url` est `None` si le schéma n'est pas autorisé.
    Link {
        url: Option<String>,
        c: Vec<Node>,
    },
    /// Image jamais chargée : affichée comme texte.
    Image {
        url: String,
        alt: String,
    },
    Code {
        text: String,
    },
    Text {
        text: String,
    },
    SoftBreak,
    HardBreak,
    Rule,
}

fn safe_url(url: &str) -> Option<String> {
    let lower = url.trim().to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") || lower.starts_with("mailto:") {
        Some(url.trim().to_owned())
    } else {
        None
    }
}

fn heading_level(l: HeadingLevel) -> u8 {
    match l {
        HeadingLevel::H1 => 1,
        HeadingLevel::H2 => 2,
        HeadingLevel::H3 => 3,
        HeadingLevel::H4 => 4,
        HeadingLevel::H5 => 5,
        HeadingLevel::H6 => 6,
    }
}

enum Frame {
    Root,
    Container(Node),
    /// Conteneur ignoré car trop profond : ses enfants sont aplatis dans le parent.
    Flattened,
    CodeBlock {
        lang: Option<String>,
        text: String,
    },
    Image {
        url: String,
        alt: String,
    },
}

fn children_mut(n: &mut Node) -> Option<&mut Vec<Node>> {
    match n {
        Node::Paragraph { c }
        | Node::Heading { c, .. }
        | Node::BlockQuote { c }
        | Node::List { c, .. }
        | Node::Item { c }
        | Node::Emphasis { c }
        | Node::Strong { c }
        | Node::Strikethrough { c }
        | Node::Link { c, .. } => Some(c),
        _ => None,
    }
}

struct Builder {
    root: Vec<Node>,
    stack: Vec<Frame>,
    nodes: usize,
}

impl Builder {
    fn depth(&self) -> usize {
        self.stack.iter().filter(|f| matches!(f, Frame::Container(_))).count()
    }

    fn push_node(&mut self, n: Node) {
        if self.nodes >= MAX_NODES {
            return;
        }
        self.nodes += 1;
        for f in self.stack.iter_mut().rev() {
            match f {
                Frame::Container(c) => {
                    if let Some(ch) = children_mut(c) {
                        ch.push(n);
                    }
                    return;
                }
                Frame::Flattened => continue,
                Frame::Root => break,
                Frame::CodeBlock { .. } | Frame::Image { .. } => return,
            }
        }
        self.root.push(n);
    }

    fn push_text(&mut self, text: &str) {
        match self.stack.last_mut() {
            Some(Frame::CodeBlock { text: t, .. }) => t.push_str(text),
            Some(Frame::Image { alt, .. }) => alt.push_str(text),
            _ => self.push_node(Node::Text { text: text.to_owned() }),
        }
    }

    fn open(&mut self, n: Node) {
        if self.depth() >= MAX_DEPTH {
            self.stack.push(Frame::Flattened);
        } else {
            self.stack.push(Frame::Container(n));
        }
    }

    fn close(&mut self) {
        match self.stack.pop() {
            Some(Frame::Container(n)) => self.push_node(n),
            Some(Frame::CodeBlock { lang, text }) => self.push_node(Node::CodeBlock { lang, text }),
            Some(Frame::Image { url, alt }) => self.push_node(Node::Image { url, alt }),
            Some(Frame::Flattened) | Some(Frame::Root) | None => {}
        }
    }
}

/// Analyse un texte Markdown en AST sûr.
pub fn parse(input: &str) -> Vec<Node> {
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    let mut b = Builder { root: Vec::new(), stack: vec![Frame::Root], nodes: 0 };
    for ev in Parser::new_ext(input, opts) {
        match ev {
            Event::Start(tag) => match tag {
                Tag::Paragraph => b.open(Node::Paragraph { c: vec![] }),
                Tag::Heading { level, .. } => b.open(Node::Heading { level: heading_level(level), c: vec![] }),
                Tag::BlockQuote(_) => b.open(Node::BlockQuote { c: vec![] }),
                Tag::CodeBlock(kind) => {
                    let lang = match kind {
                        CodeBlockKind::Fenced(l) if !l.is_empty() => Some(
                            l.chars()
                                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '+')
                                .take(32)
                                .collect(),
                        ),
                        _ => None,
                    };
                    b.stack.push(Frame::CodeBlock { lang, text: String::new() });
                }
                Tag::List(start) => b.open(Node::List { ordered: start.is_some(), start, c: vec![] }),
                Tag::Item => b.open(Node::Item { c: vec![] }),
                Tag::Emphasis => b.open(Node::Emphasis { c: vec![] }),
                Tag::Strong => b.open(Node::Strong { c: vec![] }),
                Tag::Strikethrough => b.open(Node::Strikethrough { c: vec![] }),
                Tag::Link { dest_url, .. } => b.open(Node::Link { url: safe_url(&dest_url), c: vec![] }),
                Tag::Image { dest_url, .. } => {
                    b.stack.push(Frame::Image { url: dest_url.to_string(), alt: String::new() })
                }
                // Balises HTML, tableaux, notes, etc. : contenu traité comme texte.
                _ => b.stack.push(Frame::Flattened),
            },
            Event::End(TagEnd::HtmlBlock) => b.close(),
            Event::End(_) => b.close(),
            Event::Text(t) => b.push_text(&t),
            Event::Code(t) => b.push_node(Node::Code { text: t.to_string() }),
            // Le HTML devient du texte littéral (jamais interprété).
            Event::Html(t) | Event::InlineHtml(t) => b.push_text(&t),
            Event::SoftBreak => b.push_node(Node::SoftBreak),
            Event::HardBreak => b.push_node(Node::HardBreak),
            Event::Rule => b.push_node(Node::Rule),
            _ => {}
        }
    }
    b.root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(s: &str) -> String {
        serde_json::to_string(&parse(s)).unwrap()
    }

    #[test]
    fn basic_formatting() {
        let ast = parse("**gras** et *italique* `code`");
        assert_eq!(
            ast,
            vec![Node::Paragraph {
                c: vec![
                    Node::Strong { c: vec![Node::Text { text: "gras".into() }] },
                    Node::Text { text: " et ".into() },
                    Node::Emphasis { c: vec![Node::Text { text: "italique".into() }] },
                    Node::Text { text: " ".into() },
                    Node::Code { text: "code".into() },
                ]
            }]
        );
    }

    #[test]
    fn raw_html_is_text() {
        let j = json("<script>alert(1)</script>\n\nsalut <img src=x onerror=alert(1)>");
        assert!(j.contains("\\u003cscript\\u003e") || j.contains("<script>"));
        // Aucun type de nœud HTML n'existe : tout est `text`.
        let ast = parse("<b>x</b>");
        fn no_html(n: &[Node]) -> bool {
            n.iter().all(|n| match n {
                Node::Text { .. } | Node::SoftBreak | Node::HardBreak => true,
                Node::Paragraph { c } => no_html(c),
                _ => false,
            })
        }
        assert!(no_html(&ast));
    }

    #[test]
    fn images_are_never_loaded() {
        let ast = parse("![pixel](https://tracker.example/p.gif)");
        assert_eq!(
            ast,
            vec![Node::Paragraph {
                c: vec![Node::Image { url: "https://tracker.example/p.gif".into(), alt: "pixel".into() }]
            }]
        );
    }

    #[test]
    fn dangerous_link_schemes_are_dropped() {
        for bad in
            ["javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,x", "file:///etc/passwd", "vbscript:x"]
        {
            let ast = parse(&format!("[clic]({bad})"));
            match &ast[0] {
                Node::Paragraph { c } => assert!(matches!(&c[0], Node::Link { url: None, .. }), "{bad}"),
                other => panic!("{other:?}"),
            }
        }
        let ast = parse("[ok](https://example.org)");
        match &ast[0] {
            Node::Paragraph { c } => {
                assert!(matches!(&c[0], Node::Link { url: Some(u), .. } if u == "https://example.org"))
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn deep_nesting_is_bounded() {
        let input = ">".repeat(10_000) + " fond";
        let ast = parse(&input);
        fn depth(n: &[Node]) -> usize {
            n.iter()
                .map(|n| match n {
                    Node::BlockQuote { c } | Node::Paragraph { c } => 1 + depth(c),
                    _ => 1,
                })
                .max()
                .unwrap_or(0)
        }
        assert!(depth(&ast) <= MAX_DEPTH + 1);
        assert!(json(&input).contains("fond"));
    }

    #[test]
    fn code_block_language_is_sanitized() {
        let ast = parse("```rust\"><x\nfn main() {}\n```");
        match &ast[0] {
            Node::CodeBlock { lang, text } => {
                assert_eq!(lang.as_deref(), Some("rustx"));
                assert_eq!(text, "fn main() {}\n");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn node_count_is_bounded() {
        let input = "*a* ".repeat(MAX_NODES * 2);
        let ast = parse(&input);
        fn count(n: &[Node]) -> usize {
            n.iter()
                .map(|n| {
                    1 + match n {
                        Node::Paragraph { c } | Node::Emphasis { c } => count(c),
                        _ => 0,
                    }
                })
                .sum()
        }
        assert!(count(&ast) <= MAX_NODES);
    }
}
