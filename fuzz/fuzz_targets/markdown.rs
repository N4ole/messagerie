//! Markdown reçu d'un correspondant → arbre restreint : ne doit jamais
//! paniquer ; tout lien conservé utilise un schéma autorisé ; la taille de
//! l'arbre reste bornée.
#![no_main]
use libfuzzer_sys::fuzz_target;
use msg_markdown::Node;

fn walk(nodes: &[Node], count: &mut usize) {
    for n in nodes {
        *count += 1;
        match n {
            Node::Link { url, c } => {
                if let Some(u) = url {
                    let l = u.to_ascii_lowercase();
                    assert!(
                        l.starts_with("https://") || l.starts_with("http://") || l.starts_with("mailto:"),
                        "schéma de lien non autorisé : {u:?}"
                    );
                }
                walk(c, count);
            }
            Node::Paragraph { c }
            | Node::Heading { c, .. }
            | Node::BlockQuote { c }
            | Node::List { c, .. }
            | Node::Item { c }
            | Node::Emphasis { c }
            | Node::Strong { c }
            | Node::Strikethrough { c } => walk(c, count),
            _ => {}
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let tree = msg_markdown::parse(text);
        let mut count = 0;
        walk(&tree, &mut count);
        assert!(count <= msg_markdown::MAX_NODES + 1, "arbre non borné : {count} nœuds");
    }
});
