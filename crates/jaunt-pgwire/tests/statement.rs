mod support;

use jaunt_pgwire::{Excerpt, FrontendMessage, StatementKind};
use support::*;

#[test]
fn excerpts_report_truncation() {
    let cases: [(&[u8], usize, &str, bool, usize); 8] = [
        (b"SELECT 1", 100, "SELECT 1", false, 0),
        (b"SELECT 1", 8, "SELECT 1", false, 0),
        (b"SELECT 1", 6, "SELECT", true, 2),
        (b"SELECT 1", 0, "", true, 8),
        ("ééé".as_bytes(), 5, "éé", true, 2),
        (b"a\xffb", 10, "a\u{fffd}b", false, 0),
        (b"a\xffb", 3, "a", true, 2),
        (b"", 4, "", false, 0),
    ];
    for (input, limit, text, truncated, dropped_bytes) in cases {
        let excerpt = Excerpt::of(input, limit);
        assert_eq!(
            excerpt,
            Excerpt {
                text: text.into(),
                truncated,
                dropped_bytes,
            },
            "{input:?} at {limit}"
        );
        assert!(excerpt.text.len() <= limit);
    }
}

#[test]
fn statements_are_extracted_from_query_and_parse() {
    let text = format!("INSERT INTO t VALUES ('{}')", "z".repeat(200));
    let mut parse = cstr("s");
    parse.extend(cstr(&text));
    parse.extend(i16s(&[0]));
    let input = after_startup(&[&message(b'Q', &cstr(&text)), &message(b'P', &parse)]);
    let messages = frontend(&input).only();
    let statements = [
        match &messages[1] {
            FrontendMessage::Query(statement) => statement.clone(),
            other => panic!("unexpected {other:?}"),
        },
        match &messages[2] {
            FrontendMessage::Parse(parse) => parse.statement.clone(),
            other => panic!("unexpected {other:?}"),
        },
    ];
    for statement in statements {
        assert_eq!(statement.as_bytes(), text.as_bytes());
        assert_eq!(statement.length(), text.len());
        assert_eq!(statement.kind(), StatementKind::Insert);
        let excerpt = statement.excerpt(32);
        assert_eq!(excerpt.text, &text[..32]);
        assert!(excerpt.truncated);
        assert_eq!(excerpt.dropped_bytes, text.len() - 32);
        let whole = statement.excerpt(4096);
        assert!(!whole.truncated);
        assert_eq!(whole.text, text);
    }
}

#[test]
fn statements_are_classified_by_first_keyword() {
    let cases: [(&str, StatementKind); 26] = [
        ("SELECT 1", StatementKind::Select),
        ("  select\n1", StatementKind::Select),
        ("(SELECT 1)", StatementKind::Select),
        ("insert into t values (1)", StatementKind::Insert),
        ("UPDATE t SET a = 1", StatementKind::Update),
        ("DELETE FROM t", StatementKind::Delete),
        ("CREATE TABLE t (a int)", StatementKind::Ddl),
        ("alter role app password 'x'", StatementKind::Ddl),
        ("DROP TABLE t", StatementKind::Ddl),
        ("TRUNCATE t", StatementKind::Ddl),
        ("GRANT SELECT ON t TO app", StatementKind::Ddl),
        ("COPY t FROM STDIN", StatementKind::Copy),
        ("SET search_path = x", StatementKind::Set),
        ("RESET ALL", StatementKind::Set),
        ("-- note\nDROP TABLE t", StatementKind::Ddl),
        (
            "/* a /* nested */ b */ DELETE FROM t",
            StatementKind::Delete,
        ),
        (";; UPDATE t SET a = 1", StatementKind::Update),
        ("WITH x AS (SELECT 1) DELETE FROM t", StatementKind::Other),
        ("SELECTED", StatementKind::Other),
        ("SELECT 1;", StatementKind::Select),
        ("SELECT 1; -- done\n /* end */ ;", StatementKind::Select),
        ("SELECT 1; DROP TABLE t", StatementKind::Other),
        ("SELECT ';' AS x", StatementKind::Other),
        ("/* unterminated DROP TABLE t", StatementKind::Other),
        ("-- only a comment", StatementKind::Other),
        ("", StatementKind::Other),
    ];
    for (text, expected) in cases {
        assert_eq!(StatementKind::of(text.as_bytes()), expected, "{text:?}");
    }
    assert_eq!(StatementKind::Ddl.as_str(), "ddl");
}

#[test]
fn compound_statements_are_flagged() {
    let cases: [(&str, bool); 7] = [
        ("SELECT 1", false),
        ("SELECT 1;", false),
        ("SELECT 1;  \n\t", false),
        ("SELECT 1; -- trailing note", false),
        ("SELECT 1; /* a */ ; /* b */", false),
        ("SELECT 1; DROP TABLE t", true),
        ("SELECT 1; /* unterminated", true),
    ];
    for (text, compound) in cases {
        let input = after_startup(&[&message(b'Q', &cstr(text))]);
        let messages = frontend(&input).only();
        let FrontendMessage::Query(statement) = &messages[1] else {
            panic!("expected a query");
        };
        assert_eq!(statement.is_compound(), compound, "{text:?}");
        if compound {
            assert_eq!(statement.kind(), StatementKind::Other, "{text:?}");
        } else {
            assert_eq!(statement.kind(), StatementKind::Select, "{text:?}");
        }
    }
}

#[test]
fn excerpt_debug_hides_the_text() {
    let excerpt = Excerpt::of(b"ALTER ROLE app PASSWORD 'hunter2'", 20);
    let rendered = format!("{excerpt:?}");
    assert!(
        !rendered.contains("hunter2") && !rendered.contains("ALTER"),
        "{rendered}"
    );
    assert!(rendered.contains("truncated: true"), "{rendered}");
    assert!(rendered.contains("length: 20"), "{rendered}");
}
