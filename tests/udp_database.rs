#[path = "../build/database.rs"]
mod database;
#[path = "../build/payload.rs"]
mod payload_parser;

use database::parse;

#[test]
fn comments_do_not_remove_payloads_or_literal_hashes() {
    let entries = parse(
        r##"
# comment with "unbalanced quotes
udp 623 # header comment
"a#b" # trailing comment
"\"#\\" # escaped quote and backslash before the closing quote
"\x80\0"
"##,
    )
    .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].payload, b"a#b\"#\\\x80\0");
}

#[test]
fn ranges_include_both_endpoints_and_deduplicate_ports() {
    let entries = parse("udp 1198-1199,1199,65534-65535,8-8 \"probe\"").unwrap();
    assert_eq!(entries[0].ports, [8, 1198, 1199, 65534, 65535]);
}

#[test]
fn duplicate_and_overlapping_port_lists_preserve_every_entry() {
    let entries =
        parse("udp 53,123 \"first\"\nudp 53,123 \"second\"\nudp 123-124 \"third\"").unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].payload, b"first");
    assert_eq!(entries[1].payload, b"second");
    assert_eq!(entries[2].ports, [123, 124]);
    assert_eq!(entries[2].payload, b"third");
}

#[test]
fn flushes_single_and_final_entries_without_a_trailing_newline() {
    for input in ["udp 48899 \"ads\"", "udp 53 \"dns\"\nudp 48899 \"ads\""] {
        let entries = parse(input).unwrap();
        assert_eq!(entries.last().unwrap().ports, [48899]);
        assert_eq!(entries.last().unwrap().payload, b"ads");
    }
}

#[test]
fn accepts_indented_headers_tabs_and_multiline_entries() {
    let entries =
        parse("  udp\t53\n\"a\"\n\"b\"\nsource 123 future \"metadata\"\n\tudp\n123\n\"c\"")
            .unwrap();
    assert_eq!(entries[0].ports, [53]);
    assert_eq!(entries[0].payload, b"ab");
    assert_eq!(entries[1].ports, [123]);
    assert_eq!(entries[1].payload, b"c");
}

#[test]
fn invalid_entries_fail_with_the_source_line_instead_of_losing_coverage() {
    for entry in [
        "udp 2-1 \"x\"",
        "udp 65536 \"x\"",
        "udp 53",
        "udp 53 \"unterminated",
        "udp 53 \"\\q\"",
        "tcp 53 \"x\"",
    ] {
        let error = parse(&format!("# comment\n{entry}")).unwrap_err();
        assert!(error.starts_with("line 2:"), "{}", error);
    }
}
