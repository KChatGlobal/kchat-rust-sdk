use kchat_mls::extract_jid_from_member_id;

#[test]
fn test_extract_jid_from_member_id() {
    assert_eq!(
        extract_jid_from_member_id("user@example.com/resource-abc123"),
        Some("user@example.com".to_owned())
    );

    assert_eq!(
        extract_jid_from_member_id("user@domain.org/device-fingerprint123"),
        Some("user@domain.org".to_owned())
    );

    assert_eq!(extract_jid_from_member_id("invalid-format"), None);

    assert_eq!(extract_jid_from_member_id("no-slash"), None);

    assert_eq!(
        extract_jid_from_member_id("/resource-abc"),
        Some("".to_owned())
    );

    assert_eq!(
        extract_jid_from_member_id("user@example.com/nodash"),
        Some("user@example.com".to_owned())
    );
}
