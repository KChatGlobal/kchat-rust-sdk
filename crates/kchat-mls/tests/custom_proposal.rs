use kchat_mls::{
    CreateCustomProposalArgs, CustomProposalType, create_custom_proposal, process_custom_proposal,
};

#[test]
fn process_custom_proposal_round_trips_serialized_payload() {
    let payload = create_custom_proposal(
        "mls-client-id",
        "group-id",
        CreateCustomProposalArgs {
            mls_fingerprint: "mls-fingerprint".to_owned(),
            custom_proposal_type: CustomProposalType::Remove,
        },
    );

    let proposal =
        process_custom_proposal(&payload).expect("serialized custom proposal should decode");

    assert_eq!(proposal.client_jid, None);
    assert_eq!(proposal.epoch, None);
    assert_eq!(proposal.group_id, "group-id");
    assert_eq!(proposal.proposal_type, CustomProposalType::Remove);
}

#[test]
fn process_custom_proposal_returns_none_for_invalid_payload() {
    assert!(process_custom_proposal(b"not-a-custom-proposal").is_none());
}
