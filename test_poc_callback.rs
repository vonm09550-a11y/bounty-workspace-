mod setup;
use crate::setup::*;

#[test]
fn test_poc_callback_no_state_restore() {
    let e = init_env();
    let users = Users::init(&e);

    let inner_id = "0".to_string();
    let token_id = format!(":{}", inner_id);
    let seed_id = e.mft_seed_id(&inner_id);

    e.create_seed(&e.owner, &seed_id, TOKEN_DECIMALS as u32, None, None).assert_success();
    e.mft_mint(&inner_id, &users.farmer1, to_yocto("100"));
    e.storage_deposit_self_to_farming(&users.farmer1).assert_success();
    e.mft_storage_deposit(&token_id, &e.farming_contract.user_account);

    e.mft_stake_free_seed(&users.farmer1, &token_id, to_yocto("100")).assert_success();
    assert_user_seed_info(
        e.get_farmer_seed(&users.farmer1, &seed_id),
        to_yocto("100"), 0, 0, 0, 0
    );

    let seed_before = e.get_seed(&seed_id);
    assert_eq!(seed_before.total_seed_amount.0, to_yocto("100"));

    e.mft_unregister(&token_id, &users.farmer1);
    assert_err!(
        e.unlock_and_withdraw_seed(&users.farmer1, &seed_id, to_yocto("40")),
        "ERR_RECEIVER_NOT_REGISTERED"
    );
    e.mft_storage_deposit(&token_id, &users.farmer1);

    // farmer_seed.free_amount: 60, expected 100
    assert_user_seed_info(
        e.get_farmer_seed(&users.farmer1, &seed_id),
        to_yocto("60"), 0, 0, 0, 0
    );

    // seed.total_seed_amount: 60, expected 100
    let seed_after = e.get_seed(&seed_id);
    assert_eq!(seed_after.total_seed_amount.0, to_yocto("60"));

    assert_eq!(e.list_lostfound().get(&seed_id).unwrap().0, to_yocto("40"));

    assert_eq!(
        true,
        e.unlock_and_withdraw_seed(&users.farmer1, &seed_id, to_yocto("60")).unwrap_json::<bool>()
    );
    assert!(e.get_farmer_seed(&users.farmer1, &seed_id).is_null());
    assert_eq!(e.mft_balance_of(&users.farmer1, &token_id), to_yocto("60"));
}

#[test]
fn test_poc_full_balance_deletion() {
    let e = init_env();
    let users = Users::init(&e);

    let inner_id = "0".to_string();
    let token_id = format!(":{}", inner_id);
    let seed_id = e.mft_seed_id(&inner_id);

    e.create_seed(&e.owner, &seed_id, TOKEN_DECIMALS as u32, None, None).assert_success();
    e.mft_mint(&inner_id, &users.farmer1, to_yocto("100"));
    e.storage_deposit_self_to_farming(&users.farmer1).assert_success();
    e.mft_storage_deposit(&token_id, &e.farming_contract.user_account);

    e.mft_stake_free_seed(&users.farmer1, &token_id, to_yocto("100")).assert_success();

    e.mft_unregister(&token_id, &users.farmer1);
    assert_err!(
        e.unlock_and_withdraw_seed(&users.farmer1, &seed_id, to_yocto("100")),
        "ERR_RECEIVER_NOT_REGISTERED"
    );
    e.mft_storage_deposit(&token_id, &users.farmer1);

    assert!(e.get_farmer_seed(&users.farmer1, &seed_id).is_null());

    let seed_after = e.get_seed(&seed_id);
    assert_eq!(seed_after.total_seed_amount.0, 0);

    assert_eq!(e.list_lostfound().get(&seed_id).unwrap().0, to_yocto("100"));

    assert_err!(
        e.unlock_and_withdraw_seed(&users.farmer1, &seed_id, to_yocto("1")),
        E301_SEED_NOT_EXIST
    );
}

#[test]
fn test_poc_incomplete_recovery() {
    let e = init_env();
    let users = Users::init(&e);

    let inner_id = "0".to_string();
    let token_id = format!(":{}", inner_id);
    let seed_id = e.mft_seed_id(&inner_id);

    e.create_seed(&e.owner, &seed_id, TOKEN_DECIMALS as u32, None, None).assert_success();
    e.mft_mint(&inner_id, &users.farmer1, to_yocto("100"));
    e.storage_deposit_self_to_farming(&users.farmer1).assert_success();
    e.mft_storage_deposit(&token_id, &e.farming_contract.user_account);

    e.mft_stake_free_seed(&users.farmer1, &token_id, to_yocto("100")).assert_success();

    e.mft_unregister(&token_id, &users.farmer1);
    assert_err!(
        e.unlock_and_withdraw_seed(&users.farmer1, &seed_id, to_yocto("100")),
        "ERR_RECEIVER_NOT_REGISTERED"
    );
    e.mft_storage_deposit(&token_id, &users.farmer1);

    assert!(e.get_farmer_seed(&users.farmer1, &seed_id).is_null());
    assert_eq!(e.list_lostfound().get(&seed_id).unwrap().0, to_yocto("100"));

    // owner recovery transfers tokens but does not restore farming position
    e.return_seed_lostfound(&e.owner, &users.farmer1, &seed_id, to_yocto("100")).assert_success();

    assert_eq!(e.mft_balance_of(&users.farmer1, &token_id), to_yocto("100"));
    assert!(e.get_farmer_seed(&users.farmer1, &seed_id).is_null());

    // seed.total_seed_amount remains 0, user must re-stake manually
    let seed_after = e.get_seed(&seed_id);
    assert_eq!(seed_after.total_seed_amount.0, 0);
}
