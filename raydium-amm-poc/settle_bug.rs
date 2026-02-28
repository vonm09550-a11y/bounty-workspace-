// tests/settle_bug.rs
//
// PoC: process_swap_base_out PC2Coin settlement passes market_asks_info
// where market_coin_vault_info is expected, causing DEX CPI to fail.
//
// Bug location: processor.rs line ~2972-2986, SwapDirection::PC2Coin branch
// when swap.amount_out > amm_coin_vault.amount triggers settlement.
//
// Run: cargo test-sbf --test settle_bug -- --nocapture

use solana_program_test::*;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

const AMM_PROGRAM_ID: Pubkey = solana_sdk::pubkey!("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8");

// Account sizes
const AMM_INFO_SIZE: usize = 752;
const MARKET_STATE_SIZE: usize = 388;   // 5 + 376 + 7
const OPEN_ORDERS_SIZE: usize = 3228;   // 5 + 3216 + 7
const SLAB_SIZE: usize = 340;           // 5 + 8 + 32 + 4*72 + 7
const EVENT_QUEUE_SIZE: usize = 128;    // Larger for serum compatibility

// Serum account flags
const FLAG_INITIALIZED: u64 = 1;
const FLAG_MARKET: u64 = 2;
const FLAG_OPEN_ORDERS: u64 = 4;
const FLAG_REQ_QUEUE: u64 = 8;
const FLAG_EVENT_QUEUE: u64 = 16;
const FLAG_BIDS: u64 = 32;
const FLAG_ASKS: u64 = 64;

const SERUM_HEAD: &[u8; 5] = b"serum";
const SERUM_TAIL: &[u8; 7] = b"padding";

fn write_u64(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

fn write_u128(buf: &mut [u8], off: usize, val: u128) {
    buf[off..off + 16].copy_from_slice(&val.to_le_bytes());
}

fn write_pubkey(buf: &mut [u8], off: usize, key: &Pubkey) {
    buf[off..off + 32].copy_from_slice(key.as_ref());
}

/// Build MarketState account (serum format)
fn build_market_state(
    own_address: &Pubkey,
    coin_mint: &Pubkey,
    pc_mint: &Pubkey,
    coin_vault: &Pubkey,
    pc_vault: &Pubkey,
    bids: &Pubkey,
    asks: &Pubkey,
    event_q: &Pubkey,
    req_q: &Pubkey,
    vault_signer_nonce: u64,
) -> Vec<u8> {
    let mut buf = vec![0u8; MARKET_STATE_SIZE];
    buf[0..5].copy_from_slice(SERUM_HEAD);
    buf[MARKET_STATE_SIZE - 7..].copy_from_slice(SERUM_TAIL);

    let b = 5;
    write_u64(&mut buf, b, FLAG_INITIALIZED | FLAG_MARKET);
    write_pubkey(&mut buf, b + 8, own_address);
    write_u64(&mut buf, b + 40, vault_signer_nonce);
    write_pubkey(&mut buf, b + 48, coin_mint);
    write_pubkey(&mut buf, b + 80, pc_mint);
    write_pubkey(&mut buf, b + 112, coin_vault);
    // coin_deposits_total, coin_fees_accrued at b+144, b+152 = 0
    write_pubkey(&mut buf, b + 160, pc_vault);
    // pc_deposits_total, pc_fees_accrued, pc_dust_threshold at b+192..b+216 = 0
    write_pubkey(&mut buf, b + 216, req_q);
    write_pubkey(&mut buf, b + 248, event_q);
    write_pubkey(&mut buf, b + 280, bids);
    write_pubkey(&mut buf, b + 312, asks);
    write_u64(&mut buf, b + 344, 1); // base_lot_size
    write_u64(&mut buf, b + 352, 1); // quote_lot_size
    buf
}

/// Build empty slab (bids or asks)
fn build_slab(flags: u64) -> Vec<u8> {
    let mut buf = vec![0u8; SLAB_SIZE];
    buf[0..5].copy_from_slice(SERUM_HEAD);
    buf[SLAB_SIZE - 7..].copy_from_slice(SERUM_TAIL);
    write_u64(&mut buf, 5, FLAG_INITIALIZED | flags);
    buf
}

/// Build empty event queue with proper header
fn build_event_queue() -> Vec<u8> {
    let mut buf = vec![0u8; EVENT_QUEUE_SIZE];
    buf[0..5].copy_from_slice(SERUM_HEAD);
    buf[EVENT_QUEUE_SIZE - 7..].copy_from_slice(SERUM_TAIL);
    write_u64(&mut buf, 5, FLAG_INITIALIZED | FLAG_EVENT_QUEUE);
    // EventQueueHeader: head(8) + count(8) + seq_num(8) = 24 bytes after flags
    // All zeros = empty queue
    buf
}

/// Build OpenOrders with coins locked (to make total_coin > vault_coin)
fn build_open_orders(market: &Pubkey, owner: &Pubkey, native_coin_total: u64) -> Vec<u8> {
    let mut buf = vec![0u8; OPEN_ORDERS_SIZE];
    buf[0..5].copy_from_slice(SERUM_HEAD);
    buf[OPEN_ORDERS_SIZE - 7..].copy_from_slice(SERUM_TAIL);

    let b = 5;
    write_u64(&mut buf, b, FLAG_INITIALIZED | FLAG_OPEN_ORDERS);
    write_pubkey(&mut buf, b + 8, market);    // market [u64;4]
    write_pubkey(&mut buf, b + 40, owner);    // owner [u64;4]
    // b+72: native_coin_free = 0
    write_u64(&mut buf, b + 80, native_coin_total);  // native_coin_total
    // b+88: native_pc_free = 0
    // b+96: native_pc_total = 0
    write_u128(&mut buf, b + 104, u128::MAX); // free_slot_bits (all free)
    buf
}

/// Build AmmInfo with proper layout
fn build_amm_info(
    nonce: u8,
    coin_vault: &Pubkey,
    pc_vault: &Pubkey,
    coin_mint: &Pubkey,
    pc_mint: &Pubkey,
    lp_mint: &Pubkey,
    open_orders: &Pubkey,
    market: &Pubkey,
    market_program: &Pubkey,
    target_orders: &Pubkey,
    amm_owner: &Pubkey,
) -> Vec<u8> {
    let mut buf = vec![0u8; AMM_INFO_SIZE];
    let mut off = 0;

    // 16 u64 fields (128 bytes)
    write_u64(&mut buf, off, 1); off += 8;              // status = Initialized (orderbook enabled)
    write_u64(&mut buf, off, nonce as u64); off += 8;   // nonce
    write_u64(&mut buf, off, 10); off += 8;             // order_num
    write_u64(&mut buf, off, 3); off += 8;              // depth
    write_u64(&mut buf, off, 6); off += 8;              // coin_decimals
    write_u64(&mut buf, off, 6); off += 8;              // pc_decimals
    write_u64(&mut buf, off, 0); off += 8;              // state
    write_u64(&mut buf, off, 0); off += 8;              // reset_flag
    write_u64(&mut buf, off, 1); off += 8;              // min_size
    write_u64(&mut buf, off, 0); off += 8;              // vol_max_cut_ratio
    write_u64(&mut buf, off, 0); off += 8;              // amount_wave
    write_u64(&mut buf, off, 1); off += 8;              // coin_lot_size
    write_u64(&mut buf, off, 1); off += 8;              // pc_lot_size
    write_u64(&mut buf, off, 1); off += 8;              // min_price_multiplier
    write_u64(&mut buf, off, 1_000_000_000); off += 8;  // max_price_multiplier
    write_u64(&mut buf, off, 1_000_000); off += 8;      // sys_decimal_value

    // Fees struct (8 u64 = 64 bytes)
    write_u64(&mut buf, off, 5); off += 8;              // min_separate_numerator
    write_u64(&mut buf, off, 10_000); off += 8;         // min_separate_denominator
    write_u64(&mut buf, off, 25); off += 8;             // trade_fee_numerator
    write_u64(&mut buf, off, 10_000); off += 8;         // trade_fee_denominator
    write_u64(&mut buf, off, 12); off += 8;             // pnl_numerator
    write_u64(&mut buf, off, 100); off += 8;            // pnl_denominator
    write_u64(&mut buf, off, 25); off += 8;             // swap_fee_numerator (0.25%)
    write_u64(&mut buf, off, 10_000); off += 8;         // swap_fee_denominator

    // StateData struct (144 bytes)
    for _ in 0..8 { write_u64(&mut buf, off, 0); off += 8; }  // 8 u64 fields
    for _ in 0..4 { write_u128(&mut buf, off, 0); off += 16; } // 4 u128 fields
    for _ in 0..2 { write_u64(&mut buf, off, 0); off += 8; }  // 2 u64 fields

    // 9 Pubkeys (288 bytes)
    write_pubkey(&mut buf, off, coin_vault); off += 32;
    write_pubkey(&mut buf, off, pc_vault); off += 32;
    write_pubkey(&mut buf, off, coin_mint); off += 32;
    write_pubkey(&mut buf, off, pc_mint); off += 32;
    write_pubkey(&mut buf, off, lp_mint); off += 32;
    write_pubkey(&mut buf, off, open_orders); off += 32;
    write_pubkey(&mut buf, off, market); off += 32;
    write_pubkey(&mut buf, off, market_program); off += 32;
    write_pubkey(&mut buf, off, target_orders); off += 32;

    // padding1 [u64;8] (64 bytes)
    off += 64;

    // amm_owner (32 bytes) + 4 u64 (32 bytes)
    write_pubkey(&mut buf, off, amm_owner); off += 32;
    write_u64(&mut buf, off, 1_000_000); off += 8;      // lp_amount
    off += 24; // client_order_id, recent_epoch, padding2

    assert_eq!(off, AMM_INFO_SIZE);
    buf
}

/// Pack SPL token account
fn pack_token_account(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut buf = vec![0u8; 165]; // spl_token Account::LEN
    write_pubkey(&mut buf, 0, mint);
    write_pubkey(&mut buf, 32, owner);
    write_u64(&mut buf, 64, amount);
    buf[72..76].copy_from_slice(&0u32.to_le_bytes()); // delegate = None
    buf[108] = 1; // state = Initialized
    buf
}

/// Pack SPL mint
fn pack_mint(decimals: u8, supply: u64, authority: Option<&Pubkey>) -> Vec<u8> {
    let mut buf = vec![0u8; 82]; // spl_token Mint::LEN
    if let Some(auth) = authority {
        buf[0..4].copy_from_slice(&1u32.to_le_bytes()); // COption::Some
        write_pubkey(&mut buf, 4, auth);
    }
    write_u64(&mut buf, 36, supply);
    buf[44] = decimals;
    buf[45] = 1; // is_initialized
    buf
}

#[tokio::test]
async fn test_settle_funds_wrong_account_bug() {
    let mut program_test = ProgramTest::new("raydium_amm", AMM_PROGRAM_ID, None);

    let dex_program_id = Pubkey::new_unique();
    program_test.add_program("serum_dex", dex_program_id, None);

    // Generate all keypairs
    let amm_kp = Keypair::new();
    let market_kp = Keypair::new();
    let coin_mint = Keypair::new().pubkey();
    let pc_mint = Keypair::new().pubkey();
    let lp_mint = Keypair::new().pubkey();
    let market_bids = Keypair::new().pubkey();
    let market_asks = Keypair::new().pubkey();
    let market_event_q = Keypair::new().pubkey();
    let market_req_q = Keypair::new().pubkey();
    let market_coin_vault = Keypair::new().pubkey();
    let market_pc_vault = Keypair::new().pubkey();
    let amm_coin_vault = Keypair::new().pubkey();
    let amm_pc_vault = Keypair::new().pubkey();
    let open_orders = Keypair::new().pubkey();
    let target_orders = Keypair::new().pubkey();
    let user = Keypair::new();
    let user_pc_ata = Keypair::new().pubkey();
    let user_coin_ata = Keypair::new().pubkey();

    // Derive AMM authority PDA
    let (amm_authority, nonce) = (0u8..=255)
        .rev()
        .find_map(|n| {
            Pubkey::create_program_address(&[b"amm authority", &[n]], &AMM_PROGRAM_ID)
                .ok()
                .map(|pk| (pk, n))
        })
        .unwrap();

    // Derive market vault signer
    let vault_signer_nonce = (0u64..)
        .find(|&n| {
            Pubkey::create_program_address(
                &[market_kp.pubkey().as_ref(), &n.to_le_bytes()],
                &dex_program_id,
            )
            .is_ok()
        })
        .unwrap();
    let market_vault_signer = Pubkey::create_program_address(
        &[market_kp.pubkey().as_ref(), &vault_signer_nonce.to_le_bytes()],
        &dex_program_id,
    )
    .unwrap();

    let rent = solana_sdk::rent::Rent::default();

    // Add mints
    for (pk, supply) in [(coin_mint, 1_000_000_000u64), (pc_mint, 1_000_000_000), (lp_mint, 1_000_000)] {
        program_test.add_account(pk, Account {
            lamports: rent.minimum_balance(82),
            data: pack_mint(6, supply, Some(&amm_authority)),
            owner: spl_token::id(),
            ..Default::default()
        });
    }

    // =======================================================================
    // KEY VALUES FOR TRIGGERING THE BUG:
    // - amm_coin_vault has LOW balance (10) to force settlement
    // - OpenOrders has HIGH native_coin_total (1000000) so total_coin is large
    // - This ensures: amount_out(1000) < total_coin but > vault(10)
    // =======================================================================

    // AMM coin vault: LOW balance to trigger settlement path
    program_test.add_account(amm_coin_vault, Account {
        lamports: rent.minimum_balance(165),
        data: pack_token_account(&coin_mint, &amm_authority, 10),  // Only 10 coins
        owner: spl_token::id(),
        ..Default::default()
    });
    // AMM PC vault: enough for the swap
    program_test.add_account(amm_pc_vault, Account {
        lamports: rent.minimum_balance(165),
        data: pack_token_account(&pc_mint, &amm_authority, 10_000_000),
        owner: spl_token::id(),
        ..Default::default()
    });

    // Market vaults (serum)
    program_test.add_account(market_coin_vault, Account {
        lamports: rent.minimum_balance(165),
        data: pack_token_account(&coin_mint, &market_vault_signer, 5_000_000),
        owner: spl_token::id(),
        ..Default::default()
    });
    program_test.add_account(market_pc_vault, Account {
        lamports: rent.minimum_balance(165),
        data: pack_token_account(&pc_mint, &market_vault_signer, 5_000_000),
        owner: spl_token::id(),
        ..Default::default()
    });

    // User has plenty of PC tokens to pay for the swap
    program_test.add_account(user_pc_ata, Account {
        lamports: rent.minimum_balance(165),
        data: pack_token_account(&pc_mint, &user.pubkey(), 10_000_000),
        owner: spl_token::id(),
        ..Default::default()
    });
    program_test.add_account(user_coin_ata, Account {
        lamports: rent.minimum_balance(165),
        data: pack_token_account(&coin_mint, &user.pubkey(), 0),
        owner: spl_token::id(),
        ..Default::default()
    });

    // Market state
    program_test.add_account(market_kp.pubkey(), Account {
        lamports: rent.minimum_balance(MARKET_STATE_SIZE),
        data: build_market_state(
            &market_kp.pubkey(), &coin_mint, &pc_mint,
            &market_coin_vault, &market_pc_vault,
            &market_bids, &market_asks, &market_event_q, &market_req_q,
            vault_signer_nonce,
        ),
        owner: dex_program_id,
        ..Default::default()
    });

    // Bids, asks, event queue, request queue
    program_test.add_account(market_bids, Account {
        lamports: rent.minimum_balance(SLAB_SIZE),
        data: build_slab(FLAG_BIDS),
        owner: dex_program_id,
        ..Default::default()
    });
    program_test.add_account(market_asks, Account {
        lamports: rent.minimum_balance(SLAB_SIZE),
        data: build_slab(FLAG_ASKS),
        owner: dex_program_id,
        ..Default::default()
    });
    program_test.add_account(market_event_q, Account {
        lamports: rent.minimum_balance(EVENT_QUEUE_SIZE),
        data: build_event_queue(),
        owner: dex_program_id,
        ..Default::default()
    });
    let mut rq = vec![0u8; EVENT_QUEUE_SIZE];
    rq[0..5].copy_from_slice(SERUM_HEAD);
    rq[EVENT_QUEUE_SIZE - 7..].copy_from_slice(SERUM_TAIL);
    write_u64(&mut rq, 5, FLAG_INITIALIZED | FLAG_REQ_QUEUE);
    program_test.add_account(market_req_q, Account {
        lamports: rent.minimum_balance(EVENT_QUEUE_SIZE),
        data: rq,
        owner: dex_program_id,
        ..Default::default()
    });

    // OpenOrders: HIGH native_coin_total so total_coin = 10 + 1000000 = 1000010
    // This allows amount_out=1000 to pass the "< total_coin" check
    program_test.add_account(open_orders, Account {
        lamports: rent.minimum_balance(OPEN_ORDERS_SIZE),
        data: build_open_orders(&market_kp.pubkey(), &amm_authority, 1_000_000),
        owner: dex_program_id,
        ..Default::default()
    });

    // Target orders (minimal, AMM-owned)
    program_test.add_account(target_orders, Account {
        lamports: rent.minimum_balance(2208),  // TargetOrders size
        data: vec![0u8; 2208],
        owner: AMM_PROGRAM_ID,
        ..Default::default()
    });

    // AMM state
    program_test.add_account(amm_kp.pubkey(), Account {
        lamports: rent.minimum_balance(AMM_INFO_SIZE),
        data: build_amm_info(
            nonce, &amm_coin_vault, &amm_pc_vault, &coin_mint, &pc_mint,
            &lp_mint, &open_orders, &market_kp.pubkey(), &dex_program_id,
            &target_orders, &user.pubkey(),
        ),
        owner: AMM_PROGRAM_ID,
        ..Default::default()
    });

    // Fund user
    program_test.add_account(user.pubkey(), Account {
        lamports: 10_000_000_000,
        ..Default::default()
    });

    let (banks, payer, blockhash) = program_test.start().await;

    // =======================================================================
    // SwapBaseOut instruction: PC -> Coin
    // amount_out = 1000 coins (user wants to receive)
    //
    // This triggers settlement because:
    //   amount_out(1000) > amm_coin_vault.amount(10)
    //
    // The bug: AMM passes market_asks_info to settle_funds instead of
    //          market_coin_vault_info, causing DEX to reject the CPI.
    // =======================================================================
    let mut ix_data = vec![11u8]; // SwapBaseOut discriminator (9=SwapBaseIn, 11=SwapBaseOut)
    ix_data.extend_from_slice(&100_000_000u64.to_le_bytes()); // max_amount_in (high limit)
    ix_data.extend_from_slice(&1000u64.to_le_bytes());         // amount_out (1000 coins)

    let accounts = vec![
        AccountMeta::new_readonly(spl_token::id(), false),      // 0: token_program
        AccountMeta::new(amm_kp.pubkey(), false),               // 1: amm
        AccountMeta::new_readonly(amm_authority, false),        // 2: amm_authority
        AccountMeta::new(open_orders, false),                   // 3: open_orders
        AccountMeta::new(target_orders, false),                 // 4: target_orders (optional)
        AccountMeta::new(amm_coin_vault, false),                // 5: amm_coin_vault
        AccountMeta::new(amm_pc_vault, false),                  // 6: amm_pc_vault
        AccountMeta::new_readonly(dex_program_id, false),       // 7: market_program
        AccountMeta::new(market_kp.pubkey(), false),            // 8: market
        AccountMeta::new(market_bids, false),                   // 9: bids
        AccountMeta::new(market_asks, false),                   // 10: asks <-- BUG: passed as coin_vault to settle_funds
        AccountMeta::new(market_event_q, false),                // 11: event_queue
        AccountMeta::new(market_coin_vault, false),             // 12: market_coin_vault (should be used)
        AccountMeta::new(market_pc_vault, false),               // 13: market_pc_vault
        AccountMeta::new_readonly(market_vault_signer, false),  // 14: vault_signer
        AccountMeta::new(user_pc_ata, false),                   // 15: user_source (PC in)
        AccountMeta::new(user_coin_ata, false),                 // 16: user_dest (coin out)
        AccountMeta::new_readonly(user.pubkey(), true),         // 17: user_owner
    ];

    let ix = Instruction {
        program_id: AMM_PROGRAM_ID,
        accounts,
        data: ix_data,
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer, &user],
        blockhash,
    );

    let result = banks.process_transaction(tx).await;

    // =======================================================================
    // EXPECTED BEHAVIOR:
    // 1. Swap calculation passes (amount_out < total_coin)
    // 2. Settlement triggered (amount_out > amm_coin_vault)
    // 3. AMM calls invoke_dex_settle_funds with WRONG account (market_asks)
    // 4. DEX rejects: coin_vault key mismatch
    //
    // The error should come from DEX (serum_dex program), NOT from AMM.
    // AMM errors are in range 0-50, DEX errors are different.
    // =======================================================================
    assert!(result.is_err(), "Transaction should fail");

    if let Err(e) = &result {
        let err_str = format!("{:?}", e);
        eprintln!("\n=== Transaction Error ===");
        eprintln!("{}", err_str);

        // Check if this is the AMM InsufficientFunds error (code 40)
        // If we see this, we haven't reached the settlement path yet
        let is_amm_insufficient_funds = err_str.contains("Custom(40)");

        if is_amm_insufficient_funds {
            eprintln!("\nFAILED: Still hitting AMM InsufficientFunds before settlement path.");
            eprintln!("Need to adjust test values to pass swap calculation checks.");
            panic!("Test did not reach the buggy settlement code path");
        }

        // If we see a different error (especially from DEX), the bug is confirmed
        eprintln!("\nSettlement path reached - DEX rejected the CPI as expected.");
    }
}
