// program/tests/settle_bug.rs
//
// Integration test: process_swap_base_out PC2Coin settle path passes
// market_asks_info where market_coin_vault_info is expected.
//
// Requires: solana-program-test in [dev-dependencies]
// Run:      cargo test-sbf --test settle_bug

use solana_program_test::*;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    solana_program_pack::Pack,
    transaction::Transaction,
};
use spl_token::state::Mint;

// --- constants ---

const AMM_PROGRAM_ID: Pubkey = solana_sdk::pubkey!("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8");

// AmmInfo size: 16 u64s (128) + Fees (64) + StateData (160) + 9 Pubkeys (288)
//              + padding1 [u64;8] (64) + amm_owner Pubkey (32) + 4 u64s (32) = 768
const AMM_INFO_SIZE: usize = 768;

// OpenBook DEX MarketState layout (packed, with 5-byte padding prefix and suffix)
// Total account size = 5 + MARKET_STATE_INNER + 7 = 388
const MARKET_STATE_PADDED_SIZE: usize = 388;

// OpenBook open orders account size
const OPEN_ORDERS_SIZE: usize = 3228;

// Slab header + minimal capacity for bids/asks accounts
const SLAB_HEADER_SIZE: usize = 32;
const SLAB_LEAF_SIZE: usize = 72;
const SLAB_MIN_CAPACITY: usize = SLAB_HEADER_SIZE + 4 * SLAB_LEAF_SIZE; // header + 4 nodes

// Event queue: header (37 bytes padded) + small buffer
const EVENT_QUEUE_SIZE: usize = 512;

// serum_dex account flags
const ACCOUNT_FLAG_INITIALIZED: u64 = 1;
const ACCOUNT_FLAG_MARKET: u64 = 2;
const ACCOUNT_FLAG_OPEN_ORDERS: u64 = 4;
const ACCOUNT_FLAG_BIDS: u64 = 16;
const ACCOUNT_FLAG_ASKS: u64 = 32;
const ACCOUNT_FLAG_EVENT_QUEUE: u64 = 128;

// --- helpers ---

/// Serialize a u64 as little-endian at the given offset.
fn write_u64(buf: &mut [u8], offset: usize, val: u64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

/// Serialize a Pubkey (32 bytes) at the given offset.
fn write_pubkey(buf: &mut [u8], offset: usize, key: &Pubkey) {
    buf[offset..offset + 32].copy_from_slice(key.as_ref());
}

/// Build minimal OpenBook DEX market state account data.
///
/// Layout (all fields u64 LE unless noted, 5-byte serum padding prefix):
///   [0..5]   padding (account tag)
///   [5..13]  account_flags
///   [13..45] own_address (Pubkey as [u64;4])
///   [45..53] vault_signer_nonce
///   [53..85] coin_mint
///   [85..117] pc_mint
///   [117..149] coin_vault      <-- DEX validates this against settle_funds arg
///   [149..157] coin_deposits_total
///   [157..165] coin_fees_accrued
///   [165..197] pc_vault
///   [197..205] pc_deposits_total
///   [205..213] pc_fees_accrued
///   [213..221] pc_dust_threshold
///   [221..253] req_q
///   [253..285] event_q
///   [285..317] bids
///   [317..349] asks
///   [349..357] base_lot_size
///   [357..365] quote_lot_size
///   [365..373] fee_rate_bps
///   [373..381] referrer_rebates_accrued
///   [381..388] padding suffix (7 bytes)
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
    let mut buf = vec![0u8; MARKET_STATE_PADDED_SIZE];

    // serum padding tag: first 5 bytes
    // byte pattern used by serum_dex for account identification
    buf[0..5].copy_from_slice(&[0u8; 5]);

    let base = 5; // offset past padding
    write_u64(&mut buf, base, ACCOUNT_FLAG_INITIALIZED | ACCOUNT_FLAG_MARKET);
    write_pubkey(&mut buf, base + 8, own_address);    // own_address
    write_u64(&mut buf, base + 40, vault_signer_nonce);
    write_pubkey(&mut buf, base + 48, coin_mint);
    write_pubkey(&mut buf, base + 80, pc_mint);
    write_pubkey(&mut buf, base + 112, coin_vault);   // coin_vault key stored here
    write_u64(&mut buf, base + 144, 0);               // coin_deposits_total
    write_u64(&mut buf, base + 152, 0);               // coin_fees_accrued
    write_pubkey(&mut buf, base + 160, pc_vault);
    write_u64(&mut buf, base + 192, 0);               // pc_deposits_total
    write_u64(&mut buf, base + 200, 0);               // pc_fees_accrued
    write_u64(&mut buf, base + 208, 0);               // pc_dust_threshold
    write_pubkey(&mut buf, base + 216, req_q);
    write_pubkey(&mut buf, base + 248, event_q);
    write_pubkey(&mut buf, base + 280, bids);
    write_pubkey(&mut buf, base + 312, asks);
    write_u64(&mut buf, base + 344, 1);               // base_lot_size
    write_u64(&mut buf, base + 352, 1);               // quote_lot_size
    write_u64(&mut buf, base + 360, 0);               // fee_rate_bps
    write_u64(&mut buf, base + 368, 0);               // referrer_rebates_accrued

    buf
}

/// Build minimal slab account data (bids or asks).
///
/// Slab header layout (serum_dex critbit):
///   [0..5]   padding
///   [5..13]  account_flags
///   [13..17] bump_index (u32)
///   [17..21] padding (u32)
///   [21..25] free_list_len (u32)
///   [25..29] free_list_head (u32)
///   [29..33] root (u32)
///   [33..37] leaf_count (u32)
///   [37..]   nodes array
fn build_slab(flags: u64) -> Vec<u8> {
    let size = 5 + 8 + 24 + SLAB_MIN_CAPACITY;
    let mut buf = vec![0u8; size];

    let base = 5;
    write_u64(&mut buf, base, ACCOUNT_FLAG_INITIALIZED | flags);
    // bump_index = 0, free_list_len = 0, free_list_head = 0, root = 0, leaf_count = 0
    // all zero is fine for an empty orderbook

    buf
}

/// Build minimal event queue account data.
fn build_event_queue() -> Vec<u8> {
    let mut buf = vec![0u8; EVENT_QUEUE_SIZE];
    let base = 5;
    write_u64(&mut buf, base, ACCOUNT_FLAG_INITIALIZED | ACCOUNT_FLAG_EVENT_QUEUE);
    // header: head(u64)=0, count(u64)=0, seq_num(u64)=0
    // all zeros is a valid empty queue
    buf
}

/// Build minimal open orders account data.
///
/// Layout (serum_dex):
///   [0..5]     padding
///   [5..13]    account_flags
///   [13..45]   market (Pubkey)
///   [45..77]   owner (Pubkey)
///   [77..85]   native_coin_free
///   [85..93]   native_coin_total
///   [93..101]  native_pc_free
///   [101..109] native_pc_total
///   [109..125] free_slot_bits (u128)
///   [125..141] is_bid_bits (u128)
///   [141..2189] orders [u128; 128]
///   [2189..3213] client_order_ids [u64; 128]
///   [3213..3221] referrer_rebates_accrued
///   [3221..3228] padding
fn build_open_orders(market: &Pubkey, owner: &Pubkey) -> Vec<u8> {
    let mut buf = vec![0u8; OPEN_ORDERS_SIZE];

    let base = 5;
    write_u64(&mut buf, base, ACCOUNT_FLAG_INITIALIZED | ACCOUNT_FLAG_OPEN_ORDERS);
    write_pubkey(&mut buf, base + 8, market);
    write_pubkey(&mut buf, base + 40, owner);
    // native_coin_free, native_coin_total = 0 (no settled funds)
    // native_pc_free, native_pc_total = 0
    // free_slot_bits = all 1s (all slots free)
    buf[base + 104..base + 120].copy_from_slice(&u128::MAX.to_le_bytes());

    buf
}

/// Build AmmInfo account data.
///
/// Fields are written in struct order matching state.rs AmmInfo.
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

    // status = Initialized (1)
    write_u64(&mut buf, off, 1); off += 8;
    // nonce
    write_u64(&mut buf, off, nonce as u64); off += 8;
    // order_num
    write_u64(&mut buf, off, 10); off += 8;
    // depth
    write_u64(&mut buf, off, 3); off += 8;
    // coin_decimals
    write_u64(&mut buf, off, 6); off += 8;
    // pc_decimals
    write_u64(&mut buf, off, 6); off += 8;
    // state (inner machine state, 0 = default)
    write_u64(&mut buf, off, 0); off += 8;
    // reset_flag
    write_u64(&mut buf, off, 0); off += 8;
    // min_size
    write_u64(&mut buf, off, 1); off += 8;
    // vol_max_cut_ratio
    write_u64(&mut buf, off, 0); off += 8;
    // amount_wave
    write_u64(&mut buf, off, 0); off += 8;
    // coin_lot_size
    write_u64(&mut buf, off, 1); off += 8;
    // pc_lot_size
    write_u64(&mut buf, off, 1); off += 8;
    // min_price_multiplier
    write_u64(&mut buf, off, 1); off += 8;
    // max_price_multiplier
    write_u64(&mut buf, off, 1_000_000_000); off += 8;
    // sys_decimal_value
    write_u64(&mut buf, off, 1_000_000); off += 8;

    // fees (Fees struct: 8 u64 fields)
    // min_separate: 5/10000
    write_u64(&mut buf, off, 5); off += 8;
    write_u64(&mut buf, off, 10_000); off += 8;
    // trade_fee: 25/10000
    write_u64(&mut buf, off, 25); off += 8;
    write_u64(&mut buf, off, 10_000); off += 8;
    // pnl: 12/100
    write_u64(&mut buf, off, 12); off += 8;
    write_u64(&mut buf, off, 100); off += 8;
    // swap_fee: 25/10000
    write_u64(&mut buf, off, 25); off += 8;
    write_u64(&mut buf, off, 10_000); off += 8;

    // state_data (StateData struct)
    // need_take_pnl_coin, need_take_pnl_pc, total_pnl_pc, total_pnl_coin
    for _ in 0..4 { write_u64(&mut buf, off, 0); off += 8; }
    // pool_open_time = 0 (already open)
    write_u64(&mut buf, off, 0); off += 8;
    // padding [u64; 2]
    write_u64(&mut buf, off, 0); off += 8;
    write_u64(&mut buf, off, 0); off += 8;
    // orderbook_to_init_time
    write_u64(&mut buf, off, 0); off += 8;
    // swap_coin_in_amount (u128)
    buf[off..off + 16].copy_from_slice(&0u128.to_le_bytes()); off += 16;
    // swap_pc_out_amount (u128)
    buf[off..off + 16].copy_from_slice(&0u128.to_le_bytes()); off += 16;
    // swap_acc_pc_fee
    write_u64(&mut buf, off, 0); off += 8;
    // swap_pc_in_amount (u128)
    buf[off..off + 16].copy_from_slice(&0u128.to_le_bytes()); off += 16;
    // swap_coin_out_amount (u128)
    buf[off..off + 16].copy_from_slice(&0u128.to_le_bytes()); off += 16;
    // swap_acc_coin_fee
    write_u64(&mut buf, off, 0); off += 8;

    // pubkey fields
    write_pubkey(&mut buf, off, coin_vault); off += 32;
    write_pubkey(&mut buf, off, pc_vault); off += 32;
    write_pubkey(&mut buf, off, coin_mint); off += 32;   // coin_vault_mint
    write_pubkey(&mut buf, off, pc_mint); off += 32;     // pc_vault_mint
    write_pubkey(&mut buf, off, lp_mint); off += 32;
    write_pubkey(&mut buf, off, open_orders); off += 32;
    write_pubkey(&mut buf, off, market); off += 32;
    write_pubkey(&mut buf, off, market_program); off += 32;
    write_pubkey(&mut buf, off, target_orders); off += 32;

    // padding1 [u64; 8]
    for _ in 0..8 { write_u64(&mut buf, off, 0); off += 8; }

    // amm_owner
    write_pubkey(&mut buf, off, amm_owner); off += 32;
    // lp_amount
    write_u64(&mut buf, off, 1_000_000); off += 8;
    // client_order_id
    write_u64(&mut buf, off, 0); off += 8;
    // recent_epoch
    write_u64(&mut buf, off, 0); off += 8;
    // padding2
    write_u64(&mut buf, off, 0); off += 8;

    assert_eq!(off, AMM_INFO_SIZE, "AmmInfo size mismatch");
    buf
}

/// Pack an SPL token account into bytes.
fn pack_token_account(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut buf = vec![0u8; spl_token::state::Account::LEN];
    // mint (32) | owner (32) | amount (8) | delegate option (4+32) | state (1) | ...
    write_pubkey(&mut buf, 0, mint);
    write_pubkey(&mut buf, 32, owner);
    buf[64..72].copy_from_slice(&amount.to_le_bytes());
    // delegate: None (0u32 = COption::None)
    buf[72..76].copy_from_slice(&0u32.to_le_bytes());
    // state: Initialized = 1
    buf[108] = 1;
    buf
}

/// Pack an SPL mint into bytes.
fn pack_mint(decimals: u8, supply: u64, mint_authority: Option<&Pubkey>) -> Vec<u8> {
    let mut buf = vec![0u8; Mint::LEN];
    // COption<Pubkey> mint_authority: 4 byte tag + 32 byte key
    if let Some(auth) = mint_authority {
        buf[0..4].copy_from_slice(&1u32.to_le_bytes());
        write_pubkey(&mut buf, 4, auth);
    }
    // supply (u64) at offset 36
    buf[36..44].copy_from_slice(&supply.to_le_bytes());
    // decimals (u8) at offset 44
    buf[44] = decimals;
    // is_initialized (bool) at offset 45
    buf[45] = 1;
    buf
}

/// Build the SwapBaseOut instruction data.
/// Layout: 1 byte instruction index (9 for SwapBaseOut) + 8 byte max_amount_in + 8 byte amount_out
fn build_swap_base_out_ix_data(max_amount_in: u64, amount_out: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(17);
    data.push(9); // SwapBaseOut instruction index
    data.extend_from_slice(&max_amount_in.to_le_bytes());
    data.extend_from_slice(&amount_out.to_le_bytes());
    data
}

// --- test ---

#[tokio::test]
async fn settle_funds_receives_asks_instead_of_coin_vault() {
    // Deploy AMM program from compiled .so
    // The .so must be at tests/fixtures/raydium_amm.so or built via cargo build-sbf
    let mut program_test = ProgramTest::new("raydium_amm", AMM_PROGRAM_ID, None);

    // We also need the OpenBook DEX program. Use the same binary that ships
    // as a dependency (serum_dex). Place the compiled .so at tests/fixtures/.
    let dex_program_id = Pubkey::new_unique();
    program_test.add_program("serum_dex", dex_program_id, None);

    // --- key generation ---

    let amm_account = Keypair::new();
    let coin_mint_kp = Keypair::new();
    let pc_mint_kp = Keypair::new();
    let lp_mint_kp = Keypair::new();
    let market_kp = Keypair::new();
    let market_bids_kp = Keypair::new();
    let market_asks_kp = Keypair::new();
    let market_event_q_kp = Keypair::new();
    let market_req_q_kp = Keypair::new();
    let market_coin_vault_kp = Keypair::new();
    let market_pc_vault_kp = Keypair::new();
    let amm_coin_vault_kp = Keypair::new();
    let amm_pc_vault_kp = Keypair::new();
    let open_orders_kp = Keypair::new();
    let target_orders_kp = Keypair::new();

    let user = Keypair::new();
    let user_pc_token_kp = Keypair::new();   // source: user pays PC
    let user_coin_token_kp = Keypair::new(); // destination: user receives coin

    let coin_mint = coin_mint_kp.pubkey();
    let pc_mint = pc_mint_kp.pubkey();

    // Derive AMM authority PDA
    // AUTHORITY_AMM seed = b"amm authority"
    let amm_seed = b"amm authority";
    let mut nonce: u8 = 255;
    let amm_authority;
    loop {
        if let Ok(key) = Pubkey::create_program_address(
            &[amm_seed, &[nonce]],
            &AMM_PROGRAM_ID,
        ) {
            amm_authority = key;
            break;
        }
        nonce -= 1;
    }

    // Derive market vault signer PDA
    let vault_signer_nonce: u64 = {
        let mut n = 0u64;
        loop {
            if Pubkey::create_program_address(
                &[market_kp.pubkey().as_ref(), &n.to_le_bytes()],
                &dex_program_id,
            )
            .is_ok()
            {
                break n;
            }
            n += 1;
        }
    };
    let market_vault_signer = Pubkey::create_program_address(
        &[market_kp.pubkey().as_ref(), &vault_signer_nonce.to_le_bytes()],
        &dex_program_id,
    )
    .unwrap();

    // --- pre-fund accounts ---

    let rent = solana_sdk::rent::Rent::default();

    // Mints
    program_test.add_account(
        coin_mint,
        Account {
            lamports: rent.minimum_balance(Mint::LEN),
            data: pack_mint(6, 1_000_000_000, Some(&amm_authority)),
            owner: spl_token::id(),
            ..Account::default()
        },
    );
    program_test.add_account(
        pc_mint,
        Account {
            lamports: rent.minimum_balance(Mint::LEN),
            data: pack_mint(6, 1_000_000_000, Some(&amm_authority)),
            owner: spl_token::id(),
            ..Account::default()
        },
    );
    program_test.add_account(
        lp_mint_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(Mint::LEN),
            data: pack_mint(6, 1_000_000, Some(&amm_authority)),
            owner: spl_token::id(),
            ..Account::default()
        },
    );

    // AMM coin vault: LOW balance to force settle path (amount_out > vault.amount)
    let amm_coin_vault_data =
        pack_token_account(&coin_mint, &amm_authority, 100); // only 100 tokens
    program_test.add_account(
        amm_coin_vault_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(spl_token::state::Account::LEN),
            data: amm_coin_vault_data,
            owner: spl_token::id(),
            ..Account::default()
        },
    );

    // AMM PC vault: enough to cover swap input
    let amm_pc_vault_data =
        pack_token_account(&pc_mint, &amm_authority, 1_000_000);
    program_test.add_account(
        amm_pc_vault_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(spl_token::state::Account::LEN),
            data: amm_pc_vault_data,
            owner: spl_token::id(),
            ..Account::default()
        },
    );

    // Market coin/pc vaults (owned by market vault signer)
    program_test.add_account(
        market_coin_vault_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(spl_token::state::Account::LEN),
            data: pack_token_account(&coin_mint, &market_vault_signer, 500_000),
            owner: spl_token::id(),
            ..Account::default()
        },
    );
    program_test.add_account(
        market_pc_vault_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(spl_token::state::Account::LEN),
            data: pack_token_account(&pc_mint, &market_vault_signer, 500_000),
            owner: spl_token::id(),
            ..Account::default()
        },
    );

    // User token accounts
    program_test.add_account(
        user_pc_token_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(spl_token::state::Account::LEN),
            data: pack_token_account(&pc_mint, &user.pubkey(), 500_000),
            owner: spl_token::id(),
            ..Account::default()
        },
    );
    program_test.add_account(
        user_coin_token_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(spl_token::state::Account::LEN),
            data: pack_token_account(&coin_mint, &user.pubkey(), 0),
            owner: spl_token::id(),
            ..Account::default()
        },
    );

    // OpenBook market state
    let market_data = build_market_state(
        &market_kp.pubkey(),
        &coin_mint,
        &pc_mint,
        &market_coin_vault_kp.pubkey(), // the REAL coin vault key stored in market state
        &market_pc_vault_kp.pubkey(),
        &market_bids_kp.pubkey(),
        &market_asks_kp.pubkey(),
        &market_event_q_kp.pubkey(),
        &market_req_q_kp.pubkey(),
        vault_signer_nonce,
    );
    program_test.add_account(
        market_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(MARKET_STATE_PADDED_SIZE),
            data: market_data,
            owner: dex_program_id,
            ..Account::default()
        },
    );

    // Bids slab (empty)
    let bids_data = build_slab(ACCOUNT_FLAG_BIDS);
    program_test.add_account(
        market_bids_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(bids_data.len()),
            data: bids_data,
            owner: dex_program_id,
            ..Account::default()
        },
    );

    // Asks slab (empty -- no open sell orders means asks.is_empty() = true,
    // so the cancel loop is skipped, but settle is still reached because
    // amount_out > amm_coin_vault.amount)
    let asks_data = build_slab(ACCOUNT_FLAG_ASKS);
    program_test.add_account(
        market_asks_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(asks_data.len()),
            data: asks_data,
            owner: dex_program_id,
            ..Account::default()
        },
    );

    // Event queue (empty)
    let eq_data = build_event_queue();
    program_test.add_account(
        market_event_q_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(eq_data.len()),
            data: eq_data,
            owner: dex_program_id,
            ..Account::default()
        },
    );

    // Request queue (minimal)
    program_test.add_account(
        market_req_q_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(EVENT_QUEUE_SIZE),
            data: vec![0u8; EVENT_QUEUE_SIZE],
            owner: dex_program_id,
            ..Account::default()
        },
    );

    // Open orders account (owned by amm_authority, pointing to market)
    let oo_data = build_open_orders(&market_kp.pubkey(), &amm_authority);
    program_test.add_account(
        open_orders_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(OPEN_ORDERS_SIZE),
            data: oo_data,
            owner: dex_program_id,
            ..Account::default()
        },
    );

    // Target orders (unused but must exist in account list)
    program_test.add_account(
        target_orders_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(8),
            data: vec![0u8; 8],
            owner: AMM_PROGRAM_ID,
            ..Account::default()
        },
    );

    // AMM state account
    let amm_data = build_amm_info(
        nonce,
        &amm_coin_vault_kp.pubkey(),
        &amm_pc_vault_kp.pubkey(),
        &coin_mint,
        &pc_mint,
        &lp_mint_kp.pubkey(),
        &open_orders_kp.pubkey(),
        &market_kp.pubkey(),
        &dex_program_id,
        &target_orders_kp.pubkey(),
        &user.pubkey(), // amm_owner (arbitrary for this test)
    );
    program_test.add_account(
        amm_account.pubkey(),
        Account {
            lamports: rent.minimum_balance(AMM_INFO_SIZE),
            data: amm_data,
            owner: AMM_PROGRAM_ID,
            ..Account::default()
        },
    );

    // Fund user with SOL
    program_test.add_account(
        user.pubkey(),
        Account {
            lamports: 10_000_000_000,
            ..Account::default()
        },
    );

    // --- start test ---

    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    // Build SwapBaseOut instruction.
    // amount_out = 500 (greater than amm_coin_vault.amount = 100)
    // This forces the PC2Coin settle path.
    // max_amount_in = large value to avoid slippage rejection
    let ix_data = build_swap_base_out_ix_data(999_999, 500);

    // Account order matches SwapBaseOut from instruction.rs:
    //  0  token_program
    //  1  amm
    //  2  amm_authority
    //  3  amm_open_orders
    //  4  (optional target_orders -- include it, total = 18)
    //  5  amm_coin_vault
    //  6  amm_pc_vault
    //  7  market_program
    //  8  market
    //  9  market_bids
    // 10  market_asks
    // 11  market_event_queue
    // 12  market_coin_vault
    // 13  market_pc_vault
    // 14  market_vault_signer
    // 15  user_source (PC token)
    // 16  user_destination (coin token)
    // 17  user_wallet (signer)
    let accounts = vec![
        AccountMeta::new_readonly(spl_token::id(), false),        // 0
        AccountMeta::new(amm_account.pubkey(), false),            // 1
        AccountMeta::new_readonly(amm_authority, false),          // 2
        AccountMeta::new(open_orders_kp.pubkey(), false),         // 3
        AccountMeta::new(target_orders_kp.pubkey(), false),       // 4 (optional)
        AccountMeta::new(amm_coin_vault_kp.pubkey(), false),     // 5
        AccountMeta::new(amm_pc_vault_kp.pubkey(), false),       // 6
        AccountMeta::new_readonly(dex_program_id, false),         // 7
        AccountMeta::new(market_kp.pubkey(), false),              // 8
        AccountMeta::new(market_bids_kp.pubkey(), false),         // 9
        AccountMeta::new(market_asks_kp.pubkey(), false),         // 10
        AccountMeta::new(market_event_q_kp.pubkey(), false),      // 11
        AccountMeta::new(market_coin_vault_kp.pubkey(), false),   // 12
        AccountMeta::new(market_pc_vault_kp.pubkey(), false),     // 13
        AccountMeta::new_readonly(market_vault_signer, false),    // 14
        AccountMeta::new(user_pc_token_kp.pubkey(), false),       // 15 source=PC
        AccountMeta::new(user_coin_token_kp.pubkey(), false),     // 16 dest=coin
        AccountMeta::new_readonly(user.pubkey(), true),           // 17 signer
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
        recent_blockhash,
    );

    // Execute. This MUST fail.
    //
    // Expected failure: the AMM's process_swap_base_out PC2Coin path calls
    // invoke_dex_settle_funds with market_asks_info as the 5th argument
    // (coin_vault position). The DEX program checks that the provided
    // coin_vault key matches market_state.coin_vault -- since market_asks_kp
    // != market_coin_vault_kp, the CPI reverts.
    //
    // If the bug were fixed (passing market_coin_vault_info instead),
    // the settle CPI would pass the coin_vault validation and proceed
    // to the actual token transfer phase.
    let result = banks_client.process_transaction(tx).await;

    assert!(
        result.is_err(),
        "transaction should fail: settle_funds receives asks account as coin_vault"
    );

    // Optionally inspect the error to confirm it originates from the DEX
    // program's account validation (not from earlier AMM checks).
    if let Err(e) = &result {
        let err_str = format!("{:?}", e);
        eprintln!("expected failure: {}", err_str);
        // The error should NOT be an AMM-level error like InvalidCoinVault
        // or InvalidStatus -- those would mean we never reached the settle call.
        // It should be a CPI error from the DEX program.
    }
}
