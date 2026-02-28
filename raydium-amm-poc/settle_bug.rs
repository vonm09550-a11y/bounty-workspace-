// program/tests/settle_bug.rs
//
// Integration test: process_swap_base_out PC2Coin settle path passes
// market_asks_info where market_coin_vault_info is expected.
//
// Requires: solana-program-test in [dev-dependencies]
// Run:      cargo test-sbf --test settle_bug

use solana_program::program_pack::Pack;
use solana_program_test::*;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use spl_token::state::Mint;

// --- constants ---

const AMM_PROGRAM_ID: Pubkey = solana_sdk::pubkey!("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8");

// AmmInfo: 16 u64s (128) + Fees (64) + StateData (144) + 9 Pubkeys (288)
//        + padding1 [u64;8] (64) + amm_owner (32) + 4 u64s (32) = 752
const AMM_INFO_SIZE: usize = 752;

// MarketState inner = 47 u64s = 376 bytes
// Total = 5 (b"serum") + 376 + 7 (b"padding") = 388
const MARKET_STATE_PADDED_SIZE: usize = 388;

// OpenOrders inner = 3216 bytes
// Total = 5 + 3216 + 7 = 3228
const OPEN_ORDERS_SIZE: usize = 3228;

// Slab: 5 (serum) + 8 (OrderBookStateHeader: account_flags) + 32 (SlabHeader) + N*72 (AnyNode) + 7 (padding)
// For N=4: 5 + 8 + 32 + 288 + 7 = 340
const SLAB_NODE_COUNT: usize = 4;
const SLAB_SIZE: usize = 5 + 8 + 32 + SLAB_NODE_COUNT * 72 + 7;

// Event queue: 5 (serum) + 32 (EventQueueHeader) + N*88 (Event) + 7 (padding)
// Minimal empty queue: 5 + 32 + 0 + 7 = 44
const EVENT_QUEUE_SIZE: usize = 44;

// serum_dex account flags (u64 bitfield) -- from openbook-dex AccountFlag enum
const ACCOUNT_FLAG_INITIALIZED: u64 = 1 << 0;  // 1
const ACCOUNT_FLAG_MARKET: u64 = 1 << 1;        // 2
const ACCOUNT_FLAG_OPEN_ORDERS: u64 = 1 << 2;   // 4
const ACCOUNT_FLAG_REQUEST_QUEUE: u64 = 1 << 3;  // 8
const ACCOUNT_FLAG_EVENT_QUEUE: u64 = 1 << 4;   // 16
const ACCOUNT_FLAG_BIDS: u64 = 1 << 5;          // 32
const ACCOUNT_FLAG_ASKS: u64 = 1 << 6;          // 64

// Serum account padding constants
const SERUM_HEAD: &[u8; 5] = b"serum";
const SERUM_TAIL: &[u8; 7] = b"padding";

// --- helpers ---

fn write_u64(buf: &mut [u8], offset: usize, val: u64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

fn write_pubkey(buf: &mut [u8], offset: usize, key: &Pubkey) {
    buf[offset..offset + 32].copy_from_slice(key.as_ref());
}

/// Build OpenBook DEX MarketState account data.
///
/// Inner layout (47 u64s = 376 bytes, all fields u64 LE, Pubkeys as [u64;4]):
///   account_flags, own_address(4), vault_signer_nonce, coin_mint(4), pc_mint(4),
///   coin_vault(4), coin_deposits_total, coin_fees_accrued, pc_vault(4),
///   pc_deposits_total, pc_fees_accrued, pc_dust_threshold, req_q(4), event_q(4),
///   bids(4), asks(4), base_lot_size, quote_lot_size, fee_rate_bps,
///   referrer_rebates_accrued
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

    buf[0..5].copy_from_slice(SERUM_HEAD);
    buf[MARKET_STATE_PADDED_SIZE - 7..].copy_from_slice(SERUM_TAIL);

    let b = 5; // base offset past serum header
    write_u64(&mut buf, b, ACCOUNT_FLAG_INITIALIZED | ACCOUNT_FLAG_MARKET);
    write_pubkey(&mut buf, b + 8, own_address);
    write_u64(&mut buf, b + 40, vault_signer_nonce);
    write_pubkey(&mut buf, b + 48, coin_mint);
    write_pubkey(&mut buf, b + 80, pc_mint);
    write_pubkey(&mut buf, b + 112, coin_vault);
    write_u64(&mut buf, b + 144, 0); // coin_deposits_total
    write_u64(&mut buf, b + 152, 0); // coin_fees_accrued
    write_pubkey(&mut buf, b + 160, pc_vault);
    write_u64(&mut buf, b + 192, 0); // pc_deposits_total
    write_u64(&mut buf, b + 200, 0); // pc_fees_accrued
    write_u64(&mut buf, b + 208, 0); // pc_dust_threshold
    write_pubkey(&mut buf, b + 216, req_q);
    write_pubkey(&mut buf, b + 248, event_q);
    write_pubkey(&mut buf, b + 280, bids);
    write_pubkey(&mut buf, b + 312, asks);
    write_u64(&mut buf, b + 344, 1); // base_lot_size
    write_u64(&mut buf, b + 352, 1); // quote_lot_size
    write_u64(&mut buf, b + 360, 0); // fee_rate_bps
    write_u64(&mut buf, b + 368, 0); // referrer_rebates_accrued

    buf
}

/// Build slab account data (bids or asks).
///
/// Layout: serum(5) + [account_flags(8) + SlabHeader(32) + nodes(N*72)] + padding(7)
///
/// SlabHeader: bump_index(u32) + unused(u32) + free_list_len(u32) +
///             free_list_head(u32) + root(u32) + leaf_count(u32) + pad(u64)
fn build_slab(flags: u64) -> Vec<u8> {
    let mut buf = vec![0u8; SLAB_SIZE];

    buf[0..5].copy_from_slice(SERUM_HEAD);
    buf[SLAB_SIZE - 7..].copy_from_slice(SERUM_TAIL);

    let b = 5;
    write_u64(&mut buf, b, ACCOUNT_FLAG_INITIALIZED | flags);
    // SlabHeader starts at b+8, all zeros = empty orderbook
    // bump_index=0, free_list_len=0, free_list_head=0, root=0, leaf_count=0

    buf
}

/// Build event queue account data.
///
/// Layout: serum(5) + [account_flags(8) + head(u64) + count(u64) + seq_num(u64) + events...] + padding(7)
fn build_event_queue() -> Vec<u8> {
    let mut buf = vec![0u8; EVENT_QUEUE_SIZE];

    buf[0..5].copy_from_slice(SERUM_HEAD);
    buf[EVENT_QUEUE_SIZE - 7..].copy_from_slice(SERUM_TAIL);

    let b = 5;
    write_u64(&mut buf, b, ACCOUNT_FLAG_INITIALIZED | ACCOUNT_FLAG_EVENT_QUEUE);
    // head=0, count=0, seq_num=0 -- all zeros, valid empty queue

    buf
}

/// Build open orders account data.
///
/// Inner layout (3216 bytes):
///   account_flags(8), market([u64;4]=32), owner([u64;4]=32),
///   native_coin_free(8), native_coin_total(8), native_pc_free(8), native_pc_total(8),
///   free_slot_bits(u128=16), is_bid_bits(u128=16),
///   orders([u128;128]=2048), client_order_ids([u64;128]=1024),
///   referrer_rebates_accrued(8)
fn build_open_orders(market: &Pubkey, owner: &Pubkey) -> Vec<u8> {
    let mut buf = vec![0u8; OPEN_ORDERS_SIZE];

    buf[0..5].copy_from_slice(SERUM_HEAD);
    buf[OPEN_ORDERS_SIZE - 7..].copy_from_slice(SERUM_TAIL);

    let b = 5;
    write_u64(&mut buf, b, ACCOUNT_FLAG_INITIALIZED | ACCOUNT_FLAG_OPEN_ORDERS);
    write_pubkey(&mut buf, b + 8, market);
    write_pubkey(&mut buf, b + 40, owner);
    // native_coin_free=0, native_coin_total=1000 (coins locked in open orders)
    // This makes total_coin = vault(100) + serum(1000) = 1100
    // So amount_out(500) < total_coin(1100) passes InsufficientFunds check
    // But amount_out(500) > vault(100) triggers settle path
    write_u64(&mut buf, b + 80, 1000); // native_coin_total
    // native_pc_free=0, native_pc_total=0
    // free_slot_bits = all 1s (all slots free = no open orders)
    buf[b + 104..b + 120].copy_from_slice(&u128::MAX.to_le_bytes());
    // is_bid_bits = 0, orders = 0, client_order_ids = 0, referrer_rebates = 0

    buf
}

/// Build AmmInfo account data.
///
/// Struct is #[repr(C, packed)] so no alignment padding.
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

    // 16 u64 fields
    write_u64(&mut buf, off, 1); off += 8;                   // status = Initialized
    write_u64(&mut buf, off, nonce as u64); off += 8;         // nonce
    write_u64(&mut buf, off, 10); off += 8;                   // order_num
    write_u64(&mut buf, off, 3); off += 8;                    // depth
    write_u64(&mut buf, off, 6); off += 8;                    // coin_decimals
    write_u64(&mut buf, off, 6); off += 8;                    // pc_decimals
    write_u64(&mut buf, off, 0); off += 8;                    // state
    write_u64(&mut buf, off, 0); off += 8;                    // reset_flag
    write_u64(&mut buf, off, 1); off += 8;                    // min_size
    write_u64(&mut buf, off, 0); off += 8;                    // vol_max_cut_ratio
    write_u64(&mut buf, off, 0); off += 8;                    // amount_wave
    write_u64(&mut buf, off, 1); off += 8;                    // coin_lot_size
    write_u64(&mut buf, off, 1); off += 8;                    // pc_lot_size
    write_u64(&mut buf, off, 1); off += 8;                    // min_price_multiplier
    write_u64(&mut buf, off, 1_000_000_000); off += 8;        // max_price_multiplier
    write_u64(&mut buf, off, 1_000_000); off += 8;            // sys_decimal_value

    // Fees (8 u64s = 64 bytes)
    write_u64(&mut buf, off, 5); off += 8;                    // min_separate_numerator
    write_u64(&mut buf, off, 10_000); off += 8;               // min_separate_denominator
    write_u64(&mut buf, off, 25); off += 8;                   // trade_fee_numerator
    write_u64(&mut buf, off, 10_000); off += 8;               // trade_fee_denominator
    write_u64(&mut buf, off, 12); off += 8;                   // pnl_numerator
    write_u64(&mut buf, off, 100); off += 8;                  // pnl_denominator
    write_u64(&mut buf, off, 25); off += 8;                   // swap_fee_numerator
    write_u64(&mut buf, off, 10_000); off += 8;               // swap_fee_denominator

    // StateData (144 bytes)
    write_u64(&mut buf, off, 0); off += 8;                    // need_take_pnl_coin
    write_u64(&mut buf, off, 0); off += 8;                    // need_take_pnl_pc
    write_u64(&mut buf, off, 0); off += 8;                    // total_pnl_pc
    write_u64(&mut buf, off, 0); off += 8;                    // total_pnl_coin
    write_u64(&mut buf, off, 0); off += 8;                    // pool_open_time
    write_u64(&mut buf, off, 0); off += 8;                    // padding[0]
    write_u64(&mut buf, off, 0); off += 8;                    // padding[1]
    write_u64(&mut buf, off, 0); off += 8;                    // orderbook_to_init_time
    buf[off..off + 16].copy_from_slice(&0u128.to_le_bytes()); off += 16; // swap_coin_in_amount
    buf[off..off + 16].copy_from_slice(&0u128.to_le_bytes()); off += 16; // swap_pc_out_amount
    write_u64(&mut buf, off, 0); off += 8;                    // swap_acc_pc_fee
    buf[off..off + 16].copy_from_slice(&0u128.to_le_bytes()); off += 16; // swap_pc_in_amount
    buf[off..off + 16].copy_from_slice(&0u128.to_le_bytes()); off += 16; // swap_coin_out_amount
    write_u64(&mut buf, off, 0); off += 8;                    // swap_acc_coin_fee

    // 9 Pubkeys (288 bytes)
    write_pubkey(&mut buf, off, coin_vault); off += 32;
    write_pubkey(&mut buf, off, pc_vault); off += 32;
    write_pubkey(&mut buf, off, coin_mint); off += 32;        // coin_vault_mint
    write_pubkey(&mut buf, off, pc_mint); off += 32;          // pc_vault_mint
    write_pubkey(&mut buf, off, lp_mint); off += 32;
    write_pubkey(&mut buf, off, open_orders); off += 32;
    write_pubkey(&mut buf, off, market); off += 32;
    write_pubkey(&mut buf, off, market_program); off += 32;
    write_pubkey(&mut buf, off, target_orders); off += 32;

    // padding1 [u64; 8] (64 bytes)
    for _ in 0..8 { write_u64(&mut buf, off, 0); off += 8; }

    // amm_owner + trailing fields (32 bytes)
    write_pubkey(&mut buf, off, amm_owner); off += 32;
    write_u64(&mut buf, off, 1_000_000); off += 8;            // lp_amount
    write_u64(&mut buf, off, 0); off += 8;                    // client_order_id
    write_u64(&mut buf, off, 0); off += 8;                    // recent_epoch
    write_u64(&mut buf, off, 0); off += 8;                    // padding2

    assert_eq!(off, AMM_INFO_SIZE, "AmmInfo size mismatch");
    buf
}

/// Pack an SPL token account into raw bytes.
fn pack_token_account(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut buf = vec![0u8; spl_token::state::Account::LEN];
    write_pubkey(&mut buf, 0, mint);
    write_pubkey(&mut buf, 32, owner);
    buf[64..72].copy_from_slice(&amount.to_le_bytes());
    // delegate: COption::None
    buf[72..76].copy_from_slice(&0u32.to_le_bytes());
    // state: Initialized = 1
    buf[108] = 1;
    buf
}

/// Pack an SPL mint into raw bytes.
fn pack_mint(decimals: u8, supply: u64, mint_authority: Option<&Pubkey>) -> Vec<u8> {
    let mut buf = vec![0u8; Mint::LEN];
    if let Some(auth) = mint_authority {
        buf[0..4].copy_from_slice(&1u32.to_le_bytes()); // COption::Some
        write_pubkey(&mut buf, 4, auth);
    }
    buf[36..44].copy_from_slice(&supply.to_le_bytes());
    buf[44] = decimals;
    buf[45] = 1; // is_initialized
    buf
}

/// Build SwapBaseOut instruction data.
/// Layout: u8(9) + u64(max_amount_in) + u64(amount_out)
fn build_swap_base_out_ix_data(max_amount_in: u64, amount_out: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(17);
    data.push(9);
    data.extend_from_slice(&max_amount_in.to_le_bytes());
    data.extend_from_slice(&amount_out.to_le_bytes());
    data
}

// --- test ---

#[tokio::test]
async fn settle_funds_receives_asks_instead_of_coin_vault() {
    let mut program_test = ProgramTest::new("raydium_amm", AMM_PROGRAM_ID, None);

    let dex_program_id = Pubkey::new_unique();
    program_test.add_program("serum_dex", dex_program_id, None);

    // --- keys ---

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
    let user_pc_token_kp = Keypair::new();
    let user_coin_token_kp = Keypair::new();

    let coin_mint = coin_mint_kp.pubkey();
    let pc_mint = pc_mint_kp.pubkey();

    // Derive AMM authority PDA (seed = b"amm authority")
    let amm_seed = b"amm authority";
    let (amm_authority, nonce) = {
        let mut n: u8 = 255;
        loop {
            if let Ok(key) = Pubkey::create_program_address(&[amm_seed, &[n]], &AMM_PROGRAM_ID) {
                break (key, n);
            }
            n -= 1;
        }
    };

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

    let rent = solana_sdk::rent::Rent::default();

    // --- mints ---

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

    // --- AMM vaults ---

    // coin vault: LOW balance to force settle path (amount_out > vault.amount)
    program_test.add_account(
        amm_coin_vault_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(spl_token::state::Account::LEN),
            data: pack_token_account(&coin_mint, &amm_authority, 100),
            owner: spl_token::id(),
            ..Account::default()
        },
    );
    program_test.add_account(
        amm_pc_vault_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(spl_token::state::Account::LEN),
            data: pack_token_account(&pc_mint, &amm_authority, 1_000_000),
            owner: spl_token::id(),
            ..Account::default()
        },
    );

    // --- market vaults ---

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

    // --- user token accounts ---

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

    // --- DEX accounts ---

    program_test.add_account(
        market_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(MARKET_STATE_PADDED_SIZE),
            data: build_market_state(
                &market_kp.pubkey(),
                &coin_mint,
                &pc_mint,
                &market_coin_vault_kp.pubkey(),
                &market_pc_vault_kp.pubkey(),
                &market_bids_kp.pubkey(),
                &market_asks_kp.pubkey(),
                &market_event_q_kp.pubkey(),
                &market_req_q_kp.pubkey(),
                vault_signer_nonce,
            ),
            owner: dex_program_id,
            ..Account::default()
        },
    );

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

    // Request queue (minimal, same padding pattern)
    let mut rq_data = vec![0u8; EVENT_QUEUE_SIZE];
    rq_data[0..5].copy_from_slice(SERUM_HEAD);
    rq_data[EVENT_QUEUE_SIZE - 7..].copy_from_slice(SERUM_TAIL);
    write_u64(&mut rq_data, 5, ACCOUNT_FLAG_INITIALIZED | ACCOUNT_FLAG_REQUEST_QUEUE);
    program_test.add_account(
        market_req_q_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(rq_data.len()),
            data: rq_data,
            owner: dex_program_id,
            ..Account::default()
        },
    );

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

    // Target orders (unused but required in account list)
    program_test.add_account(
        target_orders_kp.pubkey(),
        Account {
            lamports: rent.minimum_balance(8),
            data: vec![0u8; 8],
            owner: AMM_PROGRAM_ID,
            ..Account::default()
        },
    );

    // --- AMM state ---

    program_test.add_account(
        amm_account.pubkey(),
        Account {
            lamports: rent.minimum_balance(AMM_INFO_SIZE),
            data: build_amm_info(
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
                &user.pubkey(),
            ),
            owner: AMM_PROGRAM_ID,
            ..Account::default()
        },
    );

    // Fund user
    program_test.add_account(
        user.pubkey(),
        Account {
            lamports: 10_000_000_000,
            ..Account::default()
        },
    );

    // --- execute ---

    let (banks_client, payer, recent_blockhash) = program_test.start().await;

    // amount_out=500 > amm_coin_vault.amount=100 => forces PC2Coin settle path
    let ix_data = build_swap_base_out_ix_data(999_999, 500);

    let accounts = vec![
        AccountMeta::new_readonly(spl_token::id(), false),        // 0  token_program
        AccountMeta::new(amm_account.pubkey(), false),            // 1  amm
        AccountMeta::new_readonly(amm_authority, false),          // 2  amm_authority
        AccountMeta::new(open_orders_kp.pubkey(), false),         // 3  open_orders
        AccountMeta::new(target_orders_kp.pubkey(), false),       // 4  target_orders (optional)
        AccountMeta::new(amm_coin_vault_kp.pubkey(), false),     // 5  amm_coin_vault
        AccountMeta::new(amm_pc_vault_kp.pubkey(), false),       // 6  amm_pc_vault
        AccountMeta::new_readonly(dex_program_id, false),         // 7  market_program
        AccountMeta::new(market_kp.pubkey(), false),              // 8  market
        AccountMeta::new(market_bids_kp.pubkey(), false),         // 9  bids
        AccountMeta::new(market_asks_kp.pubkey(), false),         // 10 asks
        AccountMeta::new(market_event_q_kp.pubkey(), false),      // 11 event_queue
        AccountMeta::new(market_coin_vault_kp.pubkey(), false),   // 12 market_coin_vault
        AccountMeta::new(market_pc_vault_kp.pubkey(), false),     // 13 market_pc_vault
        AccountMeta::new_readonly(market_vault_signer, false),    // 14 vault_signer
        AccountMeta::new(user_pc_token_kp.pubkey(), false),       // 15 user_source (PC)
        AccountMeta::new(user_coin_token_kp.pubkey(), false),     // 16 user_dest (coin)
        AccountMeta::new_readonly(user.pubkey(), true),           // 17 user_wallet
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

    // The AMM CPIs into settle_funds passing market_asks as coin_vault.
    // The DEX checks coin_vault key against market_state.coin_vault and rejects.
    // If the bug were fixed (market_coin_vault_info), the CPI would pass
    // account validation and proceed to token transfer.
    let result = banks_client.process_transaction(tx).await;

    assert!(
        result.is_err(),
        "transaction should fail: settle_funds receives asks account as coin_vault"
    );

    if let Err(e) = &result {
        let err_str = format!("{:?}", e);
        eprintln!("expected failure: {}", err_str);
    }
}
