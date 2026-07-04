"""
Phase 8: Realistic backtest of elite trader's BTC strategy.
Trader: 0x2d99fe0f36c1aebd28a1a2c0e82e8ca13c2ea351

Strategy reverse-engineered from fills:
- Long-only BTC with 2x isolated leverage
- Buy during consolidation/dips
- Exit via grid of limit sell orders at incremental price levels (+$25-50 apart)
- Hold weeks until target reached
- Patient macro bull approach

Backtest params:
- Capital: $100
- Fee budget: $5
- Period: 30 days
- Leverage: 2x isolated
- Maker fee: 0.015% (limit orders)
- Taker fee: 0.035% (market orders)
"""
import requests
import json
import time
from datetime import datetime, timedelta
import math

BASE = "https://api.hyperliquid.xyz"

def post_info(payload):
    r = requests.post(f"{BASE}/info", json=payload, timeout=30)
    return r.json()

# Get BTC candles for last 60 days (need more data for context)
now_ms = int(time.time() * 1000)
sixty_days_ago = now_ms - (60 * 24 * 60 * 60 * 1000)

print("=== Fetching BTC price data ===")
candles = post_info({
    "type": "candleSnapshot",
    "req": {
        "coin": "BTC",
        "interval": "1h",
        "startTime": sixty_days_ago,
        "endTime": now_ms
    }
})

print(f"Got {len(candles)} hourly candles")

# Parse candles
prices = []
for c in candles:
    prices.append({
        "time": c["t"],
        "open": float(c["o"]),
        "high": float(c["h"]),
        "low": float(c["l"]),
        "close": float(c["c"]),
        "volume": float(c["v"]),
        "dt": datetime.fromtimestamp(c["t"]/1000),
    })

prices.sort(key=lambda x: x["time"])

# Use last 30 days for backtest, prior 30 for context
thirty_days_ago_ms = now_ms - (30 * 24 * 60 * 60 * 1000)
backtest_prices = [p for p in prices if p["time"] >= thirty_days_ago_ms]
context_prices = [p for p in prices if p["time"] < thirty_days_ago_ms]

print(f"Backtest period: {backtest_prices[0]['dt'].strftime('%Y-%m-%d')} to {backtest_prices[-1]['dt'].strftime('%Y-%m-%d')}")
print(f"BTC range: ${min(p['low'] for p in backtest_prices):,.0f} - ${max(p['high'] for p in backtest_prices):,.0f}")
print(f"Start: ${backtest_prices[0]['open']:,.0f}, End: ${backtest_prices[-1]['close']:,.0f}")

# Also extract the actual trader's fills for the 30-day backtest period
ELITE = "0x2d99fe0f36c1aebd28a1a2c0e82e8ca13c2ea351"
trader_fills = post_info({
    "type": "userFillsByTime",
    "user": ELITE,
    "startTime": thirty_days_ago_ms,
    "endTime": now_ms,
    "aggregateByTime": True
})

btc_trader_fills = [f for f in trader_fills if f.get("coin") == "BTC"]
print(f"\nTrader's actual BTC fills in period: {len(btc_trader_fills)}")
if btc_trader_fills:
    trader_btc_pnl = sum(float(f.get("closedPnl", "0")) for f in btc_trader_fills)
    print(f"Trader's actual BTC PnL in period: ${trader_btc_pnl:,.2f}")

# ==============================================
# BACKTEST ENGINE
# ==============================================

print(f"\n{'='*80}")
print("REALISTIC BACKTEST")
print(f"{'='*80}\n")

# Strategy parameters (derived from trader's behavior)
INITIAL_CAPITAL = 100.0
FEE_BUDGET = 5.0
LEVERAGE = 2
MAKER_FEE = 0.00015  # 0.015%
TAKER_FEE = 0.00035  # 0.035%

# Grid exit: sell in increments of ~$50 apart (scaled from trader's $25 on larger positions)
GRID_STEP = 50  # $50 price increment between sell levels
# The trader uses ~1.1 BTC per exit level on a 170 BTC position
# That's ~0.65% of position per level. We'll use similar proportional sizing.
EXIT_PCT_PER_LEVEL = 0.02  # 2% of position per exit level (scaled for small account)

# Entry signal: Buy when price drops >2% from recent high (trader buys dips)
DIP_THRESHOLD = 0.02  # 2% dip from recent high
LOOKBACK = 48  # 48-hour lookback for local high

# The trader holds for weeks. We'll set a max hold time but let the grid do the work.
MAX_HOLD_HOURS = 30 * 24  # 30 days max hold

class BacktestEngine:
    def __init__(self, capital, leverage, maker_fee, taker_fee, fee_budget):
        self.initial_capital = capital
        self.capital = capital
        self.leverage = leverage
        self.maker_fee = maker_fee
        self.taker_fee = taker_fee
        self.fee_budget = fee_budget
        self.fees_paid = 0.0

        self.position = 0.0  # BTC size
        self.entry_price = 0.0
        self.notional = 0.0
        self.margin = 0.0

        self.trades = []
        self.equity_curve = []
        self.pnl_total = 0.0
        self.wins = 0
        self.losses = 0
        self.grid_sells = []  # pending grid sell orders

    def can_afford_fee(self, notional, is_maker=True):
        fee = notional * (self.maker_fee if is_maker else self.taker_fee)
        return self.fees_paid + fee <= self.fee_budget

    def open_long(self, price, timestamp):
        if self.position > 0:
            return False

        # Size: use full available capital with leverage
        available = self.capital
        notional = available * self.leverage
        fee = notional * self.taker_fee  # market order to enter

        if self.fees_paid + fee > self.fee_budget:
            return False

        size = notional / price
        self.position = size
        self.entry_price = price
        self.notional = notional
        self.margin = available
        self.capital -= available
        self.fees_paid += fee

        # Set up grid exit orders
        self.grid_sells = []
        remaining = size
        level = 1
        while remaining > 0:
            sell_price = price + (GRID_STEP * level)
            sell_size = min(size * EXIT_PCT_PER_LEVEL, remaining)
            if sell_size <= 0:
                break
            self.grid_sells.append({
                "price": sell_price,
                "size": sell_size,
                "filled": False
            })
            remaining -= sell_size
            level += 1

        self.trades.append({
            "type": "BUY",
            "time": timestamp,
            "price": price,
            "size": size,
            "notional": notional,
            "fee": fee,
            "capital_after": self.capital,
        })
        return True

    def check_grid_fills(self, high_price, timestamp):
        fills = []
        for order in self.grid_sells:
            if not order["filled"] and high_price >= order["price"]:
                # Fill the grid order
                order["filled"] = True
                sell_notional = order["size"] * order["price"]
                fee = sell_notional * self.maker_fee  # limit order

                pnl = (order["price"] - self.entry_price) * order["size"]
                pnl_after_fee = pnl - fee

                self.position -= order["size"]
                self.pnl_total += pnl_after_fee
                self.capital += (order["size"] * self.entry_price / self.leverage) + pnl_after_fee
                self.fees_paid += fee

                if pnl_after_fee > 0:
                    self.wins += 1
                else:
                    self.losses += 1

                fills.append({
                    "type": "SELL",
                    "time": timestamp,
                    "price": order["price"],
                    "size": order["size"],
                    "notional": sell_notional,
                    "pnl": pnl,
                    "fee": fee,
                    "pnl_net": pnl_after_fee,
                    "capital_after": self.capital,
                })

        self.trades.extend(fills)
        return fills

    def close_position(self, price, timestamp, reason=""):
        if self.position <= 0:
            return

        notional = self.position * price
        fee = notional * self.taker_fee
        pnl = (price - self.entry_price) * self.position
        pnl_after_fee = pnl - fee

        self.pnl_total += pnl_after_fee
        self.capital += (self.position * self.entry_price / self.leverage) + pnl_after_fee
        self.fees_paid += fee

        if pnl_after_fee > 0:
            self.wins += 1
        else:
            self.losses += 1

        self.trades.append({
            "type": f"CLOSE ({reason})",
            "time": timestamp,
            "price": price,
            "size": self.position,
            "notional": notional,
            "pnl": pnl,
            "fee": fee,
            "pnl_net": pnl_after_fee,
            "capital_after": self.capital,
        })

        self.position = 0
        self.grid_sells = []

    def get_equity(self, current_price):
        if self.position > 0:
            unrealized = (current_price - self.entry_price) * self.position
            return self.capital + (self.position * self.entry_price / self.leverage) + unrealized
        return self.capital

    def liquidation_price(self):
        if self.position <= 0:
            return 0
        # For isolated 2x: liquidation when loss = margin
        # loss = (entry - liq) * size = margin
        # liq = entry - margin/size = entry - (entry/leverage) = entry * (1 - 1/leverage)
        return self.entry_price * (1 - 1 / self.leverage) * 1.005  # 0.5% buffer

# Run backtest
engine = BacktestEngine(INITIAL_CAPITAL, LEVERAGE, MAKER_FEE, TAKER_FEE, FEE_BUDGET)

entry_cooldown = 0
position_open_time = 0

for i, candle in enumerate(backtest_prices):
    current_time = candle["dt"]
    price = candle["close"]
    high = candle["high"]
    low = candle["low"]

    # Record equity
    equity = engine.get_equity(price)
    engine.equity_curve.append({
        "time": current_time.strftime("%Y-%m-%d %H:%M"),
        "price": price,
        "equity": equity,
        "position": engine.position,
    })

    # Check liquidation
    if engine.position > 0:
        liq_price = engine.liquidation_price()
        if low <= liq_price:
            engine.close_position(liq_price, current_time, "LIQUIDATION")
            entry_cooldown = 48
            continue

    # Check grid fills
    if engine.position > 0:
        engine.check_grid_fills(high, current_time)
        position_open_time += 1

    # Entry signal: look for dip
    if engine.position == 0 and entry_cooldown <= 0:
        lookback_start = max(0, i - LOOKBACK)
        recent_high = max(p["high"] for p in backtest_prices[lookback_start:i+1])
        dip_pct = (recent_high - price) / recent_high

        if dip_pct >= DIP_THRESHOLD:
            if engine.can_afford_fee(engine.capital * LEVERAGE, is_maker=False):
                engine.open_long(price, current_time)
                position_open_time = 0

    if entry_cooldown > 0:
        entry_cooldown -= 1

# Close any remaining position at end
if engine.position > 0:
    engine.close_position(backtest_prices[-1]["close"], backtest_prices[-1]["dt"], "END_OF_PERIOD")

# ==============================================
# RESULTS
# ==============================================

print(f"{'='*80}")
print("BACKTEST RESULTS")
print(f"{'='*80}\n")

print(f"Period: {backtest_prices[0]['dt'].strftime('%Y-%m-%d')} to {backtest_prices[-1]['dt'].strftime('%Y-%m-%d')}")
print(f"BTC Price: ${backtest_prices[0]['open']:,.0f} -> ${backtest_prices[-1]['close']:,.0f} ({(backtest_prices[-1]['close']/backtest_prices[0]['open']-1)*100:+.1f}%)")
print()

print(f"Initial Capital:     ${INITIAL_CAPITAL:>10,.2f}")
print(f"Final Equity:        ${engine.get_equity(backtest_prices[-1]['close']):>10,.2f}")
print(f"Total PnL:           ${engine.pnl_total:>10,.2f}")
print(f"Return:              {engine.pnl_total/INITIAL_CAPITAL*100:>9.2f}%")
print(f"Fees Paid:           ${engine.fees_paid:>10,.4f} / ${FEE_BUDGET:.2f} budget")
print()

total_trades = engine.wins + engine.losses
print(f"Total Trades:        {total_trades}")
print(f"Wins:                {engine.wins}")
print(f"Losses:              {engine.losses}")
print(f"Win Rate:            {engine.wins/total_trades*100:.1f}%" if total_trades > 0 else "Win Rate: N/A")
print()

# Equity curve stats
equities = [e["equity"] for e in engine.equity_curve]
peak = equities[0]
max_dd = 0
max_dd_pct = 0
for eq in equities:
    peak = max(peak, eq)
    dd = peak - eq
    dd_pct = dd / peak if peak > 0 else 0
    max_dd = max(max_dd, dd)
    max_dd_pct = max(max_dd_pct, dd_pct)

print(f"Max Drawdown:        ${max_dd:>10,.2f} ({max_dd_pct*100:.1f}%)")
print(f"Peak Equity:         ${max(equities):>10,.2f}")
print(f"Min Equity:          ${min(equities):>10,.2f}")
print()

# Detailed trade log
print(f"\n{'='*80}")
print("TRADE LOG")
print(f"{'='*80}\n")
print(f"{'Time':<20} {'Type':<16} {'Price':>10} {'Size':>12} {'PnL':>10} {'Fee':>8} {'Capital':>10}")
print(f"{'-'*100}")

for t in engine.trades:
    pnl_str = f"${t.get('pnl_net', 0):>8,.2f}" if 'pnl_net' in t else ""
    print(f"{t['time'].strftime('%Y-%m-%d %H:%M') if isinstance(t['time'], datetime) else t['time']:<20} "
          f"{t['type']:<16} ${t['price']:>8,.0f} {t['size']:>11.8f} {pnl_str:>10} "
          f"${t['fee']:>6,.4f} ${t['capital_after']:>8,.2f}")

# Weekly breakdown
print(f"\n{'='*80}")
print("WEEKLY EQUITY")
print(f"{'='*80}\n")

weekly_equity = {}
for e in engine.equity_curve:
    wk = e["time"][:10]
    weekly_equity[wk] = e["equity"]

prev_eq = INITIAL_CAPITAL
print(f"{'Date':<12} {'Equity':>10} {'Change':>10} {'BTC':>10}")
print(f"{'-'*45}")
days = sorted(weekly_equity.keys())
for d in days[::24]:  # Daily snapshot
    eq = weekly_equity[d]
    change = eq - prev_eq
    btc_p = [p for p in backtest_prices if p["dt"].strftime("%Y-%m-%d") == d]
    btc_price = btc_p[0]["close"] if btc_p else 0
    print(f"{d:<12} ${eq:>8,.2f} ${change:>8,.2f} ${btc_price:>8,.0f}")
    prev_eq = eq

# Compare with trader's actual performance
if btc_trader_fills:
    total_trader_pnl = sum(float(f.get("closedPnl", "0")) for f in btc_trader_fills)
    total_trader_vol = sum(float(f.get("sz", "0")) * float(f.get("px", "0")) for f in btc_trader_fills)
    trader_acct = 663966  # from current state

    print(f"\n{'='*80}")
    print("COMPARISON: Our Backtest vs Trader's Actual")
    print(f"{'='*80}\n")
    print(f"{'Metric':<25} {'Our Backtest':>15} {'Trader Actual':>15} {'Ratio':>10}")
    print(f"{'-'*65}")
    print(f"{'Capital':<25} ${INITIAL_CAPITAL:>13,.0f} ${trader_acct:>13,.0f} {INITIAL_CAPITAL/trader_acct:.4f}x")
    print(f"{'PnL':<25} ${engine.pnl_total:>13,.2f} ${total_trader_pnl:>13,.0f}")
    our_roi = engine.pnl_total/INITIAL_CAPITAL*100
    trader_roi = total_trader_pnl/trader_acct*100 if trader_acct > 0 else 0
    print(f"{'ROI':<25} {our_roi:>12.2f}% {trader_roi:>12.2f}%")
    print(f"{'Fees Paid':<25} ${engine.fees_paid:>13,.4f}")

# Save results
results = {
    "trader_address": ELITE,
    "backtest_period": f"{backtest_prices[0]['dt'].strftime('%Y-%m-%d')} to {backtest_prices[-1]['dt'].strftime('%Y-%m-%d')}",
    "initial_capital": INITIAL_CAPITAL,
    "final_equity": engine.get_equity(backtest_prices[-1]["close"]),
    "total_pnl": engine.pnl_total,
    "return_pct": engine.pnl_total / INITIAL_CAPITAL * 100,
    "fees_paid": engine.fees_paid,
    "total_trades": total_trades,
    "wins": engine.wins,
    "losses": engine.losses,
    "win_rate": engine.wins / total_trades * 100 if total_trades > 0 else 0,
    "max_drawdown": max_dd,
    "max_drawdown_pct": max_dd_pct * 100,
    "leverage": LEVERAGE,
    "strategy": "Long-only BTC, 2x isolated leverage, dip-buy + grid-exit",
    "trades": [
        {k: str(v) if isinstance(v, datetime) else v for k, v in t.items()}
        for t in engine.trades
    ],
    "equity_curve": engine.equity_curve,
}

with open("backtest_results.json", "w") as f:
    json.dump(results, f, indent=2, default=str)

print(f"\nResults saved to backtest_results.json")
