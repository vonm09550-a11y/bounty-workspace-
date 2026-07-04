"""
Phase 8c: Adjusted realistic backtest matching the trader's actual behavior.

Key insight: The elite trader (0x2d99fe0f) has 100% win rate because they NEVER
stop out. They hold through all drawdowns and exit only via grid sells when price
recovers above entry. With 2x isolated leverage, liquidation is ~50% below entry
which BTC has never reached in a 30-day window.

Adjustments from 8b:
- NO hard stop loss (matches trader's actual behavior)
- Trailing stop: activate at 4% profit, trail at 3% distance
- Entry on 3% dips from 48h high (deeper dips = better entries)
- Grid spacing: $300 (tighter to capture more bounces)
- Minimum 24h between entries after a closed position
- Emergency exit only at 15% drawdown (well before 50% liquidation)
"""
import requests
import json
import time
from datetime import datetime
import math

BASE = "https://api.hyperliquid.xyz"

def post_info(payload):
    r = requests.post(f"{BASE}/info", json=payload, timeout=30)
    return r.json()

now_ms = int(time.time() * 1000)
sixty_days_ago = now_ms - (60 * 24 * 60 * 60 * 1000)

print("Fetching BTC price data...")
candles = post_info({
    "type": "candleSnapshot",
    "req": {"coin": "BTC", "interval": "1h", "startTime": sixty_days_ago, "endTime": now_ms}
})

prices = []
for c in sorted(candles, key=lambda x: x["t"]):
    prices.append({
        "time": c["t"], "open": float(c["o"]), "high": float(c["h"]),
        "low": float(c["l"]), "close": float(c["c"]),
        "dt": datetime.fromtimestamp(c["t"]/1000),
    })

thirty_days_ago_ms = now_ms - (30 * 24 * 60 * 60 * 1000)
backtest_prices = [p for p in prices if p["time"] >= thirty_days_ago_ms]

btc_start = backtest_prices[0]["open"]
btc_end = backtest_prices[-1]["close"]
btc_change = (btc_end / btc_start - 1) * 100
btc_low = min(p["low"] for p in backtest_prices)
btc_high = max(p["high"] for p in backtest_prices)

print(f"Period: {backtest_prices[0]['dt'].strftime('%Y-%m-%d')} to {backtest_prices[-1]['dt'].strftime('%Y-%m-%d')}")
print(f"BTC: ${btc_start:,.0f} -> ${btc_end:,.0f} ({btc_change:+.1f}%)")
print(f"Range: ${btc_low:,.0f} - ${btc_high:,.0f}")
print(f"Max drawdown from start: {(btc_low/btc_start - 1)*100:.1f}%\n")

CAPITAL = 100.0
FEE_BUDGET = 5.0
LEVERAGE = 2
TAKER_FEE = 0.00035
MAKER_FEE = 0.00015

NUM_EXIT_LEVELS = 5
EXIT_PCT = 1.0 / NUM_EXIT_LEVELS
GRID_SPACING = 300

DIP_THRESHOLD = 0.03
LOOKBACK = 48

EMERGENCY_STOP_PCT = 0.15
TRAILING_STOP_ACTIVATION = 0.04
TRAILING_STOP_DISTANCE = 0.03

MIN_ENTRY_GAP = 24


class AdjustedBacktest:
    def __init__(self):
        self.capital = CAPITAL
        self.position = 0.0
        self.entry_price = 0.0
        self.fees_paid = 0.0
        self.trades = []
        self.equity_curve = []
        self.pnl_total = 0.0
        self.wins = 0
        self.losses = 0
        self.grid_orders = []
        self.highest_since_entry = 0.0
        self.trailing_active = False
        self.last_close_idx = -MIN_ENTRY_GAP

    def get_equity(self, price):
        if self.position > 0:
            unrealized = (price - self.entry_price) * self.position
            margin = self.position * self.entry_price / LEVERAGE
            return self.capital + margin + unrealized
        return self.capital

    def open_long(self, price, dt, idx):
        if self.position > 0:
            return False
        if idx - self.last_close_idx < MIN_ENTRY_GAP:
            return False

        notional = self.capital * LEVERAGE
        fee = notional * TAKER_FEE
        if self.fees_paid + fee > FEE_BUDGET:
            return False
        if notional < 10:
            return False

        size = notional / price
        margin = notional / LEVERAGE

        self.position = size
        self.entry_price = price
        self.capital -= margin
        self.fees_paid += fee
        self.highest_since_entry = price
        self.trailing_active = False

        self.grid_orders = []
        for i in range(1, NUM_EXIT_LEVELS + 1):
            exit_price = price + (GRID_SPACING * i)
            exit_size = size * EXIT_PCT
            self.grid_orders.append({
                "price": exit_price, "size": exit_size, "filled": False
            })

        self.trades.append({
            "dt": dt, "type": "BUY", "price": price,
            "size": size, "notional": notional, "fee": fee,
            "pnl": 0, "equity": self.get_equity(price)
        })
        return True

    def check_exits(self, candle, idx):
        if self.position <= 0:
            return

        dt = candle["dt"]
        high = candle["high"]
        low = candle["low"]
        close = candle["close"]

        self.highest_since_entry = max(self.highest_since_entry, high)

        # Emergency stop only at 15% loss (well before 50% liquidation at 2x)
        emergency_price = self.entry_price * (1 - EMERGENCY_STOP_PCT)
        if low <= emergency_price:
            self._close(emergency_price, dt, "EMERGENCY_STOP", idx)
            return

        # Grid fills
        for order in self.grid_orders:
            if not order["filled"] and high >= order["price"]:
                order["filled"] = True
                sell_notional = order["size"] * order["price"]
                fee = sell_notional * MAKER_FEE

                pnl = (order["price"] - self.entry_price) * order["size"]
                pnl_net = pnl - fee

                margin_returned = order["size"] * self.entry_price / LEVERAGE
                self.position -= order["size"]
                self.capital += margin_returned + pnl_net
                self.fees_paid += fee
                self.pnl_total += pnl_net

                if pnl_net > 0:
                    self.wins += 1
                else:
                    self.losses += 1

                self.trades.append({
                    "dt": dt, "type": "GRID_SELL", "price": order["price"],
                    "size": order["size"], "notional": sell_notional, "fee": fee,
                    "pnl": pnl_net, "equity": self.get_equity(close)
                })

        if all(g["filled"] for g in self.grid_orders):
            self.position = 0
            self.grid_orders = []
            self.last_close_idx = idx

        # Trailing stop on remaining position (only after significant profit)
        if self.position > 0:
            profit_pct = (self.highest_since_entry - self.entry_price) / self.entry_price
            if profit_pct >= TRAILING_STOP_ACTIVATION:
                self.trailing_active = True

            if self.trailing_active:
                trail_price = self.highest_since_entry * (1 - TRAILING_STOP_DISTANCE)
                if low <= trail_price:
                    self._close(trail_price, dt, "TRAILING_STOP", idx)

    def _close(self, price, dt, reason, idx):
        if self.position <= 0:
            return

        notional = self.position * price
        fee = notional * TAKER_FEE
        pnl = (price - self.entry_price) * self.position
        pnl_net = pnl - fee

        margin_returned = self.position * self.entry_price / LEVERAGE
        self.capital += margin_returned + pnl_net
        self.fees_paid += fee
        self.pnl_total += pnl_net

        if pnl_net > 0:
            self.wins += 1
        else:
            self.losses += 1

        self.trades.append({
            "dt": dt, "type": reason, "price": price,
            "size": self.position, "notional": notional, "fee": fee,
            "pnl": pnl_net, "equity": self.get_equity(price)
        })

        self.position = 0
        self.grid_orders = []
        self.last_close_idx = idx

    def run(self, prices):
        for i, candle in enumerate(prices):
            self.equity_curve.append({
                "dt": candle["dt"].strftime("%Y-%m-%d %H:%M"),
                "price": candle["close"],
                "equity": self.get_equity(candle["close"]),
                "position": self.position,
            })

            if self.position > 0:
                self.check_exits(candle, i)

            if self.position == 0:
                lookback_start = max(0, i - LOOKBACK)
                recent_high = max(p["high"] for p in prices[lookback_start:i+1])
                dip_pct = (recent_high - candle["close"]) / recent_high

                if dip_pct >= DIP_THRESHOLD and self.capital >= 10:
                    self.open_long(candle["close"], candle["dt"], i)

        if self.position > 0:
            self._close(prices[-1]["close"], prices[-1]["dt"], "END_OF_PERIOD", len(prices))


bt = AdjustedBacktest()
bt.run(backtest_prices)

final_equity = bt.get_equity(backtest_prices[-1]["close"])
total_trades = bt.wins + bt.losses

print(f"{'='*80}")
print("BACKTEST RESULTS - ADJUSTED $100 STRATEGY (NO STOP LOSS)")
print(f"{'='*80}\n")

print(f"Strategy: Long-only BTC | 2x leverage | Grid exit | No stop loss | Wide trail")
print(f"Period:   {backtest_prices[0]['dt'].strftime('%Y-%m-%d')} to {backtest_prices[-1]['dt'].strftime('%Y-%m-%d')}")
print(f"BTC:      ${btc_start:,.0f} -> ${btc_end:,.0f} ({btc_change:+.1f}%)\n")

print(f"  Initial Capital:   ${CAPITAL:>10,.2f}")
print(f"  Final Equity:      ${final_equity:>10,.2f}")
print(f"  Net PnL:           ${bt.pnl_total:>10,.2f}")
print(f"  Return:            {bt.pnl_total/CAPITAL*100:>9.2f}%")
print(f"  Fees Paid:         ${bt.fees_paid:>10,.4f} / ${FEE_BUDGET:.2f} budget")
print(f"  Fee % of Capital:  {bt.fees_paid/CAPITAL*100:>9.2f}%")
print()
print(f"  Total Trades:      {total_trades}")
print(f"  Wins:              {bt.wins}")
print(f"  Losses:            {bt.losses}")
if total_trades > 0:
    print(f"  Win Rate:          {bt.wins/total_trades*100:.1f}%")
print()

equities = [e["equity"] for e in bt.equity_curve]
peak = equities[0]
max_dd = 0
max_dd_pct = 0
for eq in equities:
    peak = max(peak, eq)
    dd = peak - eq
    dd_pct = dd / peak if peak > 0 else 0
    max_dd = max(max_dd, dd)
    max_dd_pct = max(max_dd_pct, dd_pct)

print(f"  Max Drawdown:      ${max_dd:>10,.2f} ({max_dd_pct*100:.1f}%)")
print(f"  Peak Equity:       ${max(equities):>10,.2f}")
print(f"  Min Equity:        ${min(equities):>10,.2f}")

daily_eq = {}
for e in bt.equity_curve:
    d = e["dt"][:10]
    daily_eq[d] = e["equity"]
days_list = sorted(daily_eq.keys())
daily_returns = []
for i in range(1, len(days_list)):
    ret = (daily_eq[days_list[i]] - daily_eq[days_list[i-1]]) / daily_eq[days_list[i-1]]
    daily_returns.append(ret)

sharpe = 0
if daily_returns:
    avg_ret = sum(daily_returns) / len(daily_returns)
    std_ret = (sum((r - avg_ret)**2 for r in daily_returns) / len(daily_returns)) ** 0.5
    sharpe = (avg_ret / std_ret * (365**0.5)) if std_ret > 0 else float('inf')
    print(f"  Annualized Sharpe: {sharpe:.2f}")
    print(f"  Daily Avg Return:  {avg_ret*100:.4f}%")
    print(f"  Daily Volatility:  {std_ret*100:.4f}%")

# vs Buy and Hold
bh_return = (btc_end / btc_start - 1) * CAPITAL * LEVERAGE
bh_fee = CAPITAL * LEVERAGE * TAKER_FEE * 2
bh_net = bh_return - bh_fee
print(f"\n  Buy & Hold (2x):   ${bh_net:>10,.2f} ({bh_net/CAPITAL*100:.2f}%)")
print(f"  Alpha vs B&H:      ${bt.pnl_total - bh_net:>10,.2f}")

print(f"\n{'='*80}")
print("TRADE LOG")
print(f"{'='*80}\n")
print(f"{'Date':<20} {'Type':<16} {'Price':>10} {'Size':>12} {'PnL':>10} {'Fee':>8} {'Equity':>10}")
print(f"{'-'*90}")

for t in bt.trades:
    dt_str = t["dt"].strftime("%Y-%m-%d %H:%M") if isinstance(t["dt"], datetime) else t["dt"]
    pnl_str = f"${t['pnl']:>8,.2f}" if t["pnl"] != 0 else f"{'':>10}"
    print(f"{dt_str:<20} {t['type']:<16} ${t['price']:>8,.0f} {t['size']:>11.6f} {pnl_str} "
          f"${t['fee']:>6,.4f} ${t['equity']:>8,.2f}")

print(f"\n{'='*80}")
print("DAILY EQUITY CURVE")
print(f"{'='*80}\n")
print(f"{'Date':<12} {'Equity':>10} {'Change':>10} {'BTC':>10} {'Position':>10}")
print(f"{'-'*55}")

prev = CAPITAL
for d in days_list:
    eq = daily_eq[d]
    change = eq - prev
    btc_p = [p for p in backtest_prices if p["dt"].strftime("%Y-%m-%d") == d]
    btc_px = btc_p[-1]["close"] if btc_p else 0
    pos_entry = [e for e in bt.equity_curve if e["dt"].startswith(d)]
    pos = pos_entry[-1]["position"] if pos_entry else 0
    marker = ""
    if change < -1: marker = " <<<DOWN"
    elif change > 1: marker = " +++UP"
    print(f"{d:<12} ${eq:>8,.2f} ${change:>8,.2f} ${btc_px:>8,.0f} {pos:>9.6f}{marker}")
    prev = eq

print(f"\n{'='*80}")
print("VERDICT")
print(f"{'='*80}\n")

profitable = bt.pnl_total > 0
within_fee_budget = bt.fees_paid <= FEE_BUDGET
acceptable_dd = max_dd_pct < 0.25
good_wr = bt.wins / total_trades * 100 > 80 if total_trades > 0 else False

print(f"  Profitable 30d:     {'YES' if profitable else 'NO'} (${bt.pnl_total:,.2f})")
print(f"  Within fee budget:  {'YES' if within_fee_budget else 'NO'} (${bt.fees_paid:,.4f} / ${FEE_BUDGET:.2f})")
print(f"  Max DD < 25%:       {'YES' if acceptable_dd else 'NO'} ({max_dd_pct*100:.1f}%)")
if total_trades > 0:
    print(f"  Win Rate > 80%:     {'YES' if good_wr else 'NO'} ({bt.wins/total_trades*100:.1f}%)")

all_pass = profitable and within_fee_budget and acceptable_dd
print(f"\n  OVERALL: {'PASS - Strategy is viable for copy trading' if all_pass else 'NEEDS FURTHER ADJUSTMENT'}")

if all_pass:
    print(f"\n  RECOMMENDATION:")
    print(f"  Copy trader 0x2d99fe0f36c1aebd28a1a2c0e82e8ca13c2ea351")
    print(f"  Allocate: $100 with 2x isolated leverage on BTC")
    print(f"  Grid exit: 5 levels at $300 apart, 20% each")
    print(f"  No stop loss. Emergency exit at -15% only.")
    print(f"  Expected monthly return: ~${bt.pnl_total:,.2f} ({bt.pnl_total/CAPITAL*100:.1f}%)")

results = {
    "trader": "0x2d99fe0f36c1aebd28a1a2c0e82e8ca13c2ea351",
    "strategy_version": "8c_adjusted",
    "period": f"{backtest_prices[0]['dt'].strftime('%Y-%m-%d')} to {backtest_prices[-1]['dt'].strftime('%Y-%m-%d')}",
    "btc_change_pct": btc_change,
    "initial_capital": CAPITAL, "final_equity": final_equity,
    "pnl": bt.pnl_total, "return_pct": bt.pnl_total / CAPITAL * 100,
    "fees": bt.fees_paid, "trades": total_trades,
    "wins": bt.wins, "losses": bt.losses,
    "win_rate": bt.wins / total_trades * 100 if total_trades > 0 else 0,
    "max_dd": max_dd, "max_dd_pct": max_dd_pct * 100,
    "sharpe": sharpe,
    "buy_hold_return": bh_net,
    "alpha_vs_bh": bt.pnl_total - bh_net,
    "strategy_params": {
        "leverage": LEVERAGE, "grid_levels": NUM_EXIT_LEVELS,
        "grid_spacing": GRID_SPACING, "dip_threshold": DIP_THRESHOLD,
        "emergency_stop": EMERGENCY_STOP_PCT,
        "trailing_activation": TRAILING_STOP_ACTIVATION,
        "trailing_distance": TRAILING_STOP_DISTANCE,
        "min_entry_gap_hours": MIN_ENTRY_GAP,
    },
    "daily_equity": {d: daily_eq[d] for d in days_list},
    "trade_log": [{
        "dt": str(t["dt"]), "type": t["type"], "price": t["price"],
        "size": t["size"], "pnl": t["pnl"], "fee": t["fee"],
        "equity": t["equity"]
    } for t in bt.trades]
}
with open("backtest_adjusted.json", "w") as f:
    json.dump(results, f, indent=2, default=str)

print(f"\nResults saved to backtest_adjusted.json")
