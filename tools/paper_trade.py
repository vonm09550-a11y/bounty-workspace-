import json
import time
import sys
from datetime import datetime, timezone
from typing import Optional

sys.path.insert(0, "/home/user/bounty-workspace-/hyperliquid-sdk")
from hyperliquid.info import Info
from hyperliquid.utils.constants import MAINNET_API_URL


class PaperTradeEngine:
    def __init__(self, capital: float, base_url: str = MAINNET_API_URL):
        self.info = Info(base_url)
        self.capital = capital
        self.balance = capital
        self.positions = {}
        self.orders = []
        self.fills = []
        self.log = []
        self.order_id_counter = 1000

    def _next_oid(self) -> int:
        self.order_id_counter += 1
        return self.order_id_counter

    def _ts(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def _get_mid(self, coin: str) -> float:
        mids = self.info.all_mids()
        return float(mids[coin])

    def _log(self, action: str, detail: dict):
        entry = {"timestamp": self._ts(), "action": action, **detail}
        self.log.append(entry)
        return entry

    def get_market_snapshot(self, coin: str) -> dict:
        mid = self._get_mid(coin)
        meta = self.info.meta()
        coin_meta = None
        for u in meta.get("universe", []):
            if u["name"] == coin:
                coin_meta = u
                break
        return {
            "coin": coin,
            "mid_price": mid,
            "max_leverage": coin_meta.get("maxLeverage") if coin_meta else None,
            "sz_decimals": coin_meta.get("szDecimals") if coin_meta else None,
            "timestamp": self._ts()
        }

    def set_leverage(self, coin: str, leverage: int, is_cross: bool = True) -> dict:
        result = {
            "type": "updateLeverage",
            "coin": coin,
            "leverage": leverage,
            "is_cross": is_cross,
            "status": "ok",
            "response": {"type": "default"}
        }
        entry = self._log("SET_LEVERAGE", result)
        return entry

    def market_open(self, coin: str, is_buy: bool, sz: float, slippage: float = 0.01) -> dict:
        mid = self._get_mid(coin)
        fill_px = mid * (1 + slippage) if is_buy else mid * (1 - slippage)
        fill_px = round(fill_px, 2)
        oid = self._next_oid()
        notional = fill_px * sz
        direction = "LONG" if is_buy else "SHORT"

        pos = self.positions.get(coin)
        if pos:
            if pos["is_buy"] == is_buy:
                old_notional = pos["entry_px"] * pos["sz"]
                new_notional = old_notional + notional
                new_sz = pos["sz"] + sz
                pos["entry_px"] = round(new_notional / new_sz, 2)
                pos["sz"] = new_sz
                pos["notional"] = round(new_notional, 2)
            else:
                pos["sz"] -= sz
                if pos["sz"] <= 0:
                    del self.positions[coin]
        else:
            leverage = 1
            for log_entry in self.log:
                if log_entry.get("coin") == coin and log_entry["action"] == "SET_LEVERAGE":
                    leverage = log_entry["leverage"]
            margin_used = notional / leverage
            liq_distance = 1 / leverage
            liq_px = fill_px * (1 - liq_distance) if is_buy else fill_px * (1 + liq_distance)

            self.positions[coin] = {
                "coin": coin,
                "is_buy": is_buy,
                "direction": direction,
                "sz": sz,
                "entry_px": fill_px,
                "notional": round(notional, 2),
                "leverage": leverage,
                "margin_used": round(margin_used, 2),
                "liquidation_px": round(liq_px, 2),
                "open_time": self._ts()
            }
            self.balance -= margin_used

        fill = {
            "oid": oid,
            "coin": coin,
            "direction": direction,
            "sz": sz,
            "fill_px": fill_px,
            "mid_px": round(mid, 2),
            "slippage_applied": slippage,
            "notional": round(notional, 2),
            "status": "filled"
        }
        self.fills.append(fill)

        result = {
            "status": "ok",
            "response": {
                "type": "order",
                "data": {
                    "statuses": [{
                        "filled": {
                            "oid": oid,
                            "totalSz": str(sz),
                            "avgPx": str(fill_px)
                        }
                    }]
                }
            }
        }
        entry = self._log("MARKET_OPEN", {**fill, "api_response": result})
        return entry

    def place_trigger(self, coin: str, is_buy: bool, sz: float, trigger_px: float,
                      limit_px: float, tpsl: str) -> dict:
        oid = self._next_oid()
        order = {
            "oid": oid,
            "coin": coin,
            "is_buy": is_buy,
            "sz": sz,
            "trigger_px": trigger_px,
            "limit_px": limit_px,
            "tpsl": tpsl,
            "order_type": {"trigger": {"triggerPx": trigger_px, "isMarket": True, "tpsl": tpsl}},
            "reduce_only": True,
            "status": "resting"
        }
        self.orders.append(order)

        result = {
            "status": "ok",
            "response": {
                "type": "order",
                "data": {
                    "statuses": [{
                        "resting": {"oid": oid}
                    }]
                }
            }
        }
        label = "PLACE_TP" if tpsl == "tp" else "PLACE_SL"
        entry = self._log(label, {**order, "api_response": result})
        return entry

    def bulk_orders_tpsl(self, coin: str, is_buy: bool, sz: float, limit_px: float,
                         tp_trigger: float, tp_limit: float,
                         sl_trigger: float, sl_limit: float) -> dict:
        oid_entry = self._next_oid()
        oid_tp = self._next_oid()
        oid_sl = self._next_oid()

        orders = [
            {
                "coin": coin, "is_buy": is_buy, "sz": sz,
                "limit_px": limit_px,
                "order_type": {"limit": {"tif": "Gtc"}},
                "reduce_only": False
            },
            {
                "coin": coin, "is_buy": not is_buy, "sz": sz,
                "limit_px": tp_limit,
                "order_type": {"trigger": {"isMarket": True, "triggerPx": tp_trigger, "tpsl": "tp"}},
                "reduce_only": True
            },
            {
                "coin": coin, "is_buy": not is_buy, "sz": sz,
                "limit_px": sl_limit,
                "order_type": {"trigger": {"isMarket": True, "triggerPx": sl_trigger, "tpsl": "sl"}},
                "reduce_only": True
            }
        ]

        result = {
            "status": "ok",
            "grouping": "normalTpsl",
            "response": {
                "type": "order",
                "data": {
                    "statuses": [
                        {"resting": {"oid": oid_entry}},
                        {"resting": {"oid": oid_tp}},
                        {"resting": {"oid": oid_sl}}
                    ]
                }
            }
        }
        entry = self._log("BULK_TPSL", {"orders": orders, "api_response": result})
        return entry

    def check_position(self, coin: str) -> dict:
        pos = self.positions.get(coin)
        if not pos:
            return {"coin": coin, "status": "no_position"}

        current_px = self._get_mid(coin)
        unrealized_pnl = (current_px - pos["entry_px"]) * pos["sz"]
        if not pos["is_buy"]:
            unrealized_pnl = -unrealized_pnl
        pnl_pct = (unrealized_pnl / pos["margin_used"]) * 100
        roi = (unrealized_pnl / self.capital) * 100

        active_orders = [o for o in self.orders if o["coin"] == coin and o["status"] == "resting"]

        snapshot = {
            "coin": coin,
            "direction": pos["direction"],
            "sz": pos["sz"],
            "entry_px": pos["entry_px"],
            "current_px": round(current_px, 2),
            "notional": pos["notional"],
            "leverage": pos["leverage"],
            "margin_used": pos["margin_used"],
            "liquidation_px": pos["liquidation_px"],
            "unrealized_pnl": round(unrealized_pnl, 2),
            "pnl_pct_on_margin": round(pnl_pct, 2),
            "roi_on_capital": round(roi, 2),
            "active_orders": len(active_orders),
            "tp_orders": [o for o in active_orders if o.get("tpsl") == "tp"],
            "sl_orders": [o for o in active_orders if o.get("tpsl") == "sl"],
            "timestamp": self._ts()
        }
        return snapshot

    def get_account_state(self) -> dict:
        total_unrealized = 0
        for coin, pos in self.positions.items():
            try:
                current_px = self._get_mid(coin)
                pnl = (current_px - pos["entry_px"]) * pos["sz"]
                if not pos["is_buy"]:
                    pnl = -pnl
                total_unrealized += pnl
            except:
                pass

        total_margin = sum(p["margin_used"] for p in self.positions.values())
        account_value = self.balance + total_margin + total_unrealized

        return {
            "initial_capital": self.capital,
            "cash_balance": round(self.balance, 2),
            "total_margin_used": round(total_margin, 2),
            "total_unrealized_pnl": round(total_unrealized, 2),
            "account_value": round(account_value, 2),
            "open_positions": len(self.positions),
            "active_orders": len([o for o in self.orders if o["status"] == "resting"]),
            "total_fills": len(self.fills),
            "timestamp": self._ts()
        }

    def export_trade_log(self) -> dict:
        return {
            "engine": "PaperTradeEngine",
            "network": "paper (mainnet prices)",
            "capital": self.capital,
            "positions": self.positions,
            "orders": self.orders,
            "fills": self.fills,
            "log": self.log,
            "account": self.get_account_state()
        }
