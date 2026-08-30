import pandas as pd
import numpy as np
from typing import Optional


def ema(series: pd.Series, period: int) -> pd.Series:
    return series.ewm(span=period, adjust=False).mean()


def sma(series: pd.Series, period: int) -> pd.Series:
    return series.rolling(window=period).mean()


def rsi(close: pd.Series, period: int = 14) -> pd.Series:
    delta = close.diff()
    gain = delta.where(delta > 0, 0.0)
    loss = -delta.where(delta < 0, 0.0)
    avg_gain = gain.ewm(alpha=1 / period, min_periods=period).mean()
    avg_loss = loss.ewm(alpha=1 / period, min_periods=period).mean()
    rs = avg_gain / avg_loss
    return 100 - (100 / (1 + rs))


def macd(close: pd.Series, fast: int = 12, slow: int = 26, signal: int = 9) -> dict:
    fast_ema = ema(close, fast)
    slow_ema = ema(close, slow)
    macd_line = fast_ema - slow_ema
    signal_line = ema(macd_line, signal)
    histogram = macd_line - signal_line
    return {"macd": macd_line, "signal": signal_line, "histogram": histogram}


def bollinger_bands(close: pd.Series, period: int = 20, std_dev: float = 2.0) -> dict:
    middle = sma(close, period)
    rolling_std = close.rolling(window=period).std()
    upper = middle + (rolling_std * std_dev)
    lower = middle - (rolling_std * std_dev)
    width = (upper - lower) / middle
    return {"upper": upper, "middle": middle, "lower": lower, "width": width}


def atr(high: pd.Series, low: pd.Series, close: pd.Series, period: int = 14) -> pd.Series:
    prev_close = close.shift(1)
    tr = pd.concat([
        high - low,
        (high - prev_close).abs(),
        (low - prev_close).abs()
    ], axis=1).max(axis=1)
    return tr.ewm(alpha=1 / period, min_periods=period).mean()


def vwap(high: pd.Series, low: pd.Series, close: pd.Series, volume: pd.Series) -> pd.Series:
    typical_price = (high + low + close) / 3
    cumulative_tp_vol = (typical_price * volume).cumsum()
    cumulative_vol = volume.cumsum()
    return cumulative_tp_vol / cumulative_vol


def score_technical(close: pd.Series, high: Optional[pd.Series] = None,
                    low: Optional[pd.Series] = None, volume: Optional[pd.Series] = None) -> dict:
    latest = close.iloc[-1]
    rsi_val = rsi(close).iloc[-1]
    macd_data = macd(close)
    bb = bollinger_bands(close)
    ema_20 = ema(close, 20).iloc[-1]
    ema_50 = ema(close, 50).iloc[-1]

    score = 0
    signals = []

    if rsi_val < 30:
        score += 2
        signals.append(f"RSI oversold: {rsi_val:.1f}")
    elif rsi_val > 70:
        score -= 2
        signals.append(f"RSI overbought: {rsi_val:.1f}")
    else:
        signals.append(f"RSI neutral: {rsi_val:.1f}")

    macd_hist = macd_data["histogram"].iloc[-1]
    macd_prev = macd_data["histogram"].iloc[-2]
    if macd_hist > 0 and macd_prev <= 0:
        score += 2
        signals.append("MACD bullish crossover")
    elif macd_hist < 0 and macd_prev >= 0:
        score -= 2
        signals.append("MACD bearish crossover")
    elif macd_hist > 0:
        score += 1
        signals.append("MACD bullish")
    else:
        score -= 1
        signals.append("MACD bearish")

    bb_pos = (latest - bb["lower"].iloc[-1]) / (bb["upper"].iloc[-1] - bb["lower"].iloc[-1])
    if bb_pos < 0.1:
        score += 1
        signals.append(f"Near lower BB: {bb_pos:.2f}")
    elif bb_pos > 0.9:
        score -= 1
        signals.append(f"Near upper BB: {bb_pos:.2f}")

    if latest > ema_20 > ema_50:
        score += 1
        signals.append("EMA aligned bullish")
    elif latest < ema_20 < ema_50:
        score -= 1
        signals.append("EMA aligned bearish")

    max_score = 6
    normalized = round((score / max_score) * 100, 1)

    return {
        "score": score,
        "normalized_score": normalized,
        "max_possible": max_score,
        "rsi": round(rsi_val, 2),
        "macd_histogram": round(macd_hist, 6),
        "bb_position": round(bb_pos, 3),
        "ema_20": round(ema_20, 4),
        "ema_50": round(ema_50, 4),
        "price": round(latest, 4),
        "signals": signals,
        "bias": "LONG" if score > 1 else "SHORT" if score < -1 else "NEUTRAL"
    }
