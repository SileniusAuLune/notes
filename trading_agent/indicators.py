"""
Technical indicator calculations.
Returns a human-readable summary dict that gets passed to Claude.
"""
import pandas as pd
import pandas_ta as ta


def compute_indicators(df: pd.DataFrame) -> dict:
    """
    Given an OHLCV DataFrame (columns: Open, High, Low, Close, Volume),
    compute a set of common indicators and return a summary dict.

    All values are rounded to 4 significant figures for readability.
    """
    close = df["Close"]
    high  = df["High"]
    low   = df["Low"]

    # ── Trend ──────────────────────────────────────────────────────────────────
    ema_20  = ta.ema(close, length=20)
    ema_50  = ta.ema(close, length=50)
    ema_200 = ta.ema(close, length=200)

    # ── Momentum ───────────────────────────────────────────────────────────────
    rsi_14 = ta.rsi(close, length=14)

    macd_df = ta.macd(close, fast=12, slow=26, signal=9)
    macd_line   = macd_df["MACD_12_26_9"]   if macd_df is not None else None
    macd_signal = macd_df["MACDs_12_26_9"]  if macd_df is not None else None
    macd_hist   = macd_df["MACDh_12_26_9"]  if macd_df is not None else None

    # ── Volatility / bands ─────────────────────────────────────────────────────
    bb_df = ta.bbands(close, length=20, std=2)
    bb_upper  = bb_df["BBU_20_2.0"] if bb_df is not None else None
    bb_middle = bb_df["BBM_20_2.0"] if bb_df is not None else None
    bb_lower  = bb_df["BBL_20_2.0"] if bb_df is not None else None

    atr_14 = ta.atr(high, low, close, length=14)

    # ── Volume ─────────────────────────────────────────────────────────────────
    vol_sma_20 = df["Volume"].rolling(20).mean() if "Volume" in df.columns else None

    def last(series):
        """Safely get the most recent non-NaN value from a series."""
        if series is None:
            return None
        val = series.dropna()
        return round(float(val.iloc[-1]), 4) if len(val) else None

    current_price = last(close)

    # Determine trend context
    trend = "neutral"
    if ema_20 is not None and ema_50 is not None:
        e20, e50 = last(ema_20), last(ema_50)
        if e20 and e50:
            trend = "bullish" if e20 > e50 else "bearish"

    # BB position (0 = at lower band, 1 = at upper band)
    bb_position = None
    if bb_upper is not None and bb_lower is not None:
        u, l = last(bb_upper), last(bb_lower)
        if u and l and u != l:
            bb_position = round((current_price - l) / (u - l), 4)

    # Volume vs average
    vol_ratio = None
    if vol_sma_20 is not None:
        avg_vol = last(vol_sma_20)
        if avg_vol and "Volume" in df.columns:
            current_vol = float(df["Volume"].iloc[-1])
            vol_ratio = round(current_vol / avg_vol, 2)

    return {
        "current_price":  current_price,
        "ema_20":         last(ema_20),
        "ema_50":         last(ema_50),
        "ema_200":        last(ema_200),
        "trend":          trend,
        "rsi_14":         last(rsi_14),
        "macd":           last(macd_line),
        "macd_signal":    last(macd_signal),
        "macd_histogram": last(macd_hist),
        "bb_upper":       last(bb_upper),
        "bb_middle":      last(bb_middle),
        "bb_lower":       last(bb_lower),
        "bb_position":    bb_position,   # 0 = oversold zone, 1 = overbought zone
        "atr_14":         last(atr_14),
        "volume_ratio":   vol_ratio,     # current vol / 20-day avg
    }


def indicators_to_text(symbol: str, indicators: dict) -> str:
    """Format indicators as a clear text block for Claude's context."""
    p = indicators
    lines = [
        f"Symbol: {symbol}",
        f"Current Price:  {p['current_price']}",
        "",
        "── Trend ──────────────────────────",
        f"  EMA 20 / 50 / 200:  {p['ema_20']} / {p['ema_50']} / {p['ema_200']}",
        f"  Trend (EMA20 vs 50): {p['trend'].upper()}",
        "",
        "── Momentum ────────────────────────",
        f"  RSI (14):            {p['rsi_14']}  {'[OVERBOUGHT >70]' if p['rsi_14'] and p['rsi_14'] > 70 else '[OVERSOLD <30]' if p['rsi_14'] and p['rsi_14'] < 30 else ''}",
        f"  MACD:                {p['macd']}",
        f"  MACD Signal:         {p['macd_signal']}",
        f"  MACD Histogram:      {p['macd_histogram']}  {'[BULLISH crossover]' if p['macd_histogram'] and p['macd_histogram'] > 0 else '[BEARISH crossover]' if p['macd_histogram'] and p['macd_histogram'] < 0 else ''}",
        "",
        "── Volatility ──────────────────────",
        f"  BB Upper / Mid / Lower: {p['bb_upper']} / {p['bb_middle']} / {p['bb_lower']}",
        f"  BB Position (0=lower, 1=upper): {p['bb_position']}",
        f"  ATR (14):            {p['atr_14']}",
        "",
        "── Volume ──────────────────────────",
        f"  Volume vs 20-day avg: {p['volume_ratio']}x  {'[HIGH VOLUME]' if p['volume_ratio'] and p['volume_ratio'] > 1.5 else ''}",
    ]
    return "\n".join(lines)
