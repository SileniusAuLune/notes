"""
Market data fetching.

Stocks: yfinance (free, no API key needed)
Forex:  OANDA practice/live REST API
"""
import datetime
from typing import Optional

import pandas as pd
import yfinance as yf

import config


def fetch_stock_ohlcv(symbol: str, days: int = config.LOOKBACK_DAYS) -> Optional[pd.DataFrame]:
    """
    Download OHLCV data for a stock symbol using yfinance.
    Returns a DataFrame with columns: Open, High, Low, Close, Volume
    or None if the download fails.
    """
    end   = datetime.date.today()
    start = end - datetime.timedelta(days=days)
    try:
        df = yf.download(symbol, start=start, end=end, progress=False, auto_adjust=True)
        if df.empty:
            print(f"[data] No data returned for {symbol}")
            return None
        df.index = pd.to_datetime(df.index)
        return df[["Open", "High", "Low", "Close", "Volume"]].dropna()
    except Exception as exc:
        print(f"[data] Failed to fetch {symbol}: {exc}")
        return None


def fetch_forex_ohlcv(pair: str, days: int = config.LOOKBACK_DAYS) -> Optional[pd.DataFrame]:
    """
    Download OHLCV candlestick data for a forex pair from OANDA.

    pair: e.g. "EUR_USD"
    Requires OANDA_API_KEY and OANDA_ACCOUNT_ID set in .env.
    Falls back to yfinance (using pair format like "EURUSD=X") when
    OANDA credentials are not configured.
    """
    if config.OANDA_API_KEY and config.OANDA_ACCOUNT_ID:
        return _fetch_oanda_candles(pair, days)
    # Fallback: yfinance can serve some forex pairs via Yahoo Finance
    yf_symbol = pair.replace("_", "") + "=X"
    return _fetch_forex_via_yfinance(yf_symbol, pair, days)


def _fetch_oanda_candles(pair: str, days: int) -> Optional[pd.DataFrame]:
    """Fetch OHLCV candles from OANDA REST API (v20)."""
    try:
        from oandapyV20 import API as OandaAPI
        from oandapyV20.endpoints.instruments import InstrumentsCandles

        environment = "practice" if config.OANDA_PRACTICE else "live"
        client = OandaAPI(access_token=config.OANDA_API_KEY, environment=environment)

        params = {
            "count": min(days * 24, 5000),  # H1 candles for the lookback
            "granularity": "H1",
            "price": "M",  # midpoint
        }
        req = InstrumentsCandles(instrument=pair, params=params)
        client.request(req)

        candles = req.response["candles"]
        records = []
        for c in candles:
            if c["complete"]:
                records.append({
                    "time":   pd.Timestamp(c["time"]),
                    "Open":   float(c["mid"]["o"]),
                    "High":   float(c["mid"]["h"]),
                    "Low":    float(c["mid"]["l"]),
                    "Close":  float(c["mid"]["c"]),
                    "Volume": float(c["volume"]),
                })
        if not records:
            return None

        df = pd.DataFrame(records).set_index("time")
        # Resample to daily for indicator calculations
        df_daily = df.resample("D").agg(
            Open=("Open", "first"),
            High=("High", "max"),
            Low=("Low", "min"),
            Close=("Close", "last"),
            Volume=("Volume", "sum"),
        ).dropna()
        return df_daily

    except Exception as exc:
        print(f"[data] OANDA fetch failed for {pair}: {exc}")
        return None


def _fetch_forex_via_yfinance(yf_symbol: str, label: str, days: int) -> Optional[pd.DataFrame]:
    """Fallback: fetch forex data via yfinance."""
    end   = datetime.date.today()
    start = end - datetime.timedelta(days=days)
    try:
        df = yf.download(yf_symbol, start=start, end=end, progress=False, auto_adjust=True)
        if df.empty:
            print(f"[data] No yfinance data for {label} ({yf_symbol})")
            return None
        df.index = pd.to_datetime(df.index)
        df = df[["Open", "High", "Low", "Close", "Volume"]].dropna()
        if "Volume" not in df.columns:
            df["Volume"] = 0
        return df
    except Exception as exc:
        print(f"[data] yfinance fallback failed for {label}: {exc}")
        return None


def get_current_price(symbol: str, asset_type: str = "stock") -> Optional[float]:
    """
    Return the most recent price for quick reference.
    asset_type: "stock" or "forex"
    """
    if asset_type == "forex":
        yf_sym = symbol.replace("_", "") + "=X"
        df = fetch_stock_ohlcv(yf_sym, days=5)
    else:
        df = fetch_stock_ohlcv(symbol, days=5)

    if df is None or df.empty:
        return None
    return float(df["Close"].iloc[-1])
