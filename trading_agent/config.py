"""
Configuration for the trading agent.
All secrets come from environment variables — never hardcode keys.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ── Anthropic ────────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]
CLAUDE_MODEL = "claude-opus-4-6"

# ── Alpaca (US stocks) ────────────────────────────────────────────────────────
# Sign up free at https://alpaca.markets → Paper Trading dashboard → API Keys
ALPACA_API_KEY    = os.getenv("ALPACA_API_KEY", "")
ALPACA_SECRET_KEY = os.getenv("ALPACA_SECRET_KEY", "")
ALPACA_PAPER      = os.getenv("ALPACA_PAPER", "true").lower() == "true"  # True = paper trade

# ── OANDA (Forex) ─────────────────────────────────────────────────────────────
# Sign up free at https://www.oanda.com → Practice account → Manage API Access
OANDA_API_KEY    = os.getenv("OANDA_API_KEY", "")
OANDA_ACCOUNT_ID = os.getenv("OANDA_ACCOUNT_ID", "")
OANDA_PRACTICE   = os.getenv("OANDA_PRACTICE", "true").lower() == "true"  # True = practice

# ── Trading universe ──────────────────────────────────────────────────────────
# Stocks: standard ticker symbols (Alpaca)
STOCK_SYMBOLS = os.getenv("STOCK_SYMBOLS", "AAPL,MSFT,NVDA,SPY").split(",")

# Forex: OANDA instrument format  e.g. EUR_USD, GBP_USD
FOREX_PAIRS   = os.getenv("FOREX_PAIRS", "EUR_USD,GBP_USD").split(",")

# ── Risk management ───────────────────────────────────────────────────────────
# Max fraction of portfolio to risk per trade (0.02 = 2%)
MAX_POSITION_SIZE_PCT = float(os.getenv("MAX_POSITION_SIZE_PCT", "0.02"))
# Minimum AI confidence score (0–1) required to execute a trade
MIN_CONFIDENCE        = float(os.getenv("MIN_CONFIDENCE", "0.65"))

# ── Run schedule ──────────────────────────────────────────────────────────────
# How often the agent wakes up to scan the market (minutes)
SCAN_INTERVAL_MINUTES = int(os.getenv("SCAN_INTERVAL_MINUTES", "15"))

# ── Lookback period for technical indicators ──────────────────────────────────
LOOKBACK_DAYS = int(os.getenv("LOOKBACK_DAYS", "60"))
