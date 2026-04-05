"""
Broker interface.

Stocks  → Alpaca (paper or live)
Forex   → OANDA (practice or live)

When broker credentials are missing the agent falls back to pure
paper-trade simulation so you can test the full pipeline immediately,
before signing up for any account.
"""
import datetime
from dataclasses import dataclass, field
from typing import Optional

import config


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class Position:
    symbol:     str
    qty:        float
    avg_cost:   float
    asset_type: str  # "stock" or "forex"

@dataclass
class TradeResult:
    symbol:     str
    action:     str   # "BUY" | "SELL" | "HOLD" | "SKIPPED"
    qty:        float
    price:      float
    reason:     str
    timestamp:  datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    simulated:  bool = False


# ── In-memory paper portfolio (used when no broker is configured) ──────────────

class PaperPortfolio:
    """
    Minimal paper-trading ledger.
    Starts with $10,000 simulated cash so you can see the system work
    end-to-end without real money.
    """
    def __init__(self, initial_cash: float = 10_000.0):
        self.cash: float = initial_cash
        self.positions: dict[str, Position] = {}
        self.trades: list[TradeResult] = []

    def equity(self, prices: dict[str, float]) -> float:
        pos_value = sum(
            p.qty * prices.get(p.symbol, p.avg_cost)
            for p in self.positions.values()
        )
        return self.cash + pos_value

    def buy(self, symbol: str, qty: float, price: float, asset_type: str) -> TradeResult:
        cost = qty * price
        if cost > self.cash:
            qty = self.cash / price
            cost = qty * price
        self.cash -= cost
        if symbol in self.positions:
            pos = self.positions[symbol]
            total_qty  = pos.qty + qty
            pos.avg_cost = (pos.qty * pos.avg_cost + cost) / total_qty
            pos.qty = total_qty
        else:
            self.positions[symbol] = Position(symbol, qty, price, asset_type)
        result = TradeResult(symbol, "BUY", qty, price,
                             reason="paper trade", simulated=True)
        self.trades.append(result)
        return result

    def sell(self, symbol: str, qty: float, price: float) -> TradeResult:
        if symbol not in self.positions:
            return TradeResult(symbol, "SKIPPED", 0, price,
                               reason="no position to sell", simulated=True)
        pos = self.positions[symbol]
        qty = min(qty, pos.qty)
        proceeds = qty * price
        self.cash += proceeds
        pos.qty -= qty
        if pos.qty <= 0:
            del self.positions[symbol]
        result = TradeResult(symbol, "SELL", qty, price,
                             reason="paper trade", simulated=True)
        self.trades.append(result)
        return result


# Shared in-memory paper portfolio (instantiated once per process)
_paper = PaperPortfolio()


# ── Alpaca (stocks) ───────────────────────────────────────────────────────────

def _alpaca_client():
    if not config.ALPACA_API_KEY:
        return None
    try:
        from alpaca.trading.client import TradingClient
        return TradingClient(
            api_key=config.ALPACA_API_KEY,
            secret_key=config.ALPACA_SECRET_KEY,
            paper=config.ALPACA_PAPER,
        )
    except Exception as exc:
        print(f"[broker] Alpaca init failed: {exc}")
        return None


def get_stock_portfolio_value() -> float:
    """Return total portfolio equity from Alpaca (or paper)."""
    client = _alpaca_client()
    if client is None:
        return _paper.cash + sum(p.qty * p.avg_cost for p in _paper.positions.values())
    try:
        account = client.get_account()
        return float(account.portfolio_value)
    except Exception as exc:
        print(f"[broker] Could not fetch Alpaca account: {exc}")
        return 10_000.0


def place_stock_order(
    symbol: str,
    action: str,          # "BUY" or "SELL"
    price: float,
    portfolio_value: float,
    reason: str = "",
) -> TradeResult:
    """
    Size the order using MAX_POSITION_SIZE_PCT of portfolio equity,
    then submit a market order via Alpaca (or simulate it).
    """
    qty = max(1, int((portfolio_value * config.MAX_POSITION_SIZE_PCT) / price))
    client = _alpaca_client()

    if client is None:
        # Simulate
        if action == "BUY":
            return _paper.buy(symbol, qty, price, "stock")
        return _paper.sell(symbol, qty, price)

    try:
        from alpaca.trading.requests import MarketOrderRequest
        from alpaca.trading.enums import OrderSide, TimeInForce

        side = OrderSide.BUY if action == "BUY" else OrderSide.SELL
        req  = MarketOrderRequest(
            symbol=symbol,
            qty=qty,
            side=side,
            time_in_force=TimeInForce.DAY,
        )
        order = client.submit_order(req)
        return TradeResult(
            symbol=symbol, action=action, qty=qty, price=price,
            reason=reason, simulated=False,
        )
    except Exception as exc:
        print(f"[broker] Alpaca order failed: {exc} — falling back to paper")
        if action == "BUY":
            return _paper.buy(symbol, qty, price, "stock")
        return _paper.sell(symbol, qty, price)


# ── OANDA (forex) ─────────────────────────────────────────────────────────────

def _oanda_client():
    if not config.OANDA_API_KEY:
        return None
    try:
        from oandapyV20 import API as OandaAPI
        env = "practice" if config.OANDA_PRACTICE else "live"
        return OandaAPI(access_token=config.OANDA_API_KEY, environment=env)
    except Exception as exc:
        print(f"[broker] OANDA init failed: {exc}")
        return None


def place_forex_order(
    pair: str,
    action: str,           # "BUY" or "SELL"
    price: float,
    portfolio_value: float,
    reason: str = "",
) -> TradeResult:
    """
    Submit a market order for a forex pair via OANDA (or simulate it).
    Units are sized to risk MAX_POSITION_SIZE_PCT of portfolio equity.
    """
    # Approximate unit size (assuming 1 unit ≈ base currency cost of ~price)
    units = int((portfolio_value * config.MAX_POSITION_SIZE_PCT) / price)
    if action == "SELL":
        units = -abs(units)

    client = _oanda_client()
    if client is None:
        symbol = pair.replace("/", "_")
        if action == "BUY":
            return _paper.buy(symbol, abs(units), price, "forex")
        return _paper.sell(symbol, abs(units), price)

    try:
        from oandapyV20.endpoints.orders import OrderCreate

        data = {
            "order": {
                "type": "MARKET",
                "instrument": pair,
                "units": str(units),
                "timeInForce": "FOK",
                "positionFill": "DEFAULT",
            }
        }
        req = OrderCreate(accountID=config.OANDA_ACCOUNT_ID, data=data)
        client.request(req)
        return TradeResult(
            symbol=pair, action=action, qty=abs(units), price=price,
            reason=reason, simulated=False,
        )
    except Exception as exc:
        print(f"[broker] OANDA order failed: {exc} — falling back to paper")
        symbol = pair.replace("/", "_")
        if action == "BUY":
            return _paper.buy(symbol, abs(units), price, "forex")
        return _paper.sell(symbol, abs(units), price)


def paper_summary() -> dict:
    """Return a snapshot of the in-memory paper portfolio."""
    return {
        "cash":      round(_paper.cash, 2),
        "positions": {s: {"qty": p.qty, "avg_cost": p.avg_cost}
                      for s, p in _paper.positions.items()},
        "trades":    len(_paper.trades),
    }
