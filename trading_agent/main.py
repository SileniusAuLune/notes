"""
Trading agent — main entry point.

Run once:   python main.py --once
Run on loop: python main.py           (scans every SCAN_INTERVAL_MINUTES)

The agent:
  1. Fetches OHLCV data for every configured symbol
  2. Computes technical indicators
  3. Asks Claude for a trade decision
  4. Executes the trade if confidence >= MIN_CONFIDENCE
  5. Logs everything to the console
"""
import argparse
import datetime
import sys
import time

import schedule
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

import config
import agent
import broker
import data_fetcher
from indicators import compute_indicators

console = Console()


# ── Per-symbol scan ───────────────────────────────────────────────────────────

def scan_symbol(symbol: str, asset_type: str) -> None:
    """Fetch data → compute indicators → ask Claude → optionally trade."""
    console.rule(f"[bold cyan]{symbol}  ({asset_type})")

    # 1. Fetch data
    if asset_type == "stock":
        df = data_fetcher.fetch_stock_ohlcv(symbol)
    else:
        df = data_fetcher.fetch_forex_ohlcv(symbol)

    if df is None or len(df) < 30:
        console.print(f"  [yellow]⚠  Not enough data for {symbol}, skipping.[/]")
        return

    # 2. Compute indicators
    indicators = compute_indicators(df)
    current_price = indicators.get("current_price")
    if current_price is None:
        console.print(f"  [yellow]⚠  Could not determine price for {symbol}, skipping.[/]")
        return

    # 3. Ask Claude
    console.print(f"  [dim]Asking Claude to analyse {symbol}…[/]")
    decision = agent.analyze(symbol, indicators, asset_type=asset_type)

    # 4. Display decision
    _print_decision(decision, indicators)

    # 5. Execute if conviction is high enough
    if decision.action == "HOLD" or decision.confidence < config.MIN_CONFIDENCE:
        console.print(
            f"  [dim]→ No trade: action={decision.action}, "
            f"confidence={decision.confidence:.2f} "
            f"(min={config.MIN_CONFIDENCE})[/]"
        )
        return

    # 6. Size and place order
    if asset_type == "stock":
        portfolio_val = broker.get_stock_portfolio_value()
        result = broker.place_stock_order(
            symbol=symbol,
            action=decision.action,
            price=current_price,
            portfolio_value=portfolio_val,
            reason=decision.reasoning,
        )
    else:
        # For forex we use paper portfolio value as proxy
        portfolio_val = broker.paper_summary()["cash"] + 10_000
        result = broker.place_forex_order(
            pair=symbol,
            action=decision.action,
            price=current_price,
            portfolio_value=portfolio_val,
            reason=decision.reasoning,
        )

    tag = "[sim]" if result.simulated else "[LIVE]"
    console.print(
        f"  [bold green]✓ {tag} {result.action} {result.qty:.4f} × "
        f"{result.symbol} @ {result.price}[/]"
    )


def _print_decision(decision: agent.TradeDecision, indicators: dict) -> None:
    action_color = {"BUY": "green", "SELL": "red", "HOLD": "yellow"}.get(decision.action, "white")

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("", style="dim", width=18)
    table.add_column("")

    table.add_row("Action",     f"[bold {action_color}]{decision.action}[/]")
    table.add_row("Confidence", f"{decision.confidence:.0%}")
    table.add_row("Price",      str(indicators.get("current_price", "—")))
    table.add_row("Entry",      str(decision.entry_price or "—"))
    table.add_row("Stop Loss",  str(decision.stop_loss or "—"))
    table.add_row("Take Profit",str(decision.take_profit or "—"))
    table.add_row("RSI (14)",   str(indicators.get("rsi_14", "—")))
    table.add_row("Trend",      indicators.get("trend", "—").upper())
    table.add_row("Reasoning",  decision.reasoning)

    console.print(Panel(table, title=f"[bold]{decision.symbol}[/]", expand=False))


# ── Full scan cycle ───────────────────────────────────────────────────────────

def run_scan() -> None:
    console.print(
        f"\n[bold white on blue] SCAN STARTED "
        f"{datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} [/]"
    )

    for symbol in config.STOCK_SYMBOLS:
        try:
            scan_symbol(symbol.strip(), "stock")
        except Exception as exc:
            console.print(f"  [red]Error scanning {symbol}: {exc}[/]")

    for pair in config.FOREX_PAIRS:
        try:
            scan_symbol(pair.strip(), "forex")
        except Exception as exc:
            console.print(f"  [red]Error scanning {pair}: {exc}[/]")

    # Show paper portfolio summary
    summary = broker.paper_summary()
    console.print(
        f"\n[dim]Paper portfolio — cash: ${summary['cash']:,.2f} | "
        f"positions: {len(summary['positions'])} | "
        f"total trades: {summary['trades']}[/]"
    )
    console.print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Claude Trading Agent")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single scan and exit (instead of looping)",
    )
    args = parser.parse_args()

    console.print(Panel.fit(
        f"[bold cyan]Claude Trading Agent[/]\n"
        f"Model: [green]{config.CLAUDE_MODEL}[/]\n"
        f"Stocks: [yellow]{', '.join(config.STOCK_SYMBOLS)}[/]\n"
        f"Forex:  [yellow]{', '.join(config.FOREX_PAIRS)}[/]\n"
        f"Min confidence to trade: [magenta]{config.MIN_CONFIDENCE:.0%}[/]\n"
        f"Alpaca paper: [cyan]{config.ALPACA_PAPER}[/]  |  "
        f"OANDA practice: [cyan]{config.OANDA_PRACTICE}[/]",
        title="[bold]Config[/]",
        border_style="cyan",
    ))

    if args.once:
        run_scan()
        sys.exit(0)

    console.print(
        f"[dim]Scheduling scans every {config.SCAN_INTERVAL_MINUTES} minutes. "
        f"Press Ctrl+C to stop.[/]\n"
    )
    run_scan()  # Run immediately on start

    schedule.every(config.SCAN_INTERVAL_MINUTES).minutes.do(run_scan)
    while True:
        schedule.run_pending()
        time.sleep(30)


if __name__ == "__main__":
    main()
