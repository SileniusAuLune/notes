"""
Claude AI trading decision engine.

For each symbol the agent:
  1. Receives a pre-computed indicators dict + text summary
  2. Asks Claude to reason about the trade opportunity
  3. Parses Claude's structured JSON decision
  4. Returns a TradeDecision

Claude uses adaptive thinking (claude-opus-4-6) so it can reason
deeply when the signals are ambiguous.
"""
import json
import re
from dataclasses import dataclass
from typing import Optional

import anthropic

import config
from indicators import indicators_to_text

# Anthropic client (reused across calls for prompt-cache efficiency)
_client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)

# System prompt is stable → cached after the first request
_SYSTEM_PROMPT = """You are an expert quantitative trading analyst.

Your job is to evaluate a set of technical indicators for a given financial
instrument and produce a clear, disciplined trade recommendation.

Rules you MUST follow:
- Preserve capital above all else. Only recommend BUY or SELL when conviction
  is genuinely high.  When in doubt, recommend HOLD.
- Never "force" a trade just because indicators exist.
- Consider whether multiple independent signals align (confluence).
- Factor in risk: only recommend aggressive positions when risk/reward > 2:1.
- Output ONLY valid JSON — no extra text, no markdown fences.

Output format (strict JSON):
{
  "action":      "BUY" | "SELL" | "HOLD",
  "confidence":  <float 0.0–1.0>,
  "entry_price": <float or null>,
  "stop_loss":   <float or null>,
  "take_profit": <float or null>,
  "reasoning":   "<concise explanation, max 3 sentences>"
}
"""


@dataclass
class TradeDecision:
    symbol:      str
    action:      str        # BUY | SELL | HOLD
    confidence:  float
    entry_price: Optional[float]
    stop_loss:   Optional[float]
    take_profit: Optional[float]
    reasoning:   str
    raw_response: str = ""


def analyze(
    symbol: str,
    indicators: dict,
    asset_type: str = "stock",   # "stock" or "forex"
    extra_context: str = "",     # optional: news headline, earnings date, etc.
) -> TradeDecision:
    """
    Ask Claude to analyse the indicators and return a TradeDecision.
    Uses adaptive thinking so Claude can reason deeply on hard cases.
    """
    indicator_text = indicators_to_text(symbol, indicators)

    user_message = f"""
Asset type: {asset_type.upper()}

{indicator_text}

{f"Additional context: {extra_context}" if extra_context else ""}

Based on these technical indicators, provide your trade recommendation as JSON.
Remember: only recommend BUY/SELL with high conviction. Default to HOLD.
"""

    response = _client.messages.create(
        model=config.CLAUDE_MODEL,
        max_tokens=1024,
        thinking={"type": "adaptive"},
        system=[{
            "type": "text",
            "text": _SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},  # cache the stable system prompt
        }],
        messages=[{"role": "user", "content": user_message}],
    )

    # Extract the text block (thinking blocks may precede it)
    raw_text = ""
    for block in response.content:
        if block.type == "text":
            raw_text = block.text
            break

    return _parse_decision(symbol, raw_text)


def _parse_decision(symbol: str, raw: str) -> TradeDecision:
    """Parse Claude's JSON response into a TradeDecision."""
    # Strip any accidental markdown fences
    clean = re.sub(r"```(?:json)?|```", "", raw).strip()

    try:
        data = json.loads(clean)
    except json.JSONDecodeError:
        # Attempt to extract JSON object from the text
        match = re.search(r"\{.*\}", clean, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
            except json.JSONDecodeError:
                data = {}
        else:
            data = {}

    action     = str(data.get("action", "HOLD")).upper()
    confidence = float(data.get("confidence", 0.0))
    reasoning  = str(data.get("reasoning", "Parse error — defaulting to HOLD"))

    if action not in {"BUY", "SELL", "HOLD"}:
        action = "HOLD"

    return TradeDecision(
        symbol=symbol,
        action=action,
        confidence=confidence,
        entry_price=_optional_float(data.get("entry_price")),
        stop_loss=_optional_float(data.get("stop_loss")),
        take_profit=_optional_float(data.get("take_profit")),
        reasoning=reasoning,
        raw_response=raw,
    )


def _optional_float(val) -> Optional[float]:
    try:
        return float(val) if val is not None else None
    except (TypeError, ValueError):
        return None
