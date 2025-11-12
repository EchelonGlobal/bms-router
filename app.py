from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field
import os, hmac, hashlib, time, threading
from typing import Optional, Literal

from webull import webull

app = FastAPI(title="BMS → Webull Paper Router (Equity + Options w/ fallback)")

# ── ENV ────────────────────────────────────────────────────────────────────────
SECRET  = os.getenv("BMS_WEBHOOK_SECRET", "")
WB_USER = os.getenv("WEBULL_USERNAME", "")
WB_PASS = os.getenv("WEBULL_PASSWORD", "")
WB_PIN  = os.getenv("WEBULL_TRADING_PIN", "")
NOTIONAL_DEFAULT = float(os.getenv("NOTIONAL_DEFAULT", "5000"))
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"

# contract selection defaults if you let the router pick an option
DEFAULT_DELTA_TARGET = float(os.getenv("OPT_DELTA", "0.30"))   # ~0.30 contracts
DEFAULT_DTE_MAX = int(os.getenv("OPT_DTE_MAX", "7"))           # up to 1 week out

# ── Webull client (lazy login) ────────────────────────────────────────────────
wb = webull()
_logged_in = False
_login_lock = threading.Lock()

def lazy_login():
    global _logged_in
    if _logged_in:
        return
    with _login_lock:
        if _logged_in:
            return
        if not (WB_USER and WB_PASS and WB_PIN):
            raise RuntimeError("Missing WEBULL_USERNAME / WEBULL_PASSWORD / WEBULL_TRADING_PIN")
        wb.login(WB_USER, WB_PASS)
        wb.get_trade_token(WB_PIN)
        _logged_in = True

# ── HMAC ───────────────────────────────────────────────────────────────────────
def verify_signature(raw: bytes, sig_header: str | None) -> bool:
    if not SECRET:
        return True
    import hashlib, hmac
    mac = hmac.new(SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, sig_header or "")

# ── Payload model ──────────────────────────────────────────────────────────────
class BmsSignal(BaseModel):
    # common
    source: str = "BMS_Vacuum"
    timestamp_et: str
    product: Literal["equity","option"] = "equity"    # <— NEW
    symbol: str                                      # equity underlying (e.g., QQQ)
    bias: Literal["CALL","PUT","NEUTRAL"]
    confidence: int = 0
    price: float
    orb: str = ""
    vwap_sync: str = ""
    idempotency_key: str

    # optional option fields if product == "option"
    expiry: Optional[str] = None          # 'YYYY-MM-DD'
    strike: Optional[float] = None
    right: Optional[Literal["CALL","PUT"]] = None     # if omitted, uses bias
    contracts: Optional[int] = None       # if omitted, computed from notional

# ── Idempotency ────────────────────────────────────────────────────────────────
_seen = {}
TTL = 6*60*60
def is_dup(key: str)->bool:
    now = time.time()
    for k,t in list(_seen.items()):
        if now - t > TTL:
            del _seen[k]
    if key in _seen:
        return True
    _seen[key] = now
    return False

# ── Helpers ────────────────────────────────────────────────────────────────────
def shares_from_notional(notional: float, px: float) -> int:
    return max(1, int(notional // max(px, 0.01)))

def contracts_from_notional(notional: float, premium_per_share: float) -> int:
    # 1 contract = 100 shares
    per_contract = max(premium_per_share*100.0, 0.01)
    return max(1, int(notional // per_contract))

def ensure_equity_supported(sym: str):
    if sym.upper() in ("BTC","ETH","BTCUSD","ETHUSD"):
        raise HTTPException(422, "Webull PAPER options/equity supports stocks/ETFs, not crypto.")

def pick_option_contract(symbol: str, right: str):
    """
    Try to pick a near-term ~0.30 delta contract for the underlying.
    If the SDK or data is unavailable, raise to let caller fallback.
    """
    # get option chain summary
    chain = wb.get_options(symbol)
    if not chain or 'data' not in chain:
        raise RuntimeError("Options chain unavailable from Webull SDK.")

    # Find nearest expiry within DEFAULT_DTE_MAX
    # The SDK returns expirations; you'll need to adapt to the exact structure of your SDK version.
    expirations = chain.get('data', {}).get('list', [])
    if not expirations:
        raise RuntimeError("No expirations found.")
    today = time.time()

    # find the first expiry within DTE window
    target_exp = None
    for exp in expirations:
        # Example: exp might have 'expireDate' -> 'YYYY-MM-DD'
        ed = exp.get('expireDate')
        if not ed: 
            continue
        # rough DTE check
        try:
            t = time.mktime(time.strptime(ed, "%Y-%m-%d"))
            dte = (t - today)/86400.0
            if 0 < dte <= DEFAULT_DTE_MAX:
                target_exp = ed
                break
        except Exception:
            continue
    if not target_exp:
        # fallback to nearest expiry
        target_exp = expirations[0].get('expireDate')

    # Pull contracts list for that expiry
    chain_for_exp = wb.get_option_quote(symbol=symbol, expireDate=target_exp)
    if not chain_for_exp:
        raise RuntimeError("Option quotes unavailable for expiry.")

    # Flatten contracts on the right side and pick closest delta to target
    # NOTE: Structure varies by SDK; adapt fields if different on your version.
    cands = []
    for item in chain_for_exp.get('data', []):
        # Each item may have fields like 'strikePrice', 'call', 'put' with Greeks
        leg = item.get('call' if right=="CALL" else 'put')
        if not leg:
            continue
        delta = abs(float(leg.get('delta') or 0.0))
        price = float(leg.get('latestPrice') or 0.0)
        contractId = leg.get('contractId') or leg.get('symbol') or leg.get('contractSymbol')
        if not contractId:
            continue
        cands.append({
            "contractId": contractId,
            "strike": float(item.get('strikePrice')),
            "delta": delta,
            "last": price,
            "expiry": target_exp
        })

    if not cands:
        raise RuntimeError("No option candidates parsed for expiry/right.")

    cands.sort(key=lambda x: abs(x['delta']-DEFAULT_DELTA_TARGET))
    return cands[0]  # best match

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.get("/")
def health():
    return {"ok": True, "logged_in": _logged_in, "dry_run": DRY_RUN}

@app.post("/trade")
async def trade(req: Request):
    raw = await req.body()
    if not verify_signature(raw, req.headers.get("X-BMS-Signature")):
        raise HTTPException(401, "Bad signature")

    try:
        sig = BmsSignal.model_validate_json(raw)
    except Exception as e:
        raise HTTPException(400, f"Bad payload: {e}")

    if is_dup(sig.idempotency_key):
        return {"status": "duplicate_ignored"}

    if sig.bias not in ("CALL","PUT"):
        return {"status":"ignored","reason":"neutral"}

    ensure_equity_supported(sig.symbol)
    side = "BUY" if sig.bias=="CALL" else "SELL"

    if DRY_RUN:
        return {"status":"dry_run","product":sig.product,"symbol":sig.symbol,"side":side}

    try:
        lazy_login()
    except Exception as e:
        raise HTTPException(503, f"webull_login_required: {e}")

    # ====== OPTIONS PATH =======================================================
    if sig.product == "option":
        right = (sig.right or sig.bias)
        try:
            # If contract not provided, pick one
            chosen = None
            if sig.expiry and sig.strike is not None:
                # You could also implement a direct lookup by strike/expiry here
                chosen = pick_option_contract(sig.symbol, right)  # still pick best delta near that expiry
            else:
                chosen = pick_option_contract(sig.symbol, right)

            premium = max(chosen['last'], 0.05)  # guard; some feeds return 0
            contracts = sig.contracts or contracts_from_notional(NOTIONAL_DEFAULT, premium)
            if contracts <= 0:
                raise RuntimeError("Computed contracts <= 0")

            # Try to place paper options order (SDK support varies by version)
            try:
                res = wb.place_order_option_paper(
                    symbol=sig.symbol,
                    action=side,
                    orderType="MKT",
                    enforce="DAY",
                    contracts=contracts,
                    contractId=chosen['contractId']
                )
                return {"status":"submitted_option", "symbol":sig.symbol, "contracts":contracts, "right":right, "expiry":chosen['expiry'], "strike":chosen['strike'], "res":res}
            except Exception as e:
                # Fall back to equity if SDK can't place option paper
                eq_qty = shares_from_notional(NOTIONAL_DEFAULT, max(sig.price, 0.01))
                res2 = wb.place_order_stock_paper(stock=sig.symbol, action=side, orderType="MKT", enforce="DAY", quant=eq_qty)
                return {"status":"fallback_equity", "reason":f"options_failed: {e}", "equity_qty":eq_qty, "res":res2}

        except HTTPException:
            raise
        except Exception as e:
            # total failure on option leg -> equity fallback
            eq_qty = shares_from_notional(NOTIONAL_DEFAULT, max(sig.price, 0.01))
            try:
                res2 = wb.place_order_stock_paper(stock=sig.symbol, action=side, orderType="MKT", enforce="DAY", quant=eq_qty)
                return {"status":"fallback_equity", "reason":f"options_unavailable: {e}", "equity_qty":eq_qty, "res":res2}
            except Exception as e2:
                raise HTTPException(502, f"webull_equity_fallback_failed: {e2}")

    # ====== EQUITY PATH ========================================================
    qty = shares_from_notional(NOTIONAL_DEFAULT, max(sig.price, 0.01))
    try:
        res = wb.place_order_stock_paper(stock=sig.symbol, action=side, orderType="MKT", enforce="DAY", quant=qty)
        return {"status":"submitted_equity","symbol":sig.symbol,"qty":qty,"res":res}
    except Exception as e:
        raise HTTPException(502, f"webull_equity_error: {e}")
