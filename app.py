from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import os, hmac, hashlib, json
from webull import webull

app = FastAPI()

# --- config / globals ---
SECRET = os.getenv("BMS_WEBHOOK_SECRET", "")
WB_USER = os.getenv("WEBULL_USERNAME", "")
WB_PASS = os.getenv("WEBULL_PASSWORD", "")
WB_PIN  = os.getenv("WEBULL_TRADING_PIN", "")

wb = webull()
_logged_in = False

def try_login():
    """Lazy login only when needed; never at import-time."""
    global _logged_in
    if _logged_in:
        return
    if not (WB_USER and WB_PASS and WB_PIN):
        raise RuntimeError("Missing Webull env vars")

    # First login; if MFA is required, webull() raises
    res = wb.login(WB_USER, WB_PASS)
    # If your account enforces trade token, set it:
    wb.get_trade_token(WB_PIN)
    _logged_in = True

def verify_signature(raw: bytes, sig: str | None) -> bool:
    if not SECRET:
        return True
    mac = hmac.new(SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, sig or "")

class BmsSignal(BaseModel):
    source: str
    timestamp_et: str
    symbol: str
    bias: str
    confidence: int
    price: float
    orb: str
    vwap_sync: str
    idempotency_key: str

@app.get("/")
def health():
    return {"ok": True, "logged_in": _logged_in}

@app.post("/trade")
async def trade(request: Request):
    raw = await request.body()
    if not verify_signature(raw, request.headers.get("X-BMS-Signature")):
        raise HTTPException(401, "Bad signature")

    data = BmsSignal.model_validate_json(raw)

    # Gate: ignore neutral
    if data.bias not in ("CALL", "PUT"):
        return {"status": "ignored", "reason": "neutral"}

    # Try to login now (not at startup)
    try:
        try_login()
    except Exception as e:
        # App stays up; caller sees why we didn't place an order
        raise HTTPException(503, f"Webull login required (MFA/2FA needed?): {e}")

    side = "BUY" if data.bias == "CALL" else "SELL"
    qty = max(1, int(5000 / data.price))  # simple fixed sizing; adjust later

    try:
        res = wb.place_order_stock_paper(
            stock=data.symbol, action=side, orderType="MKT",
            enforce="DAY", quant=qty
        )
        return {"status": "submitted", "side": side, "qty": qty, "result": res}
    except Exception as e:
        raise HTTPException(500, f"webull_error: {e}")
