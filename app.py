from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import os, hmac, hashlib
from webull import webull

app = FastAPI()

# Webull login (paper)
wb = webull()
def login():
    if not wb.is_account_id_set():
        wb.login(os.getenv("WEBULL_USERNAME"), os.getenv("WEBULL_PASSWORD"))
        wb.get_trade_token(os.getenv("WEBULL_TRADING_PIN"))
login()

# Shared secret to verify BMS webhook
SECRET = os.getenv("BMS_WEBHOOK_SECRET")

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

def verify_signature(raw, sig):
    if not SECRET:
        return True
    mac = hmac.new(SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, sig or "")

@app.post("/trade")
async def trade(request: Request):
    raw = await request.body()
    if not verify_signature(raw, request.headers.get("X-BMS-Signature")):
        raise HTTPException(401, "Bad signature")
    data = BmsSignal.model_validate_json(raw)

    if data.bias not in ["CALL", "PUT"]:
        return {"status": "ignored", "reason": "neutral"}

    side = "BUY" if data.bias == "CALL" else "SELL"
    qty = max(1, int(5000 / data.price))  # fixed $5k size

    login()
    res = wb.place_order_stock_paper(
        stock=data.symbol, action=side, orderType="MKT",
        enforce="DAY", quant=qty
    )
    return {"status": "submitted", "side": side, "qty": qty, "result": res}
