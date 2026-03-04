import hashlib
import hmac
import logging

import httpx

from open_webui.config import (
    SPARKLOC_PAYMENT_TOKEN,
    SPARKLOC_PAYMENT_ID,
)
from open_webui.env import WEBUI_NAME

log = logging.getLogger(__name__)

SPARKLOC_BASE = "https://sparkloc.com"


class SparklocClient:
    def __init__(self):
        pass

    # ---------- signing ----------

    def _get_secret_key(self) -> str:
        """secret_key = SHA256(token)"""
        token = SPARKLOC_PAYMENT_TOKEN.value
        return hashlib.sha256(token.encode()).hexdigest()

    def sign(self, params: dict) -> str:
        """HMAC-SHA256(secret_key, sorted_param_string)"""
        secret_key = self._get_secret_key()
        sorted_params = sorted((k, v) for k, v in params.items() if k != "signature")
        param_string = "&".join(f"{k}={v}" for k, v in sorted_params)
        return hmac.new(
            secret_key.encode(),
            param_string.encode(),
            hashlib.sha256,
        ).hexdigest()

    def verify(self, params: dict) -> bool:
        """Verify callback signature."""
        received_sig = params.get("signature", "")
        verify_params = {k: v for k, v in params.items() if k != "signature"}
        expected_sig = self.sign(verify_params)
        return hmac.compare_digest(expected_sig, received_sig)

    # ---------- API ----------

    async def create_trade(self, out_trade_no: str, amount: int) -> dict:
        """
        POST /credit/payment/pay/{payment_id}/process.json

        Params: amount (int), description (str), order_id (str), signature (str)
        Returns: { payment_url, transaction_id, status, amount, is_test }
        """
        payment_id = SPARKLOC_PAYMENT_ID.value

        params = {
            "amount": amount,
            "description": f"{WEBUI_NAME} Credit",
            "order_id": out_trade_no,
        }
        params["signature"] = self.sign(params)

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{SPARKLOC_BASE}/credit/payment/pay/{payment_id}/process.json",
                data=params,
            )
            data = resp.json()
            log.info("sparkloc create_trade resp: %s", data)
            return data


sparkloc_client = SparklocClient()
