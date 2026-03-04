import hashlib
import hmac
import logging

import httpx

from open_webui.config import (
    SPARKLOC_PAYMENT_TOKEN,
    SPARKLOC_PAYMENT_ID,
    SPARKLOC_CALLBACK_HOST,
    WEBUI_NAME,
)
from open_webui.env import GLOBAL_LOG_LEVEL

logger = logging.getLogger(__name__)
logger.setLevel(GLOBAL_LOG_LEVEL)


class SparklocClient:
    """
    Sparkloc payment client
    """

    def _get_secret_key(self) -> str:
        """Derive secret_key from token: SHA256(token)"""
        token = SPARKLOC_PAYMENT_TOKEN.value
        return hashlib.sha256(token.encode()).hexdigest()

    def sign(self, params: dict) -> str:
        """Generate HMAC-SHA256 signature for params"""
        secret_key = self._get_secret_key()
        # sort params alphabetically, exclude 'signature' itself
        sorted_params = sorted(
            (k, v) for k, v in params.items() if k != "signature"
        )
        param_string = "&".join(f"{k}={v}" for k, v in sorted_params)
        signature = hmac.new(
            secret_key.encode(),
            param_string.encode(),
            hashlib.sha256,
        ).hexdigest()
        return signature

    def verify(self, params: dict) -> bool:
        """Verify callback signature"""
        received_sig = params.get("signature", "")
        if not received_sig:
            return False
        expected_sig = self.sign(params)
        return hmac.compare_digest(received_sig, expected_sig)

    async def create_trade(self, out_trade_no: str, amount: float) -> dict:
        """Initiate a payment via Sparkloc API"""
        payment_id = SPARKLOC_PAYMENT_ID.value
        callback_host = SPARKLOC_CALLBACK_HOST.value.rstrip("/")

        params = {
            "out_trade_no": out_trade_no,
            "amount": f"{amount:.2f}",
            "description": f"{WEBUI_NAME} Credit",
            "notify_url": f"{callback_host}/api/v1/credit/callback/sparkloc",
            "return_url": f"{callback_host}",
        }
        params["signature"] = self.sign(params)

        client = httpx.AsyncClient()
        try:
            resp = await client.post(
                url=f"https://sparkloc.com/credit/payment/pay/{payment_id}/process.json",
                data=params,
            )
            data = resp.json()
            if data.get("payment_url"):
                return {
                    "code": 1,
                    "payurl": data["payment_url"],
                    "trade_no": out_trade_no,
                }
            return {"code": -1, "msg": data.get("error", str(data))}
        except Exception as err:
            logger.exception("sparkloc create trade error: %s", err)
            return {"code": -1, "msg": str(err)}
        finally:
            await client.aclose()


sparkloc_client = SparklocClient()
