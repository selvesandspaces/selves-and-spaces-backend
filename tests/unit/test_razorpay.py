"""Gateway and settings tests. The real SDK runs with its HTTP call faked: no network."""

import pytest
import razorpay
import requests
from pydantic import ValidationError

from app.config import Settings
from app.payments.razorpay import REQUEST_TIMEOUT, DummyGateway, GatewayError, RazorpayGateway, sign

BASE = dict(_env_file=None, supabase_url="https://x.supabase.co", supabase_secret_key="k")
REAL = dict(razorpay_key_id="rzp_test_abc", razorpay_key_secret="secret", razorpay_webhook_secret="whsec")


class FakeOrders:
    def __init__(self, result=None, error=None):
        self.result, self.error, self.calls = result, error, []

    def create(self, data):
        self.calls.append(data)
        if self.error:
            raise self.error
        return self.result


def gateway_with(orders=None) -> RazorpayGateway:
    """The real gateway and the real SDK utility (signature checks); only the HTTP order call is faked."""
    client = razorpay.Client(auth=("rzp_test_abc", "secret"))
    client.order = orders or FakeOrders({"id": "order_real123"})
    return RazorpayGateway("rzp_test_abc", "secret", "whsec", client=client)


def test_create_order_sends_amount_currency_receipt():
    orders = FakeOrders({"id": "order_real123"})
    assert gateway_with(orders).create_order(20020, receipt="chk-1") == "order_real123"
    assert orders.calls == [{"amount": 20020, "currency": "INR", "receipt": "chk-1"}]


@pytest.mark.parametrize(
    "orders",
    [
        FakeOrders(error=razorpay.errors.BadRequestError("Authentication failed")),
        FakeOrders(error=razorpay.errors.ServerError("boom")),
        FakeOrders(error=razorpay.errors.GatewayError("bank down")),
        FakeOrders({"no": "id"}),
        FakeOrders(error=requests.ConnectTimeout("slow")),
    ],
)
def test_razorpay_failures_become_gateway_error(orders):
    with pytest.raises(GatewayError):
        gateway_with(orders).create_order(100, receipt="r")


def test_gateway_error_does_not_leak_the_key():
    orders = FakeOrders(error=requests.ConnectionError("connect failed for rzp_test_abc:secret"))
    with pytest.raises(GatewayError) as exc:
        gateway_with(orders).create_order(100, receipt="r")
    assert "secret" not in str(exc.value) and exc.value.__cause__ is None


def test_real_client_has_a_request_timeout():
    seen = {}

    class Probe(requests.adapters.HTTPAdapter):
        def send(self, request, **kwargs):
            seen.update(kwargs)
            raise requests.ConnectionError("no network in tests")

    gw = RazorpayGateway("rzp_test_abc", "secret", "whsec")
    gw._client.session.mount("https://", Probe())
    with pytest.raises(GatewayError):
        gw.create_order(100, receipt="r")
    assert seen["timeout"] == REQUEST_TIMEOUT


def test_payment_signature_matches_razorpays_documented_scheme():
    # Razorpay: hex HMAC-SHA256 of "<order_id>|<payment_id>" keyed by the key secret.
    gw = gateway_with()
    good = sign("secret", b"order_1|pay_1")
    assert gw.verify_payment_signature("order_1", "pay_1", good)
    assert not gw.verify_payment_signature("order_1", "pay_2", good)
    assert not gw.verify_payment_signature("order_2", "pay_1", good)
    assert not gw.verify_payment_signature("order_1", "pay_1", "")
    assert not gw.verify_payment_signature("order_1", "pay_1", sign("whsec", b"order_1|pay_1"))


def test_webhook_signature_uses_the_webhook_secret_not_the_key_secret():
    gw = gateway_with()
    assert gw.verify_webhook_signature(b'{"a":1}', sign("whsec", b'{"a":1}'))
    assert not gw.verify_webhook_signature(b'{"a":1}', sign("secret", b'{"a":1}'))
    assert not gw.verify_webhook_signature(b'{"a":2}', sign("whsec", b'{"a":1}'))


def test_webhook_body_that_is_not_utf8_is_rejected_not_crashed():
    assert not gateway_with().verify_webhook_signature(b"\xff\xfe", "anything")


def test_webhook_signature_covers_non_ascii_bodies():
    body = '{"note":"caf\u00e9 \u20b9"}'.encode()
    assert gateway_with().verify_webhook_signature(body, sign("whsec", body))


def test_dummy_gateway_round_trips_and_makes_unique_ids():
    gw = DummyGateway()
    a, b = gw.create_order(100, "r"), gw.create_order(100, "r")
    assert a != b and a.startswith("order_dummy")
    proof = gw.simulate_payment(a)
    assert gw.verify_payment_signature(proof["razorpay_order_id"], proof["razorpay_payment_id"], proof["razorpay_signature"])


# --- settings ---------------------------------------------------------------


def test_dummy_is_the_default_and_needs_no_keys():
    assert Settings(**BASE).razorpay_mode == "dummy"


def test_dummy_mode_is_refused_in_production():
    with pytest.raises(ValidationError, match="not allowed when ENVIRONMENT=production"):
        Settings(**BASE, environment="production", cors_origins="https://shop.example.com")


def test_real_modes_require_all_three_secrets():
    with pytest.raises(ValidationError, match="RAZORPAY_KEY_ID"):
        Settings(**BASE, razorpay_mode="test")
    with pytest.raises(ValidationError, match="RAZORPAY_WEBHOOK_SECRET"):
        Settings(**BASE, razorpay_mode="test", razorpay_key_id="rzp_test_a", razorpay_key_secret="s")


def test_key_prefix_must_match_mode():
    with pytest.raises(ValidationError, match="rzp_test_"):
        Settings(**BASE, razorpay_mode="test", **{**REAL, "razorpay_key_id": "rzp_live_abc"})
    with pytest.raises(ValidationError, match="rzp_live_"):
        Settings(**BASE, razorpay_mode="live", **REAL)


def test_valid_test_and_live_configs_load_and_production_may_use_live():
    assert Settings(**BASE, razorpay_mode="test", **REAL).razorpay_mode == "test"
    live = {**REAL, "razorpay_key_id": "rzp_live_abc"}
    assert Settings(
        **BASE, razorpay_mode="live", environment="production", cors_origins="https://shop.example.com", **live
    ).is_production


def test_secrets_are_not_in_repr():
    text = repr(Settings(**BASE, razorpay_mode="test", **REAL))
    assert "secret'" not in text and "whsec" not in text
