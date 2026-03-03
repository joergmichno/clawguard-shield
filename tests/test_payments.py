"""
Tests for Stripe payment integration endpoints.
"""

import json
from unittest.mock import patch, MagicMock

# Note: Functions are imported into app.py, so we patch them at 'app.*'
# not 'payments.*' — that's how Python mocking works.


class TestUpgradeEndpoint:
    """Tests for POST /api/v1/upgrade."""

    def test_upgrade_requires_auth(self, client):
        """Upgrade endpoint requires API key."""
        resp = client.post("/api/v1/upgrade", json={"tier": "pro"})
        assert resp.status_code == 401

    def test_upgrade_invalid_tier(self, client, api_key):
        """Upgrade with invalid tier returns 400."""
        resp = client.post(
            "/api/v1/upgrade",
            json={"tier": "gold"},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error"] == "invalid_tier"

    def test_upgrade_already_on_tier(self, client, pro_api_key):
        """Upgrade to current tier returns 400."""
        resp = client.post(
            "/api/v1/upgrade",
            json={"tier": "pro"},
            headers={"X-API-Key": pro_api_key},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error"] == "already_on_tier"

    @patch("app.create_checkout_session")
    def test_upgrade_success(self, mock_checkout, client, api_key):
        """Upgrade returns checkout URL on success."""
        mock_checkout.return_value = "https://checkout.stripe.com/test_session"

        resp = client.post(
            "/api/v1/upgrade",
            json={"tier": "pro"},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "checkout_url" in data
        assert data["checkout_url"] == "https://checkout.stripe.com/test_session"

    @patch("app.create_checkout_session")
    def test_upgrade_stripe_not_configured(self, mock_checkout, client, api_key):
        """Upgrade returns 503 when Stripe is not configured."""
        mock_checkout.return_value = None

        resp = client.post(
            "/api/v1/upgrade",
            json={"tier": "pro"},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 503
        data = resp.get_json()
        assert data["error"] == "checkout_error"

    def test_upgrade_default_tier_is_pro(self, client, api_key):
        """Upgrade with no tier specified defaults to pro."""
        with patch("app.create_checkout_session") as mock:
            mock.return_value = "https://checkout.stripe.com/test"
            resp = client.post(
                "/api/v1/upgrade",
                json={},
                headers={"X-API-Key": api_key},
            )
            assert resp.status_code == 200
            mock.assert_called_once()
            # Verify 'pro' was passed as the tier
            call_kwargs = mock.call_args
            assert "pro" in str(call_kwargs)


class TestStripeWebhook:
    """Tests for POST /api/v1/webhook/stripe."""

    def test_webhook_invalid_signature(self, client):
        """Webhook with invalid signature returns 400."""
        resp = client.post(
            "/api/v1/webhook/stripe",
            data=b"{}",
            headers={"Stripe-Signature": "invalid"},
            content_type="application/json",
        )
        assert resp.status_code == 400

    @patch("app.verify_webhook")
    @patch("app.handle_checkout_completed")
    def test_webhook_checkout_completed(self, mock_handle, mock_verify, client):
        """Webhook processes checkout.session.completed."""
        mock_verify.return_value = {
            "type": "checkout.session.completed",
            "data": {"object": {"metadata": {"key_hash": "abc", "tier": "pro"}}},
        }
        mock_handle.return_value = True

        resp = client.post(
            "/api/v1/webhook/stripe",
            data=b'{"type": "checkout.session.completed"}',
            headers={"Stripe-Signature": "valid"},
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["received"] is True
        mock_handle.assert_called_once()

    @patch("app.verify_webhook")
    def test_webhook_unknown_event(self, mock_verify, client):
        """Webhook acknowledges unknown events with 200."""
        mock_verify.return_value = {
            "type": "some.unknown.event",
            "data": {"object": {}},
        }

        resp = client.post(
            "/api/v1/webhook/stripe",
            data=b'{"type": "some.unknown.event"}',
            headers={"Stripe-Signature": "valid"},
            content_type="application/json",
        )
        assert resp.status_code == 200


class TestBillingEndpoint:
    """Tests for POST /api/v1/billing."""

    def test_billing_requires_auth(self, client):
        """Billing endpoint requires API key."""
        resp = client.post("/api/v1/billing")
        assert resp.status_code == 401

    def test_billing_no_subscription(self, client, api_key):
        """Billing returns 404 when no subscription exists."""
        resp = client.post(
            "/api/v1/billing",
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 404
        data = resp.get_json()
        assert data["error"] == "no_subscription"

    @patch("app.get_stripe_customer_id")
    @patch("app.create_billing_portal_session")
    def test_billing_success(self, mock_portal, mock_customer, client, api_key):
        """Billing returns portal URL on success."""
        mock_customer.return_value = "cus_test123"
        mock_portal.return_value = "https://billing.stripe.com/session/test"

        resp = client.post(
            "/api/v1/billing",
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "portal_url" in data


class TestPaymentDatabaseOperations:
    """Tests for payment-related database operations."""

    def test_upgrade_key_tier(self, api_key):
        """Upgrading tier persists in database."""
        from auth import hash_key
        from payments import upgrade_key_tier
        from database import get_api_key

        key_hash = hash_key(api_key)
        result = upgrade_key_tier(
            key_hash=key_hash,
            tier="pro",
            stripe_customer_id="cus_test123",
            stripe_subscription_id="sub_test456",
        )
        assert result is True

        # Verify in database
        key_data = get_api_key(key_hash)
        assert key_data["tier"] == "pro"
        assert key_data["stripe_customer_id"] == "cus_test123"
        assert key_data["stripe_subscription_id"] == "sub_test456"
        assert key_data["subscription_status"] == "active"

    def test_downgrade_to_free(self, api_key):
        """Downgrading resets tier to free."""
        from auth import hash_key
        from payments import upgrade_key_tier, downgrade_to_free
        from database import get_api_key

        key_hash = hash_key(api_key)

        # First upgrade
        upgrade_key_tier(key_hash, "pro", "cus_test", "sub_test789")

        # Then downgrade
        result = downgrade_to_free("sub_test789")
        assert result is True

        key_data = get_api_key(key_hash)
        assert key_data["tier"] == "free"
        assert key_data["subscription_status"] == "canceled"

    def test_update_subscription_status(self, api_key):
        """Subscription status updates persist."""
        from auth import hash_key
        from payments import upgrade_key_tier, update_subscription_status
        from database import get_api_key

        key_hash = hash_key(api_key)
        upgrade_key_tier(key_hash, "pro", "cus_test", "sub_status_test")

        result = update_subscription_status("sub_status_test", "past_due")
        assert result is True

        key_data = get_api_key(key_hash)
        assert key_data["subscription_status"] == "past_due"

    def test_get_stripe_customer_id(self, api_key):
        """Can retrieve Stripe customer ID."""
        from auth import hash_key
        from payments import upgrade_key_tier, get_stripe_customer_id

        key_hash = hash_key(api_key)

        # Before upgrade: no customer ID
        assert get_stripe_customer_id(key_hash) is None

        # After upgrade: has customer ID
        upgrade_key_tier(key_hash, "pro", "cus_lookup_test", "sub_xxx")
        assert get_stripe_customer_id(key_hash) == "cus_lookup_test"


class TestUpgradedTierBehavior:
    """Tests that upgraded keys get proper tier limits."""

    def test_upgraded_key_gets_pro_limits(self, client, api_key):
        """After upgrade, API key gets Pro tier limits."""
        from auth import hash_key
        from payments import upgrade_key_tier

        key_hash = hash_key(api_key)
        upgrade_key_tier(key_hash, "pro", "cus_test", "sub_test")

        # Check usage endpoint shows pro tier
        resp = client.get(
            "/api/v1/usage",
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["tier"] == "pro"
        assert data["daily_limit"] == 10000

    def test_upgraded_key_accepts_larger_text(self, client, api_key):
        """Pro key can scan larger texts."""
        from auth import hash_key
        from payments import upgrade_key_tier

        key_hash = hash_key(api_key)
        upgrade_key_tier(key_hash, "pro", "cus_test", "sub_test")

        # Free limit is 5000 chars, Pro is 50000
        large_text = "A" * 10000  # Over free limit, under pro limit
        resp = client.post(
            "/api/v1/scan",
            json={"text": large_text},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 200
