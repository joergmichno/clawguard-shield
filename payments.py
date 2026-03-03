"""
ClawGuard Shield — Stripe Payment Integration
Handles checkout sessions, webhooks, and subscription management.
"""

import os
import stripe
from database import get_db

# ─── Stripe Config ───────────────────────────────────────────────────────────

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")

STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

# Stripe Price IDs (set in .env after creating products in Stripe Dashboard)
STRIPE_PRICES = {
    "pro": os.environ.get("STRIPE_PRICE_PRO_ID", ""),
    "enterprise": os.environ.get("STRIPE_PRICE_ENTERPRISE_ID", ""),
}

# Base URL for redirects
BASE_URL = os.environ.get("BASE_URL", "https://prompttools.co")


# ─── Checkout ────────────────────────────────────────────────────────────────

def create_checkout_session(email: str, key_hash: str, tier: str) -> str | None:
    """Create a Stripe Checkout Session for upgrading to Pro or Enterprise.

    Returns the checkout URL or None on error.
    """
    price_id = STRIPE_PRICES.get(tier)
    if not price_id:
        return None

    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            payment_method_types=["card"],
            customer_email=email,
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=f"{BASE_URL}/shield?upgrade=success&tier={tier}",
            cancel_url=f"{BASE_URL}/shield?upgrade=cancelled",
            metadata={
                "key_hash": key_hash,
                "tier": tier,
            },
        )
        return session.url
    except stripe.StripeError:
        return None


def create_billing_portal_session(stripe_customer_id: str) -> str | None:
    """Create a Stripe Billing Portal session for managing subscriptions.

    Returns the portal URL or None on error.
    """
    try:
        session = stripe.billing_portal.Session.create(
            customer=stripe_customer_id,
            return_url=f"{BASE_URL}/shield",
        )
        return session.url
    except stripe.StripeError:
        return None


# ─── Webhook Processing ─────────────────────────────────────────────────────

def verify_webhook(payload: bytes, signature: str) -> dict | None:
    """Verify and parse a Stripe webhook event.

    Returns the event dict or None if verification fails.
    """
    try:
        event = stripe.Webhook.construct_event(
            payload, signature, STRIPE_WEBHOOK_SECRET
        )
        return event
    except (stripe.SignatureVerificationError, ValueError):
        return None


def handle_checkout_completed(event: dict) -> bool:
    """Process a checkout.session.completed event.

    Upgrades the user's tier and stores Stripe IDs.
    Returns True on success.
    """
    session = event["data"]["object"]
    metadata = session.get("metadata", {})
    key_hash = metadata.get("key_hash")
    tier = metadata.get("tier")
    customer_id = session.get("customer")
    subscription_id = session.get("subscription")

    if not key_hash or not tier:
        return False

    return upgrade_key_tier(
        key_hash=key_hash,
        tier=tier,
        stripe_customer_id=customer_id,
        stripe_subscription_id=subscription_id,
    )


def handle_subscription_updated(event: dict) -> bool:
    """Process subscription updates (cancellation, payment failure, etc.)."""
    subscription = event["data"]["object"]
    subscription_id = subscription.get("id")
    status = subscription.get("status")  # active, past_due, canceled, unpaid

    if not subscription_id:
        return False

    return update_subscription_status(subscription_id, status)


def handle_subscription_deleted(event: dict) -> bool:
    """Process subscription deletion — downgrade to free."""
    subscription = event["data"]["object"]
    subscription_id = subscription.get("id")

    if not subscription_id:
        return False

    return downgrade_to_free(subscription_id)


# ─── Database Operations ────────────────────────────────────────────────────

def upgrade_key_tier(
    key_hash: str,
    tier: str,
    stripe_customer_id: str | None = None,
    stripe_subscription_id: str | None = None,
) -> bool:
    """Upgrade an API key to a new tier and store Stripe IDs."""
    try:
        with get_db() as conn:
            conn.execute(
                """UPDATE api_keys
                   SET tier = ?,
                       stripe_customer_id = ?,
                       stripe_subscription_id = ?,
                       subscription_status = 'active'
                   WHERE key_hash = ? AND is_active = 1""",
                (tier, stripe_customer_id, stripe_subscription_id, key_hash),
            )
        return True
    except Exception:
        return False


def update_subscription_status(subscription_id: str, status: str) -> bool:
    """Update subscription status for a given Stripe subscription."""
    try:
        with get_db() as conn:
            conn.execute(
                """UPDATE api_keys
                   SET subscription_status = ?
                   WHERE stripe_subscription_id = ? AND is_active = 1""",
                (status, subscription_id),
            )
        return True
    except Exception:
        return False


def downgrade_to_free(subscription_id: str) -> bool:
    """Downgrade user to free tier when subscription is deleted."""
    try:
        with get_db() as conn:
            conn.execute(
                """UPDATE api_keys
                   SET tier = 'free',
                       subscription_status = 'canceled',
                       stripe_subscription_id = NULL
                   WHERE stripe_subscription_id = ? AND is_active = 1""",
                (subscription_id,),
            )
        return True
    except Exception:
        return False


def get_stripe_customer_id(key_hash: str) -> str | None:
    """Get the Stripe customer ID for an API key."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT stripe_customer_id FROM api_keys WHERE key_hash = ? AND is_active = 1",
            (key_hash,),
        ).fetchone()
        if row and row["stripe_customer_id"]:
            return row["stripe_customer_id"]
    return None
