"""
Tests for authentication system.
"""

from auth import generate_api_key, hash_key, validate_key_format, get_key_prefix, TIER_LIMITS


class TestKeyGeneration:
    """API key generation and format."""

    def test_key_starts_with_prefix(self):
        key = generate_api_key()
        assert key.startswith("cgs_")

    def test_key_correct_length(self):
        key = generate_api_key()
        # cgs_ (4) + 32 hex = 36 total
        assert len(key) == 36

    def test_keys_are_unique(self):
        keys = {generate_api_key() for _ in range(100)}
        assert len(keys) == 100

    def test_key_is_hex_after_prefix(self):
        key = generate_api_key()
        hex_part = key[4:]
        int(hex_part, 16)  # Should not raise


class TestKeyHashing:
    """SHA-256 hashing."""

    def test_hash_is_deterministic(self):
        key = "cgs_abc123"
        assert hash_key(key) == hash_key(key)

    def test_hash_is_64_chars(self):
        h = hash_key("cgs_test")
        assert len(h) == 64

    def test_different_keys_different_hashes(self):
        h1 = hash_key("cgs_key1")
        h2 = hash_key("cgs_key2")
        assert h1 != h2


class TestKeyValidation:
    """Format validation."""

    def test_valid_key(self):
        key = generate_api_key()
        assert validate_key_format(key) is True

    def test_invalid_prefix(self):
        assert validate_key_format("xyz_0000000000000000000000000000abcd") is False

    def test_too_short(self):
        assert validate_key_format("cgs_abc") is False

    def test_too_long(self):
        assert validate_key_format("cgs_" + "a" * 64) is False

    def test_non_hex(self):
        assert validate_key_format("cgs_gggggggggggggggggggggggggggggggg") is False

    def test_empty(self):
        assert validate_key_format("") is False


class TestKeyPrefix:
    """Display prefix extraction."""

    def test_prefix_truncated(self):
        key = generate_api_key()
        prefix = get_key_prefix(key)
        assert prefix.endswith("...")
        assert len(prefix) == 15  # 12 chars + ...


class TestTierLimits:
    """Tier configuration."""

    def test_free_tier(self):
        assert TIER_LIMITS["free"]["monthly_limit"] == 3
        assert TIER_LIMITS["free"]["daily_limit"] is None
        assert TIER_LIMITS["free"]["max_text_length"] == 5000

    def test_pro_tier(self):
        assert TIER_LIMITS["pro"]["daily_limit"] == 1000
        assert TIER_LIMITS["pro"]["monthly_limit"] is None
        assert TIER_LIMITS["pro"]["max_text_length"] == 50000

    def test_enterprise_tier(self):
        assert TIER_LIMITS["enterprise"]["daily_limit"] is None
        assert TIER_LIMITS["enterprise"]["monthly_limit"] is None
        assert TIER_LIMITS["enterprise"]["max_text_length"] == 200000

    def test_all_tiers_exist(self):
        assert set(TIER_LIMITS.keys()) == {"free", "pro", "enterprise"}
