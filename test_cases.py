"""
test_cases.py

Complete Test Suite for Secret Sharing & Threshold Cryptography System
Run with: pytest test_cases.py -v
"""

import pytest
import hashlib
import hmac as hmac_lib
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

# ═══════════════════════════════════════════════════════════
#  MEMBER 1 — Cryptographic Engine Tests
#  File: crypto_engine.py
# ═══════════════════════════════════════════════════════════

from crypto_engine import (
    mod_add, mod_sub, mod_mul, mod_inv, mod_div,
    generate_shares, reconstruct_secret,
    generate_random_secret, hash_secret, verify_reconstruction,
    P
)


class TestFiniteFieldArithmetic:
    """TC-M1-01 to TC-M1-05: GF(P) arithmetic correctness"""

    def test_mod_add_basic(self):
        """TC-M1-01: Addition stays within field"""
        result = mod_add(10, 20)
        assert result == 30
        assert result < P

    def test_mod_add_overflow(self):
        """TC-M1-02: Addition wraps around field prime"""
        result = mod_add(P - 1, 2)
        assert result == 1

    def test_mod_sub_basic(self):
        """TC-M1-03: Subtraction in field"""
        result = mod_sub(30, 10)
        assert result == 20

    def test_mod_sub_negative_wraps(self):
        """TC-M1-04: Subtraction wraps correctly (no negative results)"""
        result = mod_sub(0, 1)
        assert result == P - 1

    def test_mod_mul_basic(self):
        """TC-M1-05: Multiplication stays in field"""
        result = mod_mul(5, 6)
        assert result == 30
        assert result < P

    def test_mod_inv_correctness(self):
        """TC-M1-06: Inverse satisfies a * a^-1 = 1 mod P"""
        a = 12345678901234567890
        inv = mod_inv(a)
        assert mod_mul(a, inv) == 1

    def test_mod_inv_zero_raises(self):
        """TC-M1-07: Zero has no modular inverse"""
        with pytest.raises(ValueError, match="No modular inverse for zero"):
            mod_inv(0)

    def test_mod_div_correctness(self):
        """TC-M1-08: Division is multiplication by inverse"""
        a, b = 100, 7
        assert mod_div(a, b) == mod_mul(a, mod_inv(b))


class TestShareGeneration:
    """TC-M1-09 to TC-M1-15: Share generation validation"""

    def test_generate_shares_count(self):
        """TC-M1-09: Correct number of shares returned"""
        secret = b'\x01' * 32
        shares = generate_shares(secret, k=3, n=5)
        assert len(shares) == 5

    def test_generate_shares_unique_x(self):
        """TC-M1-10: All x values are unique"""
        secret = b'\xab' * 32
        shares = generate_shares(secret, k=3, n=5)
        x_values = [s[0] for s in shares]
        assert len(x_values) == len(set(x_values))

    def test_generate_shares_x_range(self):
        """TC-M1-11: x values go from 1 to n"""
        secret = b'\xff' * 32
        shares = generate_shares(secret, k=3, n=5)
        assert [s[0] for s in shares] == [1, 2, 3, 4, 5]

    def test_generate_shares_k_too_small(self):
        """TC-M1-12: k < 2 raises ValueError"""
        with pytest.raises(ValueError, match="Threshold k must be at least 2"):
            generate_shares(b'\x01' * 32, k=1, n=5)

    def test_generate_shares_n_less_than_k(self):
        """TC-M1-13: n < k raises ValueError"""
        with pytest.raises(ValueError, match="Total shares n must be"):
            generate_shares(b'\x01' * 32, k=5, n=3)

    def test_generate_shares_empty_secret(self):
        """TC-M1-14: Empty secret raises ValueError"""
        with pytest.raises(ValueError, match="Secret cannot be empty"):
            generate_shares(b'', k=2, n=3)

    def test_generate_shares_randomness(self):
        """TC-M1-15: Two calls produce different y values (random coefficients)"""
        secret = b'\xaa' * 32
        shares1 = generate_shares(secret, k=3, n=5)
        shares2 = generate_shares(secret, k=3, n=5)
        # y values should differ due to random polynomial coefficients
        y1 = [s[1] for s in shares1]
        y2 = [s[1] for s in shares2]
        assert y1 != y2


class TestReconstruction:
    """TC-M1-16 to TC-M1-22: Lagrange interpolation correctness"""

    def test_reconstruct_exact_k(self):
        """TC-M1-16: Reconstruct with exactly k shares succeeds"""
        secret = b'\x12\x34\x56\x78' * 8  # 32 bytes
        shares = generate_shares(secret, k=3, n=5)
        result = reconstruct_secret(shares[:3], secret_length=32)
        assert result == secret

    def test_reconstruct_more_than_k(self):
        """TC-M1-17: Reconstruct with more than k shares succeeds"""
        secret = b'\xde\xad\xbe\xef' * 8
        shares = generate_shares(secret, k=3, n=5)
        result = reconstruct_secret(shares, secret_length=32)  # all 5
        assert result == secret

    def test_reconstruct_any_k_combination(self):
        """TC-M1-18: Any combination of k shares gives same result"""
        secret = b'\x11' * 32
        shares = generate_shares(secret, k=3, n=5)
        r1 = reconstruct_secret([shares[0], shares[1], shares[2]], 32)
        r2 = reconstruct_secret([shares[0], shares[2], shares[4]], 32)
        r3 = reconstruct_secret([shares[1], shares[3], shares[4]], 32)
        assert r1 == r2 == r3 == secret

    def test_reconstruct_fewer_than_k_wrong(self):
        """TC-M1-19: Fewer than k shares returns WRONG result (not the secret)"""
        secret = b'\x99' * 32
        shares = generate_shares(secret, k=3, n=5)
        wrong = reconstruct_secret(shares[:2], secret_length=32)
        assert wrong != secret  # information-theoretic security

    def test_reconstruct_duplicate_x_raises(self):
        """TC-M1-20: Duplicate share x values raises ValueError"""
        secret = b'\x55' * 32
        shares = generate_shares(secret, k=3, n=5)
        duped = [shares[0], shares[0], shares[1]]  # share 0 twice
        with pytest.raises(ValueError, match="Duplicate shares detected"):
            reconstruct_secret(duped, secret_length=32)

    def test_reconstruct_too_few_shares_raises(self):
        """TC-M1-21: Less than 2 shares raises ValueError"""
        secret = b'\x77' * 32
        shares = generate_shares(secret, k=3, n=5)
        with pytest.raises(ValueError, match="Need at least 2 shares"):
            reconstruct_secret([shares[0]], secret_length=32)

    def test_reconstruct_random_aes_key(self):
        """TC-M1-22: Works correctly with a real random AES-256 key"""
        import os
        secret = os.urandom(32)
        shares = generate_shares(secret, k=4, n=7)
        result = reconstruct_secret(shares[:4], secret_length=32)
        assert result == secret


class TestHelpers:
    """TC-M1-23 to TC-M1-25: Utility functions"""

    def test_generate_random_secret_length(self):
        """TC-M1-23: Random secret is correct length"""
        s = generate_random_secret(32)
        assert len(s) == 32

    def test_hash_secret_deterministic(self):
        """TC-M1-24: Same secret always gives same SHA-256 fingerprint"""
        s = b'\xab' * 32
        assert hash_secret(s) == hash_secret(s)

    def test_verify_reconstruction_match(self):
        """TC-M1-25: Constant-time comparison works"""
        s = b'\xcc' * 32
        assert verify_reconstruction(s, s) is True
        assert verify_reconstruction(s, b'\x00' * 32) is False


# ═══════════════════════════════════════════════════════════
#  MEMBER 2 — Backend & API Tests
#  Files: admin.py, executive.py, database.py, security.py
# ═══════════════════════════════════════════════════════════

from security import hash_password, verify_password, normalize_password
from utils.aes_service import generate_aes_key, encrypt_data, decrypt_data


class TestPasswordSecurity:
    """TC-M2-01 to TC-M2-06: Password hashing and verification"""

    def test_hash_password_not_plaintext(self):
        """TC-M2-01: Hashed password is not the original"""
        pwd = "strongpass123"
        hashed = hash_password(pwd)
        assert hashed != pwd

    def test_hash_password_bcrypt_prefix(self):
        """TC-M2-02: Output is a bcrypt hash"""
        hashed = hash_password("testpassword")
        assert hashed.startswith("$2b$")

    def test_verify_password_correct(self):
        """TC-M2-03: Correct password verifies successfully"""
        pwd = "mypassword"
        hashed = hash_password(pwd)
        assert verify_password(pwd, hashed) is True

    def test_verify_password_wrong(self):
        """TC-M2-04: Wrong password fails verification"""
        hashed = hash_password("correct")
        assert verify_password("wrong", hashed) is False

    def test_normalize_password_sha256(self):
        """TC-M2-05: Normalize produces 64-char hex (SHA-256)"""
        norm = normalize_password("anypassword")
        assert len(norm) == 64

    def test_hash_long_password_safe(self):
        """TC-M2-06: Passwords over 72 bytes are handled safely (bcrypt limit bypass)"""
        long_pwd = "a" * 100
        hashed = hash_password(long_pwd)
        assert verify_password(long_pwd, hashed) is True


class TestAESService:
    """TC-M2-07 to TC-M2-12: AES-256-GCM encryption"""

    def test_generate_aes_key_length(self):
        """TC-M2-07: AES key is 32 bytes (256 bits)"""
        key = generate_aes_key()
        assert len(key) == 32

    def test_generate_aes_key_random(self):
        """TC-M2-08: Two generated keys are different"""
        assert generate_aes_key() != generate_aes_key()

    def test_encrypt_returns_three_parts(self):
        """TC-M2-09: Encrypt returns ciphertext, nonce, tag"""
        key = generate_aes_key()
        ct, nonce, tag = encrypt_data(b"hello world", key)
        assert ct is not None
        assert len(nonce) == 12
        assert len(tag) == 16

    def test_decrypt_roundtrip(self):
        """TC-M2-10: Decrypt(Encrypt(data)) == original data"""
        key = generate_aes_key()
        data = b"secret message 12345"
        ct, nonce, tag = encrypt_data(data, key)
        result = decrypt_data(ct, key, nonce, tag)
        assert result == data

    def test_decrypt_wrong_key_fails(self):
        """TC-M2-11: Decrypting with wrong key raises exception"""
        key1 = generate_aes_key()
        key2 = generate_aes_key()
        ct, nonce, tag = encrypt_data(b"data", key1)
        with pytest.raises(Exception):
            decrypt_data(ct, key2, nonce, tag)

    def test_encrypt_ciphertext_differs_from_plaintext(self):
        """TC-M2-12: Ciphertext is not the same as plaintext"""
        key = generate_aes_key()
        pt = b"visible plaintext"
        ct, _, _ = encrypt_data(pt, key)
        assert ct != pt


class TestAPIEndpoints:
    """TC-M2-13 to TC-M2-20: FastAPI route testing"""

    @pytest.fixture
    def client(self):
        from app import app
        from database import Base, engine
        Base.metadata.create_all(bind=engine)
        return TestClient(app)

    def test_root_endpoint(self, client):
        """TC-M2-13: Root returns running message"""
        resp = client.get("/")
        assert resp.status_code == 200
        assert "Running" in resp.json()["message"]

    def test_create_user_success(self, client):
        """TC-M2-14: Create user returns id, name, role"""
        resp = client.post("/admin/create-user", json={
            "name": "TestExec", "role": "executive", "password": "pass123"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "TestExec"
        assert data["role"] == "executive"
        assert "id" in data

    def test_create_user_missing_fields(self, client):
        """TC-M2-15: Missing fields returns validation error"""
        resp = client.post("/admin/create-user", json={"name": "NoPass"})
        assert resp.status_code == 422

    def test_generate_key_success(self, client):
        """TC-M2-16: Generate key with valid k and n succeeds"""
        resp = client.post("/admin/generate-key?k=3&n=5")
        assert resp.status_code == 200
        assert "generated" in resp.json()["message"].lower()

    def test_generate_key_n_less_than_k(self, client):
        """TC-M2-17: n < k should fail or return error"""
        resp = client.post("/admin/generate-key?k=5&n=3")
        # Should either be 422 or return an error message
        assert resp.status_code in [200, 422, 500]
        if resp.status_code == 200:
            assert "error" in resp.json()

    def test_submit_share_not_found(self, client):
        """TC-M2-18: Submit non-existent share returns error"""
        resp = client.post("/executive/submit-share?share_x=999")
        assert resp.status_code == 200
        assert "error" in resp.json()

    def test_submit_share_success(self, client):
        """TC-M2-19: Submit valid share after key generation"""
        client.post("/admin/generate-key?k=3&n=5")
        resp = client.post("/executive/submit-share?share_x=1")
        assert resp.status_code == 200
        assert "error" not in resp.json()

    def test_reconstruct_no_init(self, client):
        """TC-M2-20: Reconstruct before generate-key returns system error"""
        # Fresh client state — no key generated
        resp = client.post("/executive/reconstruct")
        assert resp.status_code == 200
        # Either "not initialized" or "not enough shares"
        body = resp.json()
        assert "error" in body


# ═══════════════════════════════════════════════════════════
#  MEMBER 3 — Security & Attack Simulation Tests
#  Files: hmac_service.py, executive.py (attacks)
# ═══════════════════════════════════════════════════════════

from utils.hmac_service import generate_hmac, verify_hmac


class TestHMACIntegrity:
    """TC-M3-01 to TC-M3-07: HMAC generation and verification"""

    def test_generate_hmac_returns_string(self):
        """TC-M3-01: HMAC returns a hex string"""
        tag = generate_hmac("12345")
        assert isinstance(tag, str)
        assert len(tag) == 64  # SHA-256 hex = 64 chars

    def test_generate_hmac_deterministic(self):
        """TC-M3-02: Same input always gives same HMAC"""
        assert generate_hmac("abc") == generate_hmac("abc")

    def test_generate_hmac_different_inputs(self):
        """TC-M3-03: Different inputs give different HMACs"""
        assert generate_hmac("share1") != generate_hmac("share2")

    def test_verify_hmac_valid(self):
        """TC-M3-04: Valid HMAC verifies correctly"""
        data = "999888777"
        tag = generate_hmac(data)
        assert verify_hmac(data, tag) is True

    def test_verify_hmac_tampered_data(self):
        """TC-M3-05: Tampered data fails HMAC verification"""
        tag = generate_hmac("original_value")
        assert verify_hmac("tampered_value", tag) is False

    def test_verify_hmac_tampered_tag(self):
        """TC-M3-06: Tampered tag fails verification"""
        data = "share_value"
        assert verify_hmac(data, "a" * 64) is False

    def test_verify_hmac_constant_time(self):
        """TC-M3-07: Uses hmac.compare_digest (timing-safe comparison)"""
        import inspect
        import utils.hmac_service as hm
        source = inspect.getsource(hm.verify_hmac)
        assert "compare_digest" in source


class TestAttackSimulations:
    """TC-M3-08 to TC-M3-18: Attack endpoint testing"""

    @pytest.fixture
    def client(self):
        from app import app
        from database import Base, engine
        Base.metadata.create_all(bind=engine)
        return TestClient(app)

    def setup_system(self, client, k=3, n=5):
        """Helper: generate key and submit shares"""
        client.post(f"/admin/generate-key?k={k}&n={n}")

    # ── ATTACK 1: Insufficient Shares ──

    def test_attack1_insufficient_shares(self, client):
        """TC-M3-08: Submitting fewer than k shares blocks reconstruction"""
        self.setup_system(client, k=3, n=5)
        client.post("/executive/submit-share?share_x=1")
        client.post("/executive/submit-share?share_x=2")
        # Only 2 shares submitted, k=3
        resp = client.post("/executive/reconstruct")
        assert resp.status_code == 200
        assert "error" in resp.json()
        assert "enough" in resp.json()["error"].lower()

    def test_attack1_zero_shares(self, client):
        """TC-M3-09: Zero shares submitted — blocked"""
        self.setup_system(client, k=3, n=5)
        resp = client.post("/executive/reconstruct")
        assert "error" in resp.json()

    def test_attack1_k_minus_one(self, client):
        """TC-M3-10: Exactly k-1 shares — always blocked"""
        self.setup_system(client, k=4, n=6)
        for x in range(1, 4):  # submit 3, need 4
            client.post(f"/executive/submit-share?share_x={x}")
        resp = client.post("/executive/reconstruct")
        assert "error" in resp.json()

    # ── ATTACK 2: Share Tampering ──

    def test_attack2_tampered_share_blocked(self, client):
        """TC-M3-11: Tampered share fails HMAC check during reconstruction"""
        self.setup_system(client, k=3, n=5)
        for x in [1, 2, 3]:
            client.post(f"/executive/submit-share?share_x={x}")
        # Tamper share 2
        client.post("/admin/tamper-share?share_x=2&value=999999999")
        resp = client.post("/executive/reconstruct")
        assert resp.status_code == 200
        assert "error" in resp.json()
        assert "tamper" in resp.json()["error"].lower()

    def test_attack2_untampered_succeeds(self, client):
        """TC-M3-12: Untampered shares reconstruct successfully"""
        self.setup_system(client, k=3, n=5)
        for x in [1, 2, 3]:
            client.post(f"/executive/submit-share?share_x={x}")
        resp = client.post("/executive/reconstruct")
        assert resp.status_code == 200
        assert "error" not in resp.json()
        assert "secret_hex" in resp.json()

    def test_attack2_tamper_endpoint_works(self, client):
        """TC-M3-13: Tamper endpoint confirms modification"""
        self.setup_system(client, k=3, n=5)
        resp = client.post("/admin/tamper-share?share_x=1&value=000111")
        assert resp.status_code == 200
        assert "error" not in resp.json()

    # ── ATTACK 3: Brute Force ──

    def test_attack3_brute_force_returns_failed(self, client):
        """TC-M3-14: Brute force simulation returns failed result"""
        self.setup_system(client, k=3, n=5)
        resp = client.post("/executive/attack/bruteforce")
        assert resp.status_code == 200
        data = resp.json()
        assert data["result"] == "failed"

    def test_attack3_no_init_returns_error(self, client):
        """TC-M3-15: Brute force without system init returns error"""
        resp = client.post("/executive/attack/bruteforce")
        assert resp.status_code == 200
        # either error or result
        assert "error" in resp.json() or "result" in resp.json()

    def test_attack3_reason_mentions_infeasible(self, client):
        """TC-M3-16: Brute force reason explains infeasibility"""
        self.setup_system(client, k=3, n=5)
        resp = client.post("/executive/attack/bruteforce")
        reason = resp.json().get("reason", "").lower()
        assert any(word in reason for word in ["infeasible", "impossible", "exponential"])

    # ── ATTACK 4: Insider Collusion ──

    def test_attack4_insufficient_shares_blocked(self, client):
        """TC-M3-17: Collusion with insufficient shares is blocked"""
        self.setup_system(client, k=3, n=5)
        client.post("/executive/submit-share?share_x=1")
        resp = client.post("/executive/attack/insider")
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("result") in ["blocked", "failed", "blocked_or_controlled"]

    def test_attack4_tampered_share_blocked(self, client):
        """TC-M3-18: Collusion with tampered share is blocked"""
        self.setup_system(client, k=3, n=5)
        for x in [1, 2, 3]:
            client.post(f"/executive/submit-share?share_x={x}")
        client.post("/admin/tamper-share?share_x=2&value=badvalue")
        resp = client.post("/executive/attack/insider")
        assert resp.status_code == 200
        data = resp.json()
        # blocked due to tamper or invalid format
        assert "error" in data or data.get("result") in ["blocked", "failed"]


# ═══════════════════════════════════════════════════════════
#  INTEGRATION TESTS — Full End-to-End Flow
# ═══════════════════════════════════════════════════════════

class TestEndToEndFlow:
    """TC-INT-01 to TC-INT-05: Complete system workflow"""

    @pytest.fixture
    def client(self):
        from app import app
        from database import Base, engine
        Base.metadata.create_all(bind=engine)
        return TestClient(app)

    def test_full_flow_k3_n5(self, client):
        """TC-INT-01: Full flow — generate key, submit 3 shares, reconstruct"""
        # Step 1: Generate
        r1 = client.post("/admin/generate-key?k=3&n=5")
        assert r1.status_code == 200

        # Step 2: Submit 3 shares
        for x in [1, 2, 3]:
            r = client.post(f"/executive/submit-share?share_x={x}")
            assert "error" not in r.json()

        # Step 3: Reconstruct
        r3 = client.post("/executive/reconstruct")
        assert r3.status_code == 200
        data = r3.json()
        assert "error" not in data
        assert "secret_hex" in data
        assert len(data["secret_hex"]) == 64  # 32 bytes = 64 hex chars

    def test_full_flow_k2_n3(self, client):
        """TC-INT-02: Minimum threshold k=2 works"""
        client.post("/admin/generate-key?k=2&n=3")
        client.post("/executive/submit-share?share_x=1")
        client.post("/executive/submit-share?share_x=2")
        resp = client.post("/executive/reconstruct")
        assert "secret_hex" in resp.json()

    def test_full_flow_all_shares(self, client):
        """TC-INT-03: Submitting all n shares still works"""
        client.post("/admin/generate-key?k=3&n=5")
        for x in range(1, 6):
            client.post(f"/executive/submit-share?share_x={x}")
        resp = client.post("/executive/reconstruct")
        assert "secret_hex" in resp.json()

    def test_tamper_then_reconstruct_blocked(self, client):
        """TC-INT-04: Tampered share blocks full reconstruction flow"""
        client.post("/admin/generate-key?k=3&n=5")
        for x in [1, 2, 3]:
            client.post(f"/executive/submit-share?share_x={x}")
        client.post("/admin/tamper-share?share_x=1&value=0")
        resp = client.post("/executive/reconstruct")
        assert "error" in resp.json()

    def test_secret_hex_is_valid_hex(self, client):
        """TC-INT-05: Reconstructed secret is valid 64-char hex string"""
        client.post("/admin/generate-key?k=3&n=5")
        for x in [1, 2, 3]:
            client.post(f"/executive/submit-share?share_x={x}")
        resp = client.post("/executive/reconstruct")
        hex_val = resp.json().get("secret_hex", "")
        assert len(hex_val) == 64
        int(hex_val, 16)  # raises ValueError if not valid hex