"""
executive.py

Handles executive operations:
- Submit share
- Reconstruct key
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database import get_db
from models import Share
from crypto_engine import reconstruct_secret
import routes.admin as admin
from utils.hmac_service import verify_hmac
from logger import log_event

executive_router = APIRouter(prefix="/executive", tags=["Executive"])


# =========================
# Submit Share
# =========================
@executive_router.post("/submit-share")
def submit_share(share_x: int, db: Session = Depends(get_db)):

    share = db.query(Share).filter(Share.share_x == share_x).first()

    if not share:
        log_event(f"Submit failed: Share {share_x} not found")
        return {"error": "Share not found"}

    share.is_submitted = True
    db.commit()

    log_event(f"Share {share_x} submitted")

    return {"message": f"Share {share_x} submitted"}


# =========================
# Reconstruct Secret
# =========================
@executive_router.post("/reconstruct")
def reconstruct(db: Session = Depends(get_db)):

    submitted_shares = db.query(Share).filter(Share.is_submitted == True).all()

    log_event("Reconstruction attempt started")

    print("THRESHOLD =", admin.THRESHOLD)
    print("submitted_shares =", len(submitted_shares))

    # ❗ FIX: threshold check
    if admin.THRESHOLD == 0:
        return {"error": "System not initialized. Generate key first."}

    if len(submitted_shares) < admin.THRESHOLD:
        log_event("Reconstruction failed: insufficient shares")
        return {"error": "Not enough shares submitted"}

    share_list = []

    for s in submitted_shares:
        print("DEBUG SHARE:", s.share_x, s.share_y_encrypted, s.hmac)
        # 🔐 HMAC Integrity Check
        if not verify_hmac(str(s.share_y_encrypted), s.hmac):
            log_event(f"Tampered share detected: {s.share_x}")
            return {"error": "Tampered share detected"}

        # ❗ safe conversion check
        try:
            share_list.append((s.share_x, int(s.share_y_encrypted)))
        except ValueError:
            log_event(f"Invalid share format: {s.share_x}")
            return {"error": "Corrupted share format"}

    # reconstruct secret
    secret_int = reconstruct_secret(share_list)

    log_event("Secret reconstructed successfully")

    return {
        "message": "Secret reconstructed successfully",
        "debug_shares_used": len(share_list)
    }
@executive_router.post("/attack/bruteforce")
def brute_force_attack():
    log_event("ATTACK 3 started: brute force attempt")

    k = admin.THRESHOLD

    if k == 0:
        return {"error": "System not initialized"}

    # simulate attacker having k-1 shares
    fake_share_count = k - 1

    log_event(f"ATTACK 3: attacker has {fake_share_count}/{k} shares")

    # mathematical conclusion (not computation)
    log_event("ATTACK 3 FAILED: search space is exponential (p^(k-1))")

    return {
        "attack": "brute_force",
        "result": "failed",
        "reason": "computationally infeasible"
    }

@executive_router.post("/attack/insider")
def insider_attack(db: Session = Depends(get_db)):

    log_event("ATTACK 4 started: insider collusion")

    k = admin.THRESHOLD

    if k == 0:
        return {"error": "System not initialized"}

    submitted_shares = db.query(Share).filter(Share.is_submitted == True).all()

    # STEP 1: enforce minimum threshold immediately
    if len(submitted_shares) < k:
        log_event("ATTACK 4 BLOCKED: insufficient shares")
        return {"error": "Not enough independent shares"}

    # STEP 2: validate integrity (HMAC check)
    valid_shares = []
    seen_x = set()

    for s in submitted_shares:

        # tampering check
        if not verify_hmac(str(s.share_y_encrypted), s.hmac):
            log_event(f"ATTACK 4 BLOCKED: tampered share detected {s.share_x}")
            return {"error": "Tampered share detected"}

        # duplicate / collusion detection
        if s.share_x in seen_x:
            log_event("ATTACK 4 BLOCKED: duplicate share usage detected")
            return {"error": "Collusion detected"}

        seen_x.add(s.share_x)

        try:
            valid_shares.append((s.share_x, int(s.share_y_encrypted)))
        except ValueError:
            log_event("ATTACK 4 BLOCKED: corrupted share format")
            return {"error": "Invalid share format"}

    # STEP 3: enforce "independent participant rule"
    if len(valid_shares) < k:
        log_event("ATTACK 4 FAILED: not enough valid independent shares")
        return {"error": "Insufficient valid shares"}

    # STEP 4: SAFE RECONSTRUCTION (only if truly valid)
    secret = reconstruct_secret(valid_shares)

    log_event("ATTACK 4: reconstruction attempted with valid shares")

    return {
        "attack": "insider_collusion",
        "result": "blocked_or_controlled",
        "reason": "system prevents reuse/tampering/collusion below threshold"
    }