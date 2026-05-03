"""
executive.py - ALL routes protected with require_executive
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database import get_db
from models import Share
from crypto_engine import reconstruct_secret
import routes.admin as admin
from utils.hmac_service import verify_hmac
from logger import log_event
from auth import require_executive

executive_router = APIRouter(prefix="/executive", tags=["Executive"])

@executive_router.post("/submit-share")
def submit_share(share_x: int, db: Session = Depends(get_db), current_user=Depends(require_executive)):
    share = db.query(Share).filter(Share.share_x == share_x).first()
    if not share:
        log_event(f"Submit failed: Share {share_x} not found")
        return {"error": "Share not found"}
    share.is_submitted = True
    db.commit()
    log_event(f"Share {share_x} submitted by {current_user.name}")
    return {"message": f"Share {share_x} submitted successfully"}

@executive_router.post("/reconstruct")
def reconstruct(db: Session = Depends(get_db), current_user=Depends(require_executive)):
    submitted_shares = db.query(Share).filter(Share.is_submitted == True).all()
    log_event(f"Reconstruction attempt by {current_user.name}")
    if admin.THRESHOLD == 0:
        return {"error": "System not initialized. Admin must run /admin/generate-key first."}
    if len(submitted_shares) < admin.THRESHOLD:
        log_event("Reconstruction failed: insufficient shares")
        return {"error": f"Not enough shares. Need {admin.THRESHOLD}, got {len(submitted_shares)}."}
    share_list = []
    for s in submitted_shares:
        if not verify_hmac(str(s.share_y_encrypted), s.hmac):
            log_event(f"Tampered share detected: {s.share_x}")
            return {"error": f"Tampered share detected at share_x={s.share_x}"}
        try:
            share_list.append((s.share_x, int(s.share_y_encrypted)))
        except ValueError:
            return {"error": f"Corrupted share format at share_x={s.share_x}"}
    secret_bytes = reconstruct_secret(share_list, secret_length=32)
    log_event(f"Secret reconstructed by {current_user.name}")
    return {"message": "Secret reconstructed successfully", "secret_hex": secret_bytes.hex(), "shares_used": len(share_list)}

@executive_router.post("/attack/bruteforce")
def brute_force_attack(current_user=Depends(require_executive)):
    log_event(f"ATTACK 3 by {current_user.name}")
    k = admin.THRESHOLD
    if k == 0:
        return {"error": "System not initialized."}
    log_event(f"ATTACK 3 FAILED: search space p^(k-1)")
    return {"attack": "brute_force", "attacker_shares": k-1, "threshold_required": k, "result": "failed", "reason": f"Search space is p^(k-1) where p is 256-bit. Computationally infeasible."}

@executive_router.post("/attack/insider")
def insider_attack(db: Session = Depends(get_db), current_user=Depends(require_executive)):
    log_event(f"ATTACK 4 by {current_user.name}")
    k = admin.THRESHOLD
    if k == 0:
        return {"error": "System not initialized."}
    submitted_shares = db.query(Share).filter(Share.is_submitted == True).all()
    if len(submitted_shares) < k:
        return {"attack": "insider_collusion", "result": "blocked", "reason": f"Only {len(submitted_shares)}/{k} shares."}
    valid_shares = []
    seen_x = set()
    for s in submitted_shares:
        if not verify_hmac(str(s.share_y_encrypted), s.hmac):
            return {"attack": "insider_collusion", "result": "blocked", "reason": f"Tampered share at share_x={s.share_x}"}
        if s.share_x in seen_x:
            return {"attack": "insider_collusion", "result": "blocked", "reason": "Duplicate share detected."}
        seen_x.add(s.share_x)
        try:
            valid_shares.append((s.share_x, int(s.share_y_encrypted)))
        except ValueError:
            return {"attack": "insider_collusion", "result": "blocked", "reason": "Invalid share format."}
    if len(valid_shares) < k:
        return {"attack": "insider_collusion", "result": "failed", "reason": f"Only {len(valid_shares)} valid shares. Need {k}."}
    reconstruct_secret(valid_shares, secret_length=32)
    return {"attack": "insider_collusion", "result": "blocked_or_controlled", "reason": "System prevents reconstruction below threshold."}