"""
admin.py

Handles admin operations:
- Generate master key
- Split into shares
- Create users
- Tamper share (attack simulation)

ALL routes protected — admin role required.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database import get_db
from models import Share, User
from crypto_engine import generate_shares
from security import hash_password
from utils.aes_service import generate_aes_key
from schemas import UserCreate, UserResponse
from utils.hmac_service import generate_hmac
from auth import require_admin

admin_router = APIRouter(prefix="/admin", tags=["Admin"])

# Store threshold globally
THRESHOLD = 0


# =========================
# Create User  (admin only)
# =========================
@admin_router.post("/create-user", response_model=UserResponse)
def create_user(
    user: UserCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin)
):
    hashed_pwd = hash_password(user.password)
    new_user = User(
        name=user.name,
        role=user.role,
        password_hash=hashed_pwd
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


# =========================
# Generate Key  (admin only)
# =========================
@admin_router.post("/generate-key")
def generate_key(
    k: int,
    n: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin)
):
    global THRESHOLD
    THRESHOLD = k

    aes_key = generate_aes_key()
    shares = generate_shares(aes_key, k, n)

    for share_x, share_y in shares:
        share_y_str = str(share_y)
        share = Share(
            user_id=None,
            share_x=share_x,
            share_y_encrypted=share_y_str,
            hmac=generate_hmac(share_y_str),
            is_submitted=False
        )
        db.add(share)

    db.commit()

    return {
        "message": "Shares generated successfully",
        "threshold": k,
        "total_shares": n
    }


# =========================
# Tamper Share  (admin only)
# =========================
@admin_router.post("/tamper-share")
def tamper_share(
    share_x: int,
    value: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin)
):
    share = db.query(Share).filter(Share.share_x == share_x).first()
    if not share:
        return {"error": "Share not found"}

    share.share_y_encrypted = value
    db.commit()

    return {"message": f"Share {share_x} tampered successfully (HMAC now invalid)"}