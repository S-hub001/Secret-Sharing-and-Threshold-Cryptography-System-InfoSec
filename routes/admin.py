"""
admin.py

Handles admin operations:
- Generate master key
- Split into shares
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

import base64

admin_router = APIRouter(prefix="/admin", tags=["Admin"])

# Store threshold globally for testing
THRESHOLD = 0


# Create user endpoint for testing user creation and password hashing
@admin_router.post("/create-user", response_model=UserResponse)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    """
    Create new user.
    Password is automatically hashed before saving.
    """

    # Hash the incoming password
    hashed_pwd = hash_password(user.password)

    # Create User object
    new_user = User(
        name=user.name,
        role=user.role,
        password_hash=hashed_pwd
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


# Generate key endpoint, generates AES key, splits into shares, stores in DB
@admin_router.post("/generate-key")
def generate_key(k: int, n: int, db: Session = Depends(get_db)):
    """
    1. Generate AES key
    2. Convert to integer
    3. Split into shares
    4. Store shares in DB
    """

    global THRESHOLD
    THRESHOLD = k

    # Generate AES key
    aes_key = generate_aes_key()

    # Convert key to integer
    secret_int = int.from_bytes(aes_key, byteorder="big")

    # Generate shares (stub)
    shares = generate_shares(secret_int, k, n)

    # Store shares in DB
    for share_x, share_y in shares:

        share_y_str = str(share_y)

        share = Share(
            user_id=None,  # assign later to executives
            share_x=share_x,
            share_y_encrypted=share_y_str,
            hmac=generate_hmac(share_y_str),
            is_submitted=False
        )

        db.add(share)

    db.commit()

    return {"message": "Shares generated successfully"}

@admin_router.post("/tamper-share")
def tamper_share(share_x: int, value: str, db: Session = Depends(get_db)):

    share = db.query(Share).filter(Share.share_x == share_x).first()

    if not share:
        return {"error": "Share not found"}

    share.share_y_encrypted = value

    db.commit()

    return {"message": "tampered successfully"}