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
from routes.admin import THRESHOLD

executive_router = APIRouter(prefix="/executive", tags=["Executive"])


# Submit share endpoint, marks share as submitted in DB
@executive_router.post("/submit-share")
def submit_share(share_x: int, db: Session = Depends(get_db)):
    """
    Mark share as submitted.
    """
    share = db.query(Share).filter(Share.share_x == share_x).first()

    if not share:
        return {"error": "Share not found"}

    share.is_submitted = True
    db.commit()

    return {"message": f"Share {share_x} submitted"}


# Reconstruct secret endpoint, checks if threshold met and reconstructs secret
@executive_router.post("/reconstruct")
def reconstruct(db: Session = Depends(get_db)):
    """
    Reconstruct secret if threshold met.
    """

    submitted_shares = db.query(Share).filter(Share.is_submitted == True).all()

    if len(submitted_shares) < THRESHOLD:
        return {"error": "Not enough shares submitted"}

    share_list = [(s.share_x, int(s.share_y_encrypted)) for s in submitted_shares]

    secret_int = reconstruct_secret(share_list)

    return {"message": "Secret reconstructed successfully"}