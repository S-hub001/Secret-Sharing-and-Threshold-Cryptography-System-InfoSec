"""
models.py

This file defines all database tables:
- Users table
- Shares table
"""

# models are for defining database structure using SQLAlchemy.
# They represent tables in the database and their relationships.
from sqlalchemy import Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    """
    Users Table

    Stores all system users.
    A user can be either:
    - Admin
    - Executive
    """

    __tablename__ = "users"

    # Primary key
    id = Column(Integer, primary_key=True, index=True)

    # User full name
    name = Column(String, nullable=False)

    # Role of user (admin or executive)
    role = Column(String, nullable=False)

    # Hashed password (never store plain password)
    password_hash = Column(String, nullable=False)

    # Relationship: One user can have one share
    share = relationship("Share", back_populates="owner")


class Share(Base):
    """
    Shares Table

    Stores Shamir secret shares assigned to executives.

    Important:
    - share_y is stored encrypted.
    - HMAC is stored for integrity verification.
    """

    __tablename__ = "shares"

    # Primary key
    id = Column(Integer, primary_key=True, index=True)

    # Foreign key linking to users table
    user_id = Column(Integer, ForeignKey("users.id"))

    # X value of share (e.g., 1,2,3...)
    share_x = Column(Integer, nullable=False)

    # Encrypted Y value of share (never store raw value)
    share_y_encrypted = Column(String, nullable=False)

    # HMAC for integrity protection
    hmac = Column(String, nullable=False)

    # Boolean to track if executive has submitted their share
    is_submitted = Column(Boolean, default=False)

    # Relationship back to user
    owner = relationship("User", back_populates="share")