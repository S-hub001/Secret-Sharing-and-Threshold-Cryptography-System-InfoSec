"""
database.py

This file is responsible for:
- Creating database connection
- Setting up SQLAlchemy engine
- Creating SessionLocal (DB session factory)
- Providing Base class for models
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# SQLite database URL
# This will create a file named secret_sharing.db in your project folder
DATABASE_URL = "sqlite:///./secret.db"

# Create SQLAlchemy engine
# connect_args is required only for SQLite
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# SessionLocal is used to create database sessions
# Each request will use a new session 
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Base class for our models
# All database models will inherit from this
Base = declarative_base()


def get_db():
    """
    Dependency function to get database session.

    This will:
    - Create a new database session
    - Yield it to the API route
    - Close it automatically after use
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()