"""
app.py

Main entry point of FastAPI application.
"""

from fastapi import FastAPI, Depends
from database import SessionLocal
from models import Base, User
from database import engine, get_db
from models import Base
from routes.admin import admin_router
from routes.executive import executive_router
from sqlalchemy.orm import Session

# Create FastAPI app
app = FastAPI()

# Create database tables automatically
Base.metadata.create_all(bind=engine)

# routers for admin and executive operations
app.include_router(admin_router)
app.include_router(executive_router)

# Root endpoint to verify API is running
@app.get("/")
def read_root():
    return {"message": "Secret Sharing Backend Running"}


# Test route to verify database connection and insertion
@app.get("/test-db")
def test_db():
    db = SessionLocal()
    new_user = User(name="Admin1", role="admin", password_hash="test")
    db.add(new_user)
    db.commit()
    db.close()
    return {"message": "User inserted"}

