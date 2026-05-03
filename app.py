"""
app.py - Main entry point with auth router + default admin seeding
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import SessionLocal, engine
from models import Base, User
from routes.admin import admin_router
from routes.executive import executive_router
from auth import auth_router
from security import hash_password
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

app = FastAPI(title="VaultKey — Secret Sharing System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

# Register all routers
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(executive_router)


@app.on_event("startup")
def seed_default_admin():
    """
    Creates a default admin user on first run if none exists.
    Username: admin   Password: admin123
    """
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.role == "admin").first()
        if not existing:
            default_admin = User(
                name="admin",
                role="admin",
                password_hash=hash_password("admin123")
            )
            db.add(default_admin)
            db.commit()
            print("✅ Default admin created — username: admin | password: admin123")
        else:
            print(f"✅ Admin already exists: {existing.name}")
    finally:
        db.close()


@app.get("/")
def read_root():
    return {"message": "VaultKey — Secret Sharing Backend Running"}


# add this AFTER all your routers
@app.get("/ui")
def serve_frontend():
    return FileResponse("frontend.html")