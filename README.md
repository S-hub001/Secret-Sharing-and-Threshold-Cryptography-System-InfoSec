# 🔐 Secret Sharing and Threshold Cryptography System

## 📌 Project Overview
This project implements a secure distributed key management system using **Shamir’s Secret Sharing Scheme** combined with **AES-256 encryption**. The system ensures that a cryptographic key can only be reconstructed when a minimum threshold of authorized users collaborate.

---

# 🧩 System Architecture

The system is divided into **four** main modules:

- Cryptographic Engine
- Backend & API Layer
- Frontend Interface
- Database Layer

---

# 📂 Folder Structure 
```
Secret-Sharing-and-Threshold-Cryptography-System-InfoSec/
│
├── app.py
├── database.py
├── models.py
├── schemas.py
├── security.py
├── crypto_engine.py  (temporary)
│
├── routes/
│   ├── admin.py
│   └── executive.py
│
├── database/
│   └── secret_sharing.db   (will be created when app runs)
|
└── utils/
    └── aes_service.py
```

---

# ⛓️ Cryptographic Engine (Member 1)
*add your part*
## 📌 Responsibilities
## ✨ Features Implemented
## ⚙️ Execution & Testing 

---

# 🛠️ Backend Module (Member 2)

## 📌 Responsibilities
This module handles all system logic, APIs, and database interactions.

---

## ✨ Features Implemented

### 1. Database Management
- SQLAlchemy ORM setup
- SQLite database integration
- Tables:
  - Users
  - Shares
- Relationships between users and shares

---

### 2. User Management
- Admin can create users
- Passwords are securely hashed using:
  - SHA-256 + bcrypt
- No plain-text password storage

---

### 3. Authentication Security
- Secure password hashing system
- Password verification support

---

### 4. Key Generation System
- AES-256 key generation
- Conversion of key into integer format
- Integration with secret sharing module (stub version)

---

### 5. Secret Sharing Flow (Stub Implementation)
- Temporary Shamir-like share generation (for testing)
- Share storage in database
- Threshold-based reconstruction logic

---

### 6. Executive Operations
- Submit share API
- Reconstruct secret API
- Threshold validation before reconstruction

---

### 7. AES Encryption System
- AES-256 key generation
- AES-GCM encryption & decryption
- Secure data handling utilities

---

## ⚙️ Execution & Testing
***Step 1: Create Project Folder***
```
Secret-Sharing-and-Threshold-Cryptography-System-InfoSec/
```
Open it in VS Code.

***Step 2: Create Virtual Environment***

In terminal:
```
python -m venv venv
venv\Scripts\activate
```
***Step 3: Install Dependencies***
```
pip install fastapi uvicorn sqlalchemy passlib[bcrypt] cryptography python-multipart python-jose
```
***Step 4: Run the app***
```
uvicorn app:app --reload
```
and open `http://localhost:8000` in browser.

***Step 5: Tested user creation in POSTMAN***
```
URL: http://127.0.0.1:8000/admin/create-user
BODY (raw-JSON): 
        {
        "name": "Exec1",
        "role": "executive",
        "password": "strongpass"
        }
```
click `send`. The result was successfully added to the database, with hashed password.

\
*The URL is `/admin/create-user` because the router has this `admin_router = APIRouter(prefix="/admin", tags=["Admin"])`. That means every route inside `admin.py` automatically becomes `/admin/whatever-you-defined`. **And so for other routes declared.***


---

# 🔐 Security & Attack Simulation (Member 3)
*add your part*
## 📌 Responsibilities
## ✨ Features Implemented
## ⚙️ Execution & Testing 

---

# 👩‍💻 Frontend Layer & Integration (Member 4)
*add your part*
## 📌 Responsibilities
## ✨ Features Implemented
## ⚙️ Execution & Testing 

---

# 🚀 Future Improvements
*later* 

---

# 👥 Team Responsibilities

- Member 1: Cryptographic Engine (Shamir Implementation)
- Member 2: Backend & API
- Member 3: Security & Attack Simulation 
- Member 4: Frontend & Integration Testing

---

# 🤝 Team Members

- Sukina Raveen 23I-2115
- Syeda Shanzay Shah 23I-2016
- Laiba Nasir 23I-2079 
- Rania Muskan Malik 23I-2056

---

# 📦 Tech Stack
- FastAPI
- SQLAlchemy
- SQLite
- Cryptography (AES)
- Passlib (bcrypt)

 