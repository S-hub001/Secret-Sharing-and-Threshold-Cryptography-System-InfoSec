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
├── database/
│   └── secret_sharing.db
│
├── routes/
│   ├── admin.py
│   └── executive.py
│
├── utils/
│   ├── aes_service.py
│   └── hmac_service.py
│
├── .gitignore
├── app.py
├── crypto_engine.py
├── database.py
├── logger.py
├── models.py
├── README.md
├── schemas.py
├── security_attacks.py
├── security.py
├── system_logs.txt
```

---
# ⛓️ Cryptographic Engine (Member 1)

## 📌 Responsibilities
This module is the heart of the entire system. It implements all low-level
cryptographic primitives required for Shamir's Secret Sharing — completely
from scratch using finite field mathematics, with no reliance on external
secret-sharing libraries.

## ✨ Features Implemented

### 1. Finite Field Arithmetic — GF(P)
All arithmetic operates over a 256-bit prime field:
P = 2^256 - 189
Functions implemented:
- `mod_add(a, b)` — Addition mod P
- `mod_sub(a, b)` — Subtraction mod P
- `mod_mul(a, b)` — Multiplication mod P
- `mod_inv(a)`    — Modular inverse via Fermat's Little Theorem: `a^(P−2) mod P`
- `mod_div(a, b)` — Division as `a × b⁻¹ mod P`
> All values are guaranteed to stay within GF(P), preventing overflow and
> ensuring cryptographic correctness.


### 2. Share Generation
```python
def generate_shares(secret: bytes, k: int, n: int) -> List[Tuple[int, int]]
```
**Steps:**
1. Convert secret bytes → integer representation
2. Generate `k−1` cryptographically random coefficients using `secrets.randbelow(P)`
3. Construct polynomial:
   `f(x) = secret + a₁x + a₂x² + ... + a(k-1)x^(k-1) mod P`
4. Evaluate at `x = 1, 2, ..., n` to produce n shares `(x, f(x))`
**Optimisation:** Polynomial evaluation uses **Horner's Method** — reduces
multiplications from O(k²) to O(k).

**Security:** Each run produces different shares for the same secret due to
freshly randomized coefficients — indistinguishable from random to any
attacker holding fewer than k shares.


### 3. Secret Reconstruction — Lagrange Interpolation
```python
def reconstruct_secret(shares: List[Tuple[int, int]], secret_length: int) -> bytes
```
Reconstructs the secret at `x = 0` using the Lagrange formula:
S = Σ [ yⱼ × Lⱼ(0) ]  mod P
Where:
Lⱼ(0) = Π [ xₘ / (xₘ − xⱼ) ]  for all m ≠ j,  mod P

Built-in protections:
- ✔ Detects and rejects **duplicate shares** before reconstruction
- ✔ Requires minimum of **2 shares** (enforced)
- ✔ Tampered shares produce a **wrong result** — never the real secret


### 4. Helper Utilities (used by Backend / API Layer)
| Function | Purpose |
|---|---|
| `generate_random_secret(n)` | Generates a cryptographically secure n-byte secret |
| `hash_secret(secret)` | SHA-256 fingerprint for verification without exposing the secret |
| `verify_reconstruction(a, b)` | Constant-time comparison to confirm reconstruction succeeded |

---

## ⚙️ Execution & Testing

**File:** `crypto_engine.py` and `test_shamir.py`

### Run Tests
python test_shamir.py
### Test Suites (32 tests — all passing)

| Suite | Tests | Coverage |
|---|---|---|
| Finite Field Arithmetic | 10 | `mod_add`, `mod_sub`, `mod_mul`, `mod_inv`, `mod_div`, wrap-around, zero edge case |
| Share Generation | 7 | Count, x-values, field bounds, randomness, validation errors |
| Reconstruction (Lagrange) | 8 | 3-of-5 success, 2-of-5 failure, subset consistency, duplicate detection, tamper detection |
| Helpers & Edge Cases | 7 | Random secret generation, hash consistency/uniqueness, full round-trip |

### Key Test Cases

| Test | Expected Result |
|---|---|
| 3-of-5 threshold | ✔ Secret reconstructed correctly |
| 2-of-5 (below threshold) | ✔ Wrong result — secret NOT revealed |
| Duplicate share submitted | ✔ `ValueError` raised |
| Modified/tampered share | ✔ Reconstruction fails — wrong secret |
| Full round-trip (32-byte key) | ✔ `verify_reconstruction()` confirms match |


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
***Step 1: Download and Navigate to Project Folder***
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

## 📌 Responsibilities
This module focuses on system security, integrity protection, and attack simulation against Shamir Secret Sharing-based key reconstruction.

---

## 🔐 SECURITY FEATURES IMPLEMENTED

### 1. Integrity Protection (HMAC System)
- Each share is protected using HMAC-SHA256
- Generated during share creation (admin module)
- Verified before reconstruction
#### ✔ Purpose:
Prevents:
- Share tampering
- Data modification attacks

---

### 2. Threshold Security Enforcement
- System uses Shamir Secret Sharing (k-of-n)
- Minimum k shares required for reconstruction
- Global threshold controlled via admin module

---

### 3. Secure Reconstruction Pipeline

#### Before reconstructing secret:
##### System verifies:
- ✔ Threshold condition (k shares required)
- ✔ HMAC integrity of each share
- ✔ Valid numeric format of shares
- ✔ No duplicate share usage

---

### 4. Attack Simulation Module

#### Implements controlled red-team attacks:
- Attack 1: Insufficient shares
- Attack 2: Share tampering
- Attack 3: Brute force feasibility analysis
- Attack 4: Insider collusion simulation

---

## ⚙️ Execution & Testing 

***Step 1: Run Project***
- uvicorn app:app --reload
- Open:
  *http://127.0.0.1:8000/docs*

***Step 2: Generate Key***
- *POST /admin/generate-key*
- k = 3 and n = 5

***Step 3: Submit Shares***
- *POST /executive/submit-share?share_x=1*
- *POST /executive/submit-share?share_x=2*
- *POST /executive/submit-share?share_x=3*

***Step 4: Normal Reconstruction***
- *POST /executive/reconstruct*

**✔ Secret successfully reconstructed if valid shares exist**

---

### 💣 ATTACK SIMULATIONS (WEB TESTING)

**🔴ATTACK 1 — Insufficient Shares**
***Method:***
- --> Submit only 2 shares when k = 3
- *POST /executive/reconstruct*

**Result:**
- *ERROR: Not enough shares submitted*
  
Why:
- Threshold condition fails.

  ---

**🔴 ATTACK 2 — Share Tampering**
***Method:***
- *POST /admin/tamper-share*

Modify share_y manually

Then:
- *POST /executive/reconstruct*

***Result:***

- *ERROR: Tampered share detected*
  
Why:
- HMAC verification fails.

  ---

**🔴 ATTACK 3 — Brute Force Attack**
***Method:***
- *POST /executive/attack/bruteforce*

***Result:***

- *FAILED: computationally infeasible*

Why brute force does NOT work:
- Shamir uses polynomial of degree k-1
  
  With less than k shares:**
- Infinite possible solutions exist
  
Search space:
-p^(k−1)

**👉 Practically impossible for large prime fields (e.g., 256-bit)**

***✔ So attacker cannot guess secret***

---

**🔴 ATTACK 4 — Insider Collusion Attack**

Method:
- *POST /executive/attack/insider*
  
***Simulation:***
Only 2 executives collide

System enforces:
- threshold check
- HMAC validation
- duplicate detection

***Result:***
-BLOCKED OR FAILED

Why insider attack fails:
- Less than k shares reveal NOTHING
- Polynomial cannot be reconstructed
- Even colluding users gain no information**

---

***📊 LOGGING SYSTEM***
-All events are logged in:

**system_logs.txt**

***some logs are listed:***
- *2026-04-27 00:50:30.046588 - ATTACK 3 started: brute force attempt*
- *2026-04-27 00:50:30.047155 - ATTACK 3: attacker has 2/3 shares*
- *2026-04-27 00:50:30.047595 - ATTACK 3 FAILED: search space is exponential (p^(k-1))*
- *2026-04-27 00:50:47.884109 - ATTACK 4 started: insider collusion*
- *2026-04-27 00:50:47.898490 - ATTACK 4: only 2 shares used*
- *2026-04-27 00:50:47.899225 - ATTACK 4 FAILED: insufficient threshold shares*
- *2026-04-27 00:56:52.181469 - Share 1 submitted*
- *2026-04-27 00:56:57.030835 - Share 2 submitted*
- *2026-04-27 00:57:02.427562 - Share 2 submitted*
- *2026-04-27 00:57:12.359514 - ATTACK 4 started: insider collusion*
- *2026-04-27 00:57:12.364466 - ATTACK 4: reconstruction attempted with valid shares*

---
 
# 👩‍💻 Frontend Layer & Integration (Member 4)

## 📌 Responsibilities
This module acts as the bridging layer of the system. It provides an intuitive, responsive user interface (UI) to make complex cryptographic processes accessible, while ensuring seamless end-to-end integration between the frontend forms, the backend APIs, and the database.

## ✨ Features Implemented

### 1. Unified Management Dashboard
- Designed a centralized interface for both administrative tasks and executive operations.
- Dynamic data rendering allows users to view system statuses, active thresholds, and total generated shares in real time.

### 2. Administrator Panel
- **Key Generation Form:** Interface to trigger master key generation, define total shares ($n$), and set the required recovery threshold ($k$).
- **User Creation Portal:** Secure forms to register new system users and assign specific system roles (Admin vs. Executive).
- **Interactive Share Viewer:** Displays administrative tools to view generated shares and manually trigger tampering events for security audits.

### 3. Executive Operations Portal
- **Secure Share Submission Form:** An optimized input module where executives can securely paste their assigned numeric points.
- **Visual Status Tracker:** A real-time threshold progress bar that dynamically updates to show exactly how many more shares are needed to reach the threshold $k$.
- **Reconstruction Module:** A one-click execution interface that collects submitted shares, verifies validation tokens, and displays the successfully recovered plaintext Master Key.

### 4. Integration & Error Handling
- Built a secure client-side API handler that communicates directly with the FastAPI backend via asynchronous AJAX/Fetch requests.
- Integrated dynamic validation alerts to catch input issues early (e.g., malformed keys, empty values, or duplicate entries) before making server calls.
- Full CORS integration mapping to ensure secure, trouble-free local hosting (`http://127.0.0.1:8000`).

## ⚙️ Execution & Testing 

***Step 1: Launch the API Backend***
Before launching the frontend, ensure your backend server is up and running:
```bash
uvicorn app:app --reload
```

***Step 2: Launch the Frontend***
1. Open the project root folder.
2. Locate the file named `index.html` (or your main frontend template).
3. **Option A:** Right-click the file and open it directly in your browser.
4. **Option B (Recommended):** Use the VS Code **Live Server** extension to launch it at `http://127.0.0.1:5500` to prevent local file routing issues.

***Step 3: End-to-End Test Workflow***
1. Open the Admin Panel UI and create three test users.
2. Generate a key with $n=5$ and $k=3$.
3. Navigate to the Executive Panel UI and submit three valid shares.
4. Click **Reconstruct Key** and verify that the original Master Key matches the generated output.

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

 
