# HECC Phase 2: Complete Project Execution Guide
## How to Setup, Run, Test, and Demo the System

This guide provides clear, step-by-step instructions to get the **HECC Phase 2 (Hybrid Quantum-Resistant Cloud Security)** platform running from scratch on your machine.

---

## 1. Prerequisites

Before running the application, make sure you have:
1. **Python 3.10 to 3.13** installed ([python.org](https://www.python.org/downloads/)).
2. **Pip** updated to the latest version.
3. An active internet connection (to communicate with Supabase Cloud).

Verify Python installation in your terminal (PowerShell or Command Prompt):
```powershell
python --version
pip --version
```

---

## 2. Install Dependencies

Open a terminal in the project directory (`hecc_phase2`) and install all required cryptographic and web dependencies:

```powershell
pip install -r requirements.txt
```

> **Key Libraries Installed**:
> - `oqs` (Open Quantum Safe): Post-quantum ML-KEM-768 lattice algorithm.
> - `cryptography`: Classical X25519, Ed25519 signatures, AES-256-GCM, and Scrypt KDF.
> - `fastapi` & `uvicorn`: High-performance asynchronous backend server.
> - `supabase`: Cloud storage bucket and PostgreSQL table client.
> - `PyJWT`: Signed token-based identity authentication.

---

## 3. Environment & Database Configuration

### Step A: Verify `.env` File
Ensure your `.env` file exists in the root directory with the following variables:
```env
SUPABASE_URL=https://<your-project-id>.supabase.co
SUPABASE_KEY=<your-supabase-service-role-or-anon-key>
KMS_MASTER_SECRET=hecc-phase2-master-secret-key-2026
JWT_SECRET=hecc-jwt-secret-change-in-production
```
*(Your project already comes with pre-configured Supabase credentials).*

### Step B: Supabase Database Setup (One-Time Setup)
If setting up a fresh Supabase database, open the **Supabase Dashboard $\rightarrow$ SQL Editor** and execute:
1. **Tables & Metadata**: Run [sql_setup.sql](file:///c:/Users/Suhas/OneDrive/Desktop/7th%20Sem/Final%20Year%20Project/hecc_phase2/sql_setup.sql)
2. **User Auth & Public Keys**: Run [sql_icat_patch.sql](file:///c:/Users/Suhas/OneDrive/Desktop/7th%20Sem/Final%20Year%20Project/hecc_phase2/sql_icat_patch.sql)
3. **Storage Bucket**: Ensure a storage bucket named `encrypted-fragments` is created (set to private).

---

## 4. Starting the Server

In your terminal, run the following command to launch the Uvicorn web server:

```powershell
python -m uvicorn app:app --reload --port 8000
```

When startup is complete, you will see:
```text
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
INFO:     Started reloader process using WatchFiles
INFO:     Application startup complete.
```

---

## 5. Opening the Web Dashboards

Once the server is running, open your web browser:

| Dashboard | URL | Purpose |
| :--- | :--- | :--- |
| **Transmitter** (Sender) | [`http://localhost:8000/`](http://localhost:8000/) | Authenticate, shard, encrypt with hybrid ML-KEM/AES, and vault to cloud |
| **Decryption Vault** (Receiver) | [`http://localhost:8000/receiver`](http://localhost:8000/receiver) | Authenticate recipient, audit Merkle tree, decapsulate key, decrypt file |
| **Interactive API Docs** | [`http://localhost:8000/docs`](http://localhost:8000/docs) | Swagger UI for raw REST API testing |

---

## 6. Complete End-to-End Demo Workflow

Here is how to demonstrate the entire project to evaluators in 3 minutes:

### Part 1: Sender Encrypts & Uploads (Transmitter)
1. Go to [`http://localhost:8000/`](http://localhost:8000/).
2. Under **01. Cryptographic Authentication & KMS Vault**:
   - Click the **Register New Identity** tab.
   - **Account Email**: `alice@mail.com` *(must follow `username@mail.com` format)*.
   - **Password**: `AliceSecretPass123`.
   - Click **Register Identity & Unlock Transmitter**.
3. Under **02. Payload Ingestion & ICAT Encapsulation**:
   - Click the file drop area and select any file (PDF, TXT, DOCX, PNG, etc.).
   - In **Authorized Recipient Email**, enter `bob@mail.com`.
   - Click **Encrypt, Capsule & Vault to Supabase**.
4. **Observe the Results**:
   - Status updates show dual key establishment (`X25519 + ML-KEM-768`), chunking with identity-bound AAD, Merkle tree root computation, and storage upload.
   - Telemetry table displays: Payload Volume, Fragment Count, KEM Time (ms), Parallel AES-GCM Time (s), and Chain Version.
   - (Optional) Click **⬇ Download ICAT Key Capsule (.icat.json)** to save the offline access token.

---

### Part 2: Recipient Decrypts & Recovers File (Decryption Vault)
1. In the top navigation bar, click **Decryption Vault** (or open [`http://localhost:8000/receiver`](http://localhost:8000/receiver)).
2. Under **01. Receiver Authentication**:
   - If Bob is not registered yet, click **Register New Identity** and create `bob@mail.com` with password `BobSecretPass456`.
   - *(If Bob was auto-provisioned during Alice's upload, simply type `bob@mail.com` + your chosen password to claim your vault)*.
   - Click **Authorize Vault Access**.
3. Under **02. Cloud Inbound Enclaves**:
   - Click **Query Shared Files**.
   - You will see the file sent by `alice@mail.com`.
   - Click on the row to select it.
   - Click **Validate Integrity & Decrypt Cloud Payload**.
4. **Observe the Decryption**:
   - The system validates the Merkle root, checks the anti-rollback version ledger, reconstructs the hybrid session key using Bob's private keys in RAM, parallel-decrypts all fragments, and **automatically downloads the exact recovered file**.

---

## 7. Running the Automated Security Test Suite

To demonstrate proof of security against tampering, MITM, and unauthorized access, run the automated test suite:

```powershell
python -m pytest test_icat_security_suite.py -v
```

### What This Test Suite Validates (8/8 Tests):
1. `test_register_and_login_flow`: Enforces strict PBKDF2 password hashing and 401 rejection on invalid credentials.
2. `test_unauthenticated_access_blocked_401`: Verifies that unauthorized endpoints reject requests without a valid JWT.
3. `test_unauthorized_user_acl_blocked_403`: Verifies that third parties (e.g. Eve) cannot download or delete Bob's files.
4. `test_icat_capsule_identity_tampering_blocked`: Modifies the recipient identity in a capsule and confirms that `CapsuleSignatureError` and AES-GCM `InvalidTag` immediately halt decryption.
5. `test_mitm_public_key_tampering_blocked`: Simulates a database attacker altering public keys and proves that the Ed25519 signature check halts encapsulation (`UntrustedPublicKeyError`).
6. `test_end_to_end_authenticated_recovery`: Tests full end-to-end cryptographic encryption, Merkle verification, and fragment reassembly.
7. `test_benchmark_auth_and_icat_kms`: Benchmarks latencies and outputs a visualization chart: `icat_kms_benchmark.png`.
8. `test_email_validation_and_claim_flow`: Tests email regex formatting and auto-provisioned recipient claims.

---

## 8. Starting Fresh / Resetting the System

If you want to clear all test users, files, and tokens before presenting:

Run this one-line cleanup command in PowerShell:
```powershell
python -c "from core.cloud_storage import _get_client; import os; c=_get_client(); c.table('files_metadata').delete().neq('file_id','___').execute(); c.table('user_public_keys').delete().neq('email','___').execute(); c.table('app_users').delete().neq('email','___').execute(); [os.remove(os.path.join(d,f)) for d in ['vaults','kms_data','icat_tokens'] if os.path.exists(d) for f in os.listdir(d) if os.path.isfile(os.path.join(d,f))]; open('local_version_ledger.json','w').write('{}'); print('System reset to clean slate!')"
```

---

## 9. Quick Troubleshooting Guide

| Issue | Cause | Fix |
| :--- | :--- | :--- |
| **`401 Unauthorized: Invalid email format`** | Email does not contain `@` or domain. | Enter email in `username@mail.com` format (e.g. `alice@example.com`). |
| **`502 Bad Gateway / Connection Refused`** | Backend server is not running. | Run `python -m uvicorn app:app --reload --port 8000` in your terminal. |
| **`403 Forbidden: Access Denied`** | Logged-in user is neither the owner nor authorized recipient. | Log in with the recipient email specified during encryption. |
| **`ModuleNotFoundError: No module named 'oqs'`** | liboqs / oqs dependency missing. | Run `pip install -r requirements.txt`. |

