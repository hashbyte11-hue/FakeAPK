 **Fake Banking APK Detection**

**Overview**

An Android Package Kit (APK) is the file format used to distribute and install applications on Android devices.
In mobile banking, APKs are prime targets for attackers because of the sensitive data they handle.

**Despite using mechanisms like:**
- App Signing
- HTTPS
- Play Protect

**APKs remain vulnerable to threats such as:**

- Unauthorized permissions

- Repackaging

- Reverse Engineering

- Malicious third-party downloads

- 0-Day Exploits

**These attacks often lead to data theft and financial fraud.**

**Proposed Solution**

We propose an approach that ensures APK Security before installation by integrating multiple verification layers:

- Source Authentication → Verify that the APK originates from a trusted source.

- Code Integrity Check → Detect tampering in APK files.

- Digital Signature Verification → Validate the authenticity of the APK.

- Only when all three checks PASS, the APK is installed.

**This guarantees:**

Stronger protection against malicious APK files.

Reduced cyberattack surface.

Increased customer trust in mobile banking applications.

🏗️ System Workflow
flowchart TD
    A[Download APK] --> B[Source Authentication]
    B --> C[Code Integrity Verification]
    C --> D[Digital Signature Verification]
    D -->|All Pass| E[Install APK ✅]
    D -->|Fail| F[Reject APK ❌]

⚙️ Tech Stack

Backend: Python, Cryptography Library

Frontend: Streamlit (for visualization & demo)

Notebook: Google Colab

Security: RSA, SHA-256

📦 Fake-Banking-APK-Detection
 ┣ 📜 README.md
 ┣ 📜 requirements.txt
 ┣ 📜 backend.py        # Core detection logic
 ┣ 📜 streamlit_ui.py   # Frontend demo
 ┣ 📂 tests             # Unit tests
 ┗ 📂 docs              # Documentation

**Key Benefits**

- Prevents APK tampering before installation.
- Detects fake/malicious banking apps.
- Enhances security & trust in mobile banking.
- Lightweight and scalable solution.

**Demo**

Google Colab - https://colab.research.google.com/drive/17GTozyCJW6saOeFmj4OELUfSrKMQsYHq#scrollTo=1PkOg-uWFeHv 

Deploy Link - https://detect-fake-bank-apk-hash-byte-siliguri-institute-of-technology.streamlit.app/

Team 

Amol Kumar (Lead)

Rohini Kumari

Bhaskar Kumar

Masuddar Rahaman

