 **Fake Banking APK Detection**

 **Demo**

- Google Colab - https://colab.research.google.com/drive/17GTozyCJW6saOeFmj4OELUfSrKMQsYHq#scrollTo=1PkOg-uWFeHv 
- Deploy Link - https://detect-fake-bank-apk-hash-byte-siliguri-institute-of-technology.streamlit.app/

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
  
_These attacks often lead to data theft and financial fraud._

**Proposed Solution**

_We propose an approach that ensures APK Security before installation by integrating multiple verification layers:_
- Source Authentication → Verify that the APK originates from a trusted source.
- Code Integrity Check → Detect tampering in APK files.
- Digital Signature Verification → Validate the authenticity of the APK.
- Only when all three checks PASS, the APK is installed.

**This guarantees:**

- Stronger protection against malicious APK files.
- Reduced cyberattack surface.
- Increased customer trust in mobile banking applications.

**Tech Stack**

- Backend: Python, Cryptography Packages and Python Built-in library
- Frontend: Streamlit (for visualization & demo)
- Notebook: Google Colab
- Security: RSA, SHA-256

**Key Benefits**

- Prevents APK tampering before installation.
- Detects fake/malicious banking apps.
- Enhances security & trust in mobile banking.
- Lightweight and scalable solution.

_**Team**_

- Amol Kumar (Lead)
- Bhaskar Kumar
- Rohini Kumari
- Masuddar Rahaman

