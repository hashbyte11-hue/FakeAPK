import streamlit as st
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature



st.set_page_config(page_title="HashByte — Frontend (Step-by-step)", layout="centered")

st.title("Virtual Demonstration of APK Security and Fake Detection Demo")
st.write("This UI presents Step-by-step workflow of the Project.")

# ----------------- Sidebar -----------------
with st.sidebar:
    st.image("organizer.png", use_container_width=True)

    st.markdown("### 📌 Submitted by")
    st.write("**Siliguri Institute of Technology**")

    st.markdown("### 👨‍🏫 Guided by")
    st.write("Prof: **Dr. Prasanta Kumar Roy**")
    st.write("📧 prasanta201284@gmail.com")

    st.markdown("### 👥 Team Members")
    team = [
        "Amol Kumar (Leader)",
        "Rohini Kurnari",
        "Bhaskar Kumar",
        "Masuddar Rahaman"
    ]
    for member in team:
        st.write(f"- {member}")

# ---------------- session state -----------------
for k in [
    "I", "J", "I_tampered", "private_key_obj", "public_key_bytes",
    "signature", "tampered_signature", "I_prime", "bank_J"
]:
    if k not in st.session_state:
        st.session_state[k] = None

# helper functions

def sha256_hex_file(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def file_exists_warn(path: str) -> bool:
    if not os.path.exists(path):
        st.warning(f"File not found: {path}. Run the appropriate earlier step first.")
        return False
    return True

# ---------------- Stage 1 ----------------
st.header("Create dummy APK files for verification")
if st.button("Create & Check Files"):
    with open("first_code.bin", "wb") as f:
        f.write(b"This is the First Executable Code of the APK")
    st.success("Created first_code.bin - contains (I)")

    with open("second_code.bin", "wb") as f:
        f.write(b"This is the Second Part of the Code")
    st.success("Created second_code.bin - contains (J)")

    # quick downloads
    with open("first_code.bin", "rb") as f:
        st.download_button("⬇ Download first_code.bin", f.read(), file_name="first_code.bin")
    with open("second_code.bin", "rb") as f:
        st.download_button("⬇ Download second_code.bin", f.read(), file_name="second_code.bin")

# ---------------- Stage 2 ----------------
st.header("Generating hashes, keys, signatures and a tampered signature for demo")
if st.button("Generate & Check"):
    if not file_exists_warn("first_code.bin") or not file_exists_warn("second_code.bin"):
        st.error("Step 1 must be run first.")
    else:
        st.session_state.I = sha256_hex_file("first_code.bin")
        st.session_state.J = sha256_hex_file("second_code.bin")

        st.session_state.I_tampered = hashlib.sha256(
            b"This is the First Executable Code of the APK **TAMPERED"
        ).hexdigest()

        private_key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        st.session_state.private_key_obj = private_key_obj
        public_key = private_key_obj.public_key()

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        st.session_state.public_key_bytes = public_bytes
        with open("public_key.pem", "wb") as f:
            f.write(public_bytes)

        data_to_sign = bytes.fromhex(st.session_state.I) + bytes.fromhex(st.session_state.J)
        signature = private_key_obj.sign(
            data_to_sign,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        st.session_state.signature = signature
        with open("signature.bin", "wb") as f:
            f.write(signature)

        tampered_sig = bytearray(signature)
        tampered_sig[0] ^= 0xFF
        st.session_state.tampered_signature = bytes(tampered_sig)
        with open("tampered_signature.bin", "wb") as f:
            f.write(st.session_state.tampered_signature)

        st.success(f"[APK SERVER] I = {st.session_state.I}")
        st.warning(f"[APK SERVER] I_tampered (demo) = {st.session_state.I_tampered}")
        st.info("Public key + signatures written to disk.")

        with open("public_key.pem", "rb") as f:
            st.download_button("⬇ Download public_key.pem", f.read(), file_name="public_key.pem")
        st.download_button("⬇ Download signature.bin (original)", st.session_state.signature, file_name="signature.bin")
        st.download_button("⬇ Download tampered_signature.bin (fake)", st.session_state.tampered_signature, file_name="tampered_signature.bin")

# ---------------- Stage 3 ----------------
st.header("3rd Party computes or chooses a tampered I'")
choice = st.radio("Which I' should the 3rd party use?", ("Compute from first_code.bin (correct)", "Use Tampered I_tampered (fake)"))
if st.button("Choose I'"):
    if choice.startswith("Use Tampered"):
        if st.session_state.I_tampered is None:
            st.error("Run Step 2 first to generate the tampered demo hash.")
        else:
            st.session_state.I_prime = st.session_state.I_tampered
            st.warning(f"[3rd PARTY] Tempered I' = {st.session_state.I_prime}")
    else:
        if not file_exists_warn("first_code.bin"):
            st.error("first_code.bin missing — run Step 1 first.")
        else:
            with open("first_code.bin", "rb") as f:
                code_3rdparty = f.read()
            st.session_state.I_prime = hashlib.sha256(code_3rdparty).hexdigest()
            st.success(f"[3rd PARTY] Computed I' = {st.session_state.I_prime}")

    if os.path.exists("signature.bin"):
        with open("signature.bin", "rb") as f:
            sig_preview = f.read(40)
        st.write("[3rd PARTY] Received signature preview (first 40 bytes):")
        st.code(sig_preview.hex())
    else:
        st.info("signature.bin not found yet — run Step 2.")

# ---------------- Stage 4 ----------------
st.header("Bank Verifies I == I'")
if st.button("Run Step 4 — Bank Verify"):
    if st.session_state.I_prime is None:
        st.error("I' not computed — run Step 3 first.")
        st.stop()

    if not file_exists_warn("first_code.bin"):
        st.error("first_code.bin missing — run Step 1 first.")
        st.stop()

    bank_I = sha256_hex_file("first_code.bin")
    if st.session_state.I_prime != bank_I:
        st.error(" Session Expired: Fake APK detected (I != I')")
        st.session_state.bank_J = None
        st.stop()
    else:
        st.success("[BANK] I == I' verified")
        st.session_state.bank_J = sha256_hex_file("second_code.bin")
        st.info(f"[BANK] J = {st.session_state.bank_J}")
        with open("second_code.bin", "rb") as f:
            st.download_button("⬇ Download second_code.bin", f.read(), file_name="second_code.bin")

# ---------------- Stage 5 ----------------
st.header("Final Verification (RSA)")
sig_choice = st.radio("Which Signature should be used?", ("Original signature.bin", "Tampered tampered_signature.bin"))

if st.button("Run Step 5 — Verify"):
    if not st.session_state.I_prime or not st.session_state.bank_J:
        st.error("Run Steps 3 and 4 before final verification.")
    else:
        sig = st.session_state.signature if sig_choice.startswith("Original") else st.session_state.tampered_signature
        if sig is None:
            st.error(" No signature found. Run Step 2 (APK Server) first.")
        else:
            data_to_verify = bytes.fromhex(st.session_state.I_prime) + bytes.fromhex(st.session_state.bank_J)
            try:
                with open("public_key.pem", "rb") as f:
                    pubkey = serialization.load_pem_public_key(f.read())

                pubkey.verify(
                    sig,
                    data_to_verify,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )

                # Save result in session state
                st.session_state.signature_valid = True
                st.success("(RSA) Signature Verified Successfully")
                st.info("Installation Successful: Key and Signature Verified, APK is Genuine.")

            except InvalidSignature:
                # Save failed result
                st.session_state.signature_valid = False
                st.error("Signature/Key verification failed")
                st.warning("⚠ Reason: The chosen signature file does not match the APK. Possible tampering detected.")
                st.error("Installation Failed: Fake APK detected. RSA Verification failed.")

            except Exception as e:
                st.session_state.signature_valid = False
                st.error(f" Verification error: {e}")



st.header("Final Verification & Installation Check")

if st.button("Verify & Install"):
    # Ensure Stage 5 was executed (signature validation)
    if "signature_valid" not in st.session_state:
        st.error("Missing Step 5 result (run Step 5 first).")

    else:
        # If Step 5 failed → reject installation immediately
        if not st.session_state.signature_valid:
            st.error("Tampered Signature Detected! Application installation failed.")
        
        else:
            # If signature is valid → allow installation
            st.success("Verification Successful (RSA Signature Valid). Application can be installed.")

st.markdown("---")
st.write("Copyright © 2025 HashByte Demo. All rights reserved.")

