import streamlit as st
import hashlib
import base64
import json
import os
import re
from cryptography.fernet import Fernet

# ========================
# 📁 FILE SETUP
# ========================
SECURE_DIR = ".secure"
os.makedirs(SECURE_DIR, exist_ok=True)
CREDENTIALS_FILE = os.path.join(SECURE_DIR, "credentials.json")
KEY_FILE = os.path.join(SECURE_DIR, "secret.key")
DATA_FILE = os.path.join(SECURE_DIR, "data.json")
MAX_ATTEMPTS = 3

def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

fernet = Fernet(load_key())

def hash_with_salt(password):
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return base64.b64encode(salt + hashed).decode()

def verify_password(stored, provided):
    data = base64.b64decode(stored.encode())
    salt, stored_hash = data[:16], data[16:]
    new_hash = hashlib.pbkdf2_hmac("sha256", provided.encode(), salt, 100000)
    return new_hash == stored_hash

def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )

# ========================
def load_credentials():
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as file:
            return json.load(file)
    return {}

def save_credentials(credentials):
    with open(CREDENTIALS_FILE, "w") as file:
        json.dump(credentials, file, indent=4)

def save_encrypted_data(username, encrypted_data):
    data = {}
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            data = json.load(f)
    data[username] = encrypted_data.decode()
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def load_and_decrypt_data(username):
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            data = json.load(f)
        if username in data:
            encrypted = data[username].encode()
            try:
                return fernet.decrypt(encrypted).decode()
            except:
                return "Decryption failed."
    return "No data found for this username."

# ========================
# 🧠 SESSION STATE INIT
# ========================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "failed_logins" not in st.session_state:
    st.session_state.failed_logins = {}

# ========================
# 🌐 UI HEADER & LOGOUT
# ========================
st.title("Secure Login & Encrypted Data App")

if st.session_state.logged_in:
    if st.button("🚪 Logout"):
        st.session_state.logged_in = False
        st.session_state.current_user = None
        st.success("Logged out successfully!")

tabs = st.tabs(["Login", "Register", "Store & Retrieve Data", "View Stored Credentials"])

credentials = load_credentials()

with tabs[0]:
    st.subheader("Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        attempts = st.session_state.failed_logins.get(email, 0)
        if attempts >= MAX_ATTEMPTS:
            st.warning("Too many failed attempts.")
        elif email in credentials:
            if verify_password(credentials[email]["passkey"], password):
                st.success(f"Welcome back, {email}!")
                st.session_state.logged_in = True
                st.session_state.current_user = email
                st.session_state.failed_logins[email] = 0
            else:
                st.session_state.failed_logins[email] = attempts + 1
                st.error("Incorrect password.")
        else:
            st.error("User not found.")

# ========================
# 📝 REGISTER TAB
# ========================
with tabs[1]:
    st.subheader("Register")
    new_email = st.text_input("New Email")
    new_password = st.text_input("New Password", type="password")

    if st.button("Register"):
        if new_email in credentials:
            st.warning("User already exists.")
        elif not is_strong_password(new_password):
            st.error("Password must include uppercase, lowercase, number, symbol & be 8+ characters.")
        else:
            credentials[new_email] = {"passkey": hash_with_salt(new_password)}
            save_credentials(credentials)
            st.success("Registered successfully!")

# ========================
# =======================
with tabs[2]:
    if not st.session_state.logged_in:
        st.warning("Please login to continue.")
    else:
        st.subheader("Store or Retrieve Secret Data")
        username = st.text_input("Username")
        secret = st.text_input("Enter secret")

        if st.button("Encrypt & Save"):
            if username and secret:
                encrypted = fernet.encrypt(secret.encode())
                save_encrypted_data(username, encrypted)
                st.success("✅ Data saved securely!")

        if st.button("Decrypt Data"):
            if username:
                result = load_and_decrypt_data(username)
                st.info(f"Decrypted Message: {result}")

with tabs[3]:
    st.subheader("Stored Credentials")
    if not st.session_state.logged_in:
        st.warning("Login required.")
    else:
        email = st.session_state.current_user
        data = credentials.get(email)
        if data:
            st.markdown(f"**Email:** `{email}`")
            st.code(data['passkey'], language="text")
        else:
            st.info("No credentials found.")
