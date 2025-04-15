import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# Constants
#create file to store data
CREDENTIALS_FILE = "credentials.json"
KEY_FILE = "secret.key"
MAX_ATTEMPTS = 3

# Load or create encryption key
def load_key():
    #open file in binary mode
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

# Encryption setup
KEY = load_key()
cipher = Fernet(KEY)

# Load credentials
def load_credentials():
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as file:
            return json.load(file)
    return {}

# Save credentials
def save_credentials(credentials):
    with open(CREDENTIALS_FILE, "w") as file:
        json.dump(credentials, file, indent=4)

# Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt password
#decode password
def encrypt_password(password):
    return cipher.encrypt(password.encode()).decode()

# Decrypt password
#enocde 
def decrypt_password(encrypted_password):
    try:
        return cipher.decrypt(encrypted_password.encode()).decode()
    except:
        return None

# Initialize session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "current_user" not in st.session_state:
    st.session_state.current_user = None

credentials = load_credentials()

# UI: Tabs for Login / Register / Data Storage
tabs = st.tabs(["Login", "Register", "Store & Retrieve Data","view store data"])


with tabs[0]:
    st.subheader("Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if email in credentials:
            stored = credentials[email]
            decrypted_pw = decrypt_password(stored["encrypted_text"])

            if decrypted_pw == password:
                st.success(f"Welcome back, {email}!")
                st.session_state.logged_in = True
                st.session_state.failed_attempts = 0
                st.session_state.current_user = email
            else:
                st.session_state.failed_attempts += 1
                st.error(" Incorrect password")
        else:
            st.error("⚠User not found")

        if st.session_state.failed_attempts >= MAX_ATTEMPTS:
            st.warning(" Too many failed attempts. Please try again later.")

# 📝 REGISTRATION TAB
with tabs[1]:
    st.subheader("Register")
    new_email = st.text_input("New Email")
    new_password = st.text_input(" New Password", type="password")

    if st.button("Register"):
        if new_email in credentials:
            st.warning("User already exists")
        elif new_email and new_password:
            hashed = hash_passkey(new_password)
            encrypted = encrypt_password(new_password)
            credentials[new_email] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            save_credentials(credentials)
            st.success("User registered successfully!")
        else:
            st.error("Please fill both fields")

# 📦 STORE / RETRIEVE DATA TAB
with tabs[2]:
    if not st.session_state.logged_in:
        st.warning("Please login first to store/retrieve data.")
    else:
        st.subheader("Secure Data Storage")
        user_data = st.text_area("Enter data to store")
        user_passkey = st.text_input("Enter passkey to encrypt", type="password")

        if st.button("Encrypt & Save"):
            if user_data and user_passkey:
                hashed = hash_passkey(user_passkey)
                encrypted = cipher.encrypt(user_data.encode()).decode()
                user_key = st.session_state.current_user + "_data"

                credentials[user_key] = {
                    "encrypted_text": encrypted,
                    "passkey": hashed
                }
                save_credentials(credentials)
                st.success(" Data stored securely!")
            else:
                st.error("⚠Provide both data and passkey")

        st.subheader(" Retrieve Stored Data")
        encrypted_input = st.text_area("Paste your encrypted text here")
        passkey_input = st.text_input("Enter your passkey to decrypt", type="password")

        if st.button("Decrypt Data"):
            if encrypted_input and passkey_input:
                hashed_input = hash_passkey(passkey_input)
                user_key = st.session_state.current_user + "_data"
                entry = credentials.get(user_key)

                if entry and entry["encrypted_text"] == encrypted_input and entry["passkey"] == hashed_input:
                    try:
                        decrypted = cipher.decrypt(encrypted_input.encode()).decode()
                        st.success(f"Decrypted Data: {decrypted}")
                    except:
                        st.error("⚠ Failed to decrypt stored data.")
                else:
                    st.warning("Invalid passkey or encrypted text.")
            else:
                st.error("⚠Please provide both fields")

with tabs[3]:
    st.subheader(" view store data")

    if not st.session_state.logged_in:
        st.warning("Please login to view your data.")
    else:
        user_key = st.session_state.current_user + "_data"
        entry = credentials.get(user_key)

        if entry:
            st.markdown("### 🔒 Encrypted Data:")
            st.code(entry["encrypted_text"], language="text")
            st.markdown("### 🧾 Stored Hashed Passkey:")
            st.code(entry["passkey"], language="text")
        else:
            st.info("No data stored for this user.")

#python3 -m venv cryptoenv

#maeydahmasroor@Maeydahs-MacBook-Pro ~ % source cryptoenv/bin/activate

