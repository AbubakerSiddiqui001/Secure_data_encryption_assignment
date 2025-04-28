import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- Session State Setup ---
if "KEY" not in st.session_state:
    st.session_state.KEY = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.KEY)
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# --- Functions ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return st.session_state.cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

def reset_failed_attempts():
    st.session_state.failed_attempts = 0

# --- Page Config ---
st.set_page_config(page_title="Secure Data Encryption - Dark Mode", page_icon="🛡️", layout="centered")

# --- Custom Dark Theme CSS ---
st.markdown(
    """
    <style>
    /* Full background with light gradient */
    body, .stApp {
        background: linear-gradient(135deg, #f9f9f9, #e0e0ff) !important;
        color: #333333 !important;
    }

    /* Headings */
    h1, h2, h3, h4, h5, h6 {
        color: #4B0082 !important; /* Deep purple heading */
    }

    /* Buttons */
    .stButton>button {
        background: linear-gradient(90deg, #7b2ff7, #f107a3) !important;
        color: white !important;
        border-radius: 8px;
        padding: 0.5rem 1rem;
        border: none;
        transition: 0.3s;
    }
    .stButton>button:hover {
        background: linear-gradient(90deg, #6200ea, #d500f9) !important;
        color: #ffffff !important;
    }

    /* Text Inputs */
    .stTextInput>div>div>input, 
    textarea, 
    .stTextArea>div>div>textarea {
        background-color: #ffffff !important;
        color: #333333 !important;
        border: 1px solid #cccccc !important;
    }

    /* Form containers */
    .css-1cpxqw2, .css-1d391kg {
        background-color: #ffffff !important;
        border-radius: 10px;
        padding: 20px;
        color: #333333 !important;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    }

    /* Sidebar */
    .css-6qob1r, .css-1lcbmhc {
        background: linear-gradient(180deg, #f9f9f9, #e0e0ff) !important;
        color: #333333 !important;
    }

    /* Alerts (Success, Info, Error messages) */
    .stAlert {
        background-color: #f1f1f1 !important;
        color: #333333 !important;
        border-left: 5px solid #4B0082;
    }

    </style>
    """,
    unsafe_allow_html=True,
)

# --- Main Title ---
st.markdown("<h1 style='text-align: center;'>🛡️ Secure Data Encryption System</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>Store and retrieve sensitive data securely and stylishly 🚀</p>", unsafe_allow_html=True)

# --- Sidebar Navigation ---
menu = ["🏠 Home", "🛡️ Store Data", "🔍 Retrieve Data", "🔑 Login"]
choice = st.sidebar.selectbox("Navigation", menu)

st.sidebar.markdown("---")
st.sidebar.markdown("<p style='color:#BBBBBB; text-align: center;'>Made by ❤️ Abubaker Siddiqui </p>", unsafe_allow_html=True)

# --- Pages ---
if choice == "🏠 Home":
    st.subheader("🏠 Welcome to Secure App - Dark Mode")
    st.info("Use the sidebar to navigate between storing and retrieving your secure data.")

elif choice == "🛡️ Store Data":
    st.subheader("🛡️ Store Your Data Securely")
    with st.form(key="store_form"):
        user_data = st.text_area("📝 Enter Your Data:", height=150)
        passkey = st.text_input("🔑 Enter a Secret Passkey:", type="password")
        submit_btn = st.form_submit_button("Encrypt & Save")

        if submit_btn:
            if user_data and passkey:
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data)
                st.session_state.stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
                st.success("✅ Your data has been securely stored!")
                st.code(encrypted_text, language="text")
            else:
                st.error("⚠️ Please fill in both fields.")

elif choice == "🔍 Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    with st.form(key="retrieve_form"):
        encrypted_text = st.text_area("🔒 Enter Your Encrypted Data:", height=150)
        passkey = st.text_input("🔑 Enter Your Secret Passkey:", type="password")
        decrypt_btn = st.form_submit_button("Decrypt")

        if decrypt_btn:
            if encrypted_text and passkey:
                decrypted_text = decrypt_data(encrypted_text, passkey)
                if decrypted_text:
                    st.success("✅ Decrypted Data:")
                    st.code(decrypted_text, language="text")
                else:
                    st.error(f"❌ Incorrect passkey! Attempts left: {3 - st.session_state.failed_attempts}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts! Please login again.")
                        st.experimental_rerun()
            else:
                st.error("⚠️ Please fill in both fields.")

elif choice == "🔑 Login":
    st.subheader("🔑 Reauthorize Access")
    with st.form(key="login_form"):
        login_pass = st.text_input("🔐 Enter Master Password:", type="password")
        login_btn = st.form_submit_button("Login")

        if login_btn:
            if login_pass == "admin123":
                reset_failed_attempts()
                st.success("✅ Login successful!")
                st.balloons()
                st.experimental_rerun()
            else:
                st.error("❌ Incorrect master password!")