import streamlit as st
import os
import logging
# import bcrypt  # Uncomment for production

logger = logging.getLogger(__name__)

def check_password_and_login() -> bool:
    """
    Checks if the user is authenticated. If not, displays a login form.
    Returns True if authenticated, False otherwise.
    """
    if st.session_state.get("password_correct", False):
        if st.sidebar.button("Logout", key="auth_logout_button"):
            st.session_state.password_correct = False
            st.rerun()
        return True

    st.sidebar.subheader("Login")
    username = st.sidebar.text_input("Username", key="auth_username_input")
    password = st.sidebar.text_input("Password", type="password", key="auth_password_input")

    if st.sidebar.button("Login", key="auth_login_button"):
        admin_user = os.getenv('STREAMLIT_ADMIN_USER', 'admin')
        admin_pass = os.getenv('STREAMLIT_ADMIN_PASS', 'password')
        
        # For production, use bcrypt for password hashing and verification:
        # hashed_pass = bcrypt.hashpw(admin_pass.encode(), bcrypt.gensalt()).decode()
        # if username == admin_user and bcrypt.checkpw(password.encode(), hashed_pass.encode()):

        # For demonstration purposes, a simple string comparison:
        if username == admin_user and password == admin_pass:
            st.session_state.password_correct = True
            st.rerun()
        else:
            st.sidebar.error("Incorrect username or password")
    return False
