import streamlit as st
import re
import uuid
from supabase import create_client, Client

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="OSINT Entity Resolution", layout="wide")


# --- SUPABASE AUTHENTICATION ---
@st.cache_resource
def init_supabase() -> Client:
    """Initialize the Supabase client using Streamlit secrets."""
    url = st.secrets["SUPABASE_URL"]
    key = st.secrets["SUPABASE_ANON_KEY"]
    return create_client(url, key)


supabase = init_supabase()


def render_login_screen():
    st.title("🔒 GGH OSINT Tools")
    st.write("Sign in with your Verdict Scope credentials.")

    with st.form("login_form"):
        email_field = st.text_input("Email Address")
        password_field = st.text_input("Password", type="password")
        submit_btn = st.form_submit_button("Authenticate", type="primary")

        if submit_btn:
            try:
                auth_session = supabase.auth.sign_in_with_password({
                    "email": email_field,
                    "password": password_field
                })
                st.session_state.authenticated = True
                st.session_state.user_email = auth_session.user.email
                st.rerun()
            except Exception as auth_error:
                error_id = str(uuid.uuid4())
                print(f"AUTH ERROR [{error_id}]: {str(auth_error)}")
                st.error("Authentication Rejected. Please check your credentials.")


# --- MAIN UI PIPELINE ---
def main_pipeline():
    # Sidebar Session Management
    st.sidebar.title("🔎 OSINT Pipeline")
    st.sidebar.write(f"Logged in as: `{st.session_state.user_email}`")
    if st.sidebar.button("Sign Out", type="secondary"):
        supabase.auth.sign_out()
        st.session_state.authenticated = False
        st.rerun()

    st.title("🔎 OSINT Cross-Reference Pipeline")
    st.markdown("Automated comparison of Ground Truth data against HIBP and Maigret.")

    # Create the two-column layout
    col1, col2 = st.columns([1, 1])

    with col1:
        st.subheader("1. Ground Truth Input")

        # Either/Or Toggle for Input Method
        input_method = st.radio(
            "Select Input Method:",
            ("Manual Entry", "File Upload"),
            horizontal=True
        )

        ground_truth_text = ""

        if input_method == "Manual Entry":
            st.markdown("**Enter Known Ground Truth Details:**")

            c1, c2 = st.columns(2)
            with c1:
                gt_name = st.text_input("Ground Truth Name (First Middle Last)")
                gt_dob = st.text_input("DOB (##-##-####)")
                gt_email = st.text_input("Email (comma separated)")
            with c2:
                gt_phone = st.text_input("Phone (comma separated)")
                gt_ssn = st.text_input("SS# (last four)")
                gt_address = st.text_input("Address")

            gt_parts = []
            if gt_name: gt_parts.append(f"Ground Truth Name: {gt_name}")
            if gt_dob: gt_parts.append(f"DOB: {gt_dob}")
            if gt_email: gt_parts.append(f"email: {gt_email}")
            if gt_phone: gt_parts.append(f"Phone: {gt_phone}")
            if gt_ssn: gt_parts.append(f"SS#: {gt_ssn}")
            if gt_address: gt_parts.append(f"Address: {gt_address}")

            ground_truth_text = "\n".join(gt_parts)

        else:
            ground_truth_file = st.file_uploader("Upload Ground Truth (.txt)", type=["txt"])
            if ground_truth_file is not None:
                ground_truth_text = ground_truth_file.read().decode("utf-8")

    with col2:
        st.subheader("2. Execution & Generation")
        st.info("Ready to connect to HIBP and Maigret.")

        if st.button("🚀 Run OSINT Pipeline", use_container_width=True):
            if not ground_truth_text:
                st.error("Please provide Ground Truth data.")
            else:
                emails_found = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", ground_truth_text)
                phones_found = re.findall(r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}", ground_truth_text)

                if not emails_found:
                    st.error("No valid email address found in the Ground Truth data.")
                else:
                    target_email = emails_found[0].strip()

                    from api_orchestrator import search_hibp, run_maigret
                    from gemini_engine import analyze_osint_data

                    with st.status(f"Executing OSINT Pipeline for {target_email}...", expanded=True) as status:
                        st.write(f"Querying Have I Been Pwned for {target_email}...")
                        hibp_res = search_hibp(target_email)

                        if phones_found:
                            raw_phone = re.sub(r'\D', '', phones_found[0])
                            hibp_phone_query = f"1{raw_phone}" if len(raw_phone) == 10 else raw_phone

                            st.write(f"Querying Have I Been Pwned for phone {hibp_phone_query}...")
                            hibp_phone_res = search_hibp(hibp_phone_query)

                            if isinstance(hibp_res, list) and isinstance(hibp_phone_res, list):
                                hibp_res.extend(hibp_phone_res)

                        st.write("Running Maigret on username (this may take a few minutes)...")
                        maigret_res = run_maigret(target_email)

                        st.write("Cross-referencing data with Gemini...")
                        final_analysis = analyze_osint_data(
                            ground_truth_text,
                            hibp_res,
                            maigret_res
                        )

                        status.update(label="Analysis Complete!", state="complete", expanded=False)

                    from report_builder import render_report
                    render_report(final_analysis, maigret_res, hibp_res, ground_truth_text, target_email)


# --- GLOBAL APP WINDOW ---
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    render_login_screen()
else:
    main_pipeline()