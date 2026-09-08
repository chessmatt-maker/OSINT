import streamlit as st
import re
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


def check_authentication():
    """
    Placeholder for the cookie-controller and temporary password logic.
    For now, returning True so you can build and test the UI locally.
    """
    return True


# --- MAIN UI PIPELINE ---
def main_pipeline():
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

            # Compile the filled blanks into the exact requested string format
            gt_parts = []
            if gt_name: gt_parts.append(f"Ground Truth Name: {gt_name}")
            if gt_dob: gt_parts.append(f"DOB: {gt_dob}")
            if gt_email: gt_parts.append(f"email: {gt_email}")
            if gt_phone: gt_parts.append(f"Phone: {gt_phone}")
            if gt_ssn: gt_parts.append(f"SS#: {gt_ssn}")
            if gt_address: gt_parts.append(f"Address: {gt_address}")

            ground_truth_text = "\n".join(gt_parts)

        else:
            # File Upload Logic
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
                # Extract the first email found in the ground truth text using regex
                emails_found = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", ground_truth_text)

                if not emails_found:
                    st.error(
                        "No valid email address found in the Ground Truth data. Please include an email to run the pipeline.")
                else:
                    target_email = emails_found[0].strip()

                    # Import your backend logic
                    from api_orchestrator import search_hibp, run_maigret
                    from gemini_engine import analyze_osint_data

                    with st.status(f"Executing OSINT Pipeline for {target_email}...", expanded=True) as status:
                        st.write(f"Querying Have I Been Pwned for {target_email}...")
                        hibp_res = search_hibp(target_email)

                        st.write("Running Maigret on username (this may take a few minutes)...")
                        maigret_res = run_maigret(target_email)

                        st.write("Cross-referencing data with Gemini...")
                        final_analysis = analyze_osint_data(
                            ground_truth_text,
                            hibp_res,
                            maigret_res
                        )

                        status.update(label="Analysis Complete!", state="complete", expanded=False)

                    # Render the formal dossier layout
                    from report_builder import render_report
                    render_report(final_analysis, maigret_res, hibp_res, ground_truth_text, target_email)


if __name__ == "__main__":
    if check_authentication():
        main_pipeline()
    else:
        st.warning("Please log in to access the OSINT tools.")