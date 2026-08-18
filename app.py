import streamlit as st
from utils.parser import parse_ground_truth, sanitize_spiderfoot, sanitize_maigret
from utils.ai_engine import evaluate_osint_data, filter_by_ground_truth
from utils.report_gen import generate_docx_report

st.set_page_config(page_title="OSINT Lit-Defense Pipeline", layout="wide", page_icon="⚖️")

st.title("⚖️ OSINT Pipeline for Civil Litigation")
st.markdown("Automated intake, AI-driven filtering, and litigation-ready report generation.")

# --- SIDEBAR: File Uploads ---
st.sidebar.header("1. Data Ingestion")
st.sidebar.markdown("Upload your raw extraction files below.")

gt_file = st.sidebar.file_uploader("Upload Ground Truth (.txt)", type=["txt"])
sf_files = st.sidebar.file_uploader("Upload SpiderFoot Scan(s) (.json)", type=["json"], accept_multiple_files=True)
mg_files = st.sidebar.file_uploader("Upload Maigret Output(s) (.json)", type=["json"], accept_multiple_files=True)

if st.sidebar.button("Run OSINT Evaluation", type="primary"):
    if not (gt_file and (sf_files or mg_files)):
        st.sidebar.error("Please upload the Ground Truth file and at least one SpiderFoot or Maigret file.")
    else:
        # --- PROCESSING PIPELINE ---
        with st.spinner("Step 1: Parsing and Sanitizing Input Data..."):
            gt_text = gt_file.getvalue().decode("utf-8")
            ground_truth = parse_ground_truth(gt_text)

            sf_sanitized = []
            for f in sf_files:
                sf_sanitized.extend(sanitize_spiderfoot(f.getvalue().decode("utf-8")))

            mg_sanitized = []
            for f in mg_files:
                mg_sanitized.extend(sanitize_maigret(f.getvalue().decode("utf-8")))

        with st.spinner("Step 2: Filtering SpiderFoot results against Ground Truth..."):
            gt_filter_results = filter_by_ground_truth(ground_truth, sf_sanitized)

        with st.spinner("Step 3: Connecting to Vertex AI for Connection Chain Analysis..."):
            analysis_results = evaluate_osint_data(ground_truth, sf_sanitized, mg_sanitized)

        if analysis_results:
            st.success("Analysis Complete!")

            # --- Ground Truth Filter Results ---
            if gt_filter_results:
                st.header("🔍 Ground Truth Filter Results")
                fr = gt_filter_results.get("filtered_results", {})

                acv = gt_filter_results.get("actionable_contact_vectors", {})
                if acv.get("primary_phone") or acv.get("primary_email"):
                    st.subheader("✅ Actionable Contact Vectors")
                    col_p, col_e = st.columns(2)
                    col_p.metric("Primary Phone", acv.get("primary_phone") or "—")
                    col_e.metric("Primary Email", acv.get("primary_email") or "—")

                col_vm, col_pm = st.columns(2)
                with col_vm:
                    st.subheader("✅ Verified Matches")
                    for item in fr.get("verified_matches", []):
                        st.success(item)
                with col_pm:
                    st.subheader("🔶 Probable Matches")
                    for item in fr.get("probable_matches", []):
                        st.warning(item)

                col_di, col_un = st.columns(2)
                with col_di:
                    st.subheader("❌ Divergent Identities")
                    for item in fr.get("divergent_identities", []):
                        st.error(f"**{item.get('conflict_reason', '')}** — {item.get('raw_data', '')}")
                with col_un:
                    st.subheader("❓ Unverified Noise")
                    for item in fr.get("unverified_noise", []):
                        st.info(item)

                st.divider()

            # --- UI PREVIEW ---
            st.header("Executive Summary")
            st.write(analysis_results.get("executive_summary", ""))

            col1, col2 = st.columns(2)

            with col1:
                st.subheader("Tier 1 & 2 Findings")
                high_conf = [f for f in analysis_results.get("findings", []) if
                             f["confidence_tier"] in ["Tier 1", "Tier 2"]]
                st.dataframe(high_conf, use_container_width=True)

            with col2:
                st.subheader("⚠️ Tier 3 (Dubious) Leads")
                dubious = [f for f in analysis_results.get("findings", []) if f["confidence_tier"] == "Tier 3"]
                st.dataframe(dubious, use_container_width=True)

            st.subheader("Targeted Google Dorks")
            for dork in analysis_results.get("google_dorks", []):
                st.code(dork, language="plaintext")

            # --- DOCUMENT GENERATION ---
            with st.spinner("Step 4: Generating Litigation-Ready Word Report..."):
                acv = gt_filter_results.get("actionable_contact_vectors", {}) if gt_filter_results else {}
                doc_bytes = generate_docx_report(ground_truth, analysis_results, acv)

            st.divider()
            st.download_button(
                label="📄 Download OSINT Word Report (.docx)",
                data=doc_bytes,
                file_name=f"OSINT_Report_{ground_truth.get('primary_name', 'Subject').replace(' ', '_')}.docx",
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                type="primary"
            )
        else:
            st.error("Pipeline failed during AI Evaluation. Check your GCP Service Account credentials and quota.")