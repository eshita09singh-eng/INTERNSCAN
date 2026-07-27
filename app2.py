import csv
import math
import re
import streamlit as st

# Global Settings
DATASET_FILE = "kaggle_scams.csv"
SCAM_KEYWORDS = [
    "fee",
    "deposit",
    "urgent",
    "pay",
    "whatsapp",
    "telegram",
    "registration",
    "rupees",
    "earn",
    "salary",
    "guaranteed",]
SUSPICIOUS_DOMAINS = ["@gmail.com", "@yahoo.com", "@outlook.com"]

@st.cache_data
def load_and_train_simulation():
  word_counts_in_scams = {word: 0 for word in SCAM_KEYWORDS}
  total_records, scam_records, safe_records = 0, 0, 0
  try:
    with open(
        DATASET_FILE, mode="r", encoding="latin-1", errors="ignore")
      as file:
      csv_reader = csv.reader(file)
      next(csv_reader, None)  
      for row in csv_reader:
        if not row or len(row) < 2:
          continue
        total_records += 1
        if row[1].strip() == "1":
          scam_records += 1
          for word in SCAM_KEYWORDS:
            if word in row[0].lower():
              word_counts_in_scams[word] += 1
        else:
          safe_records += 1
    p_scam = scam_records / total_records if total_records > 0 else 0
    p_safe = safe_records / total_records if total_records > 0 else 0
    entropy = (
        -(p_scam * math.log2(p_scam) + p_safe * math.log2(p_safe))
        if p_scam > 0 and p_safe > 0
        else 0)
    return (word_counts_in_scams,total_records,scam_records,safe_records,entropy,)
  except FileNotFoundError:
    return None



st.set_page_config(
    page_title="InternScan AI", page_icon="🛡️", layout="centered")

st.title("🛡️ InternScan: Job Scam Detection System")
st.write("Class 12 Corporate Security Simulation Project (Powered by NLP & Risk Analysis)")
st.markdown("---")


data_results = load_and_train_simulation()

if data_results is None:
  st.error( f"❌ Critical Error: '{DATASET_FILE}' not found in this folder! Website cannot start." )
else:
  trained_weights, total_rec, scam_rec, safe_rec, entropy_val = data_results


  st.sidebar.header("📊 Dataset Analytics Dashboard")
  st.sidebar.info(f"**Total Records Trained:** {total_rec}")
  st.sidebar.success(f"**Genuine Samples:** {safe_rec}")
  st.sidebar.error(f"**Scam Samples:** {scam_rec}")
  st.sidebar.warning(f"**Dataset Entropy:** {entropy_val:.4f}")

  st.subheader("🔍 Scan a New Job Posting / Email")

  text_input = st.text_area("Paste the Job Description text here:",
      height=150,
      placeholder=("Example: Urgent requirement! Earn 5000/day. Pay 500 registration fee..." ), )
  email_input = st.text_input(
      "Recruiter's Email Address:", placeholder="hr@company.com")


  if st.button("🚀 Run AI Scan Risk Analysis"):
    if not text_input.strip():
      st.warning("⚠️ Please paste some text content to analyze.")
    else:
      words = text_input.lower().split()
      word_count = len(words)
      text_lower = text_input.lower()
      email_lower = email_input.lower()

      risk_score = 0
      triggered_features = []

     
      numbers = [int(n) for n in re.findall(r"\b\d+\b", text_lower)]
      has_unrealistic_amount = any(num >= 50000 for num in numbers)
      has_frequency_payout = any(p in text_lower for p in ["per day", "daily", "per hour", "p/d"}])

      if has_unrealistic_amount or (any(n >= 5000 for n in numbers) and has_frequency_payout):
        risk_score += 65
        triggered_features.append(
            "🚨 Unrealistic Payout Anomaly: Unreasonably high financial promise/daily payout detected.")

     
      if word_count < 10:
        risk_score += 35
        triggered_features.append(f"⚠️ Structural Anomaly: Description is too short ({word_count} words). Lacks job role details.")

      for word in SCAM_KEYWORDS:
        if word in words:
          risk_score += 20
          triggered_features.append(f"🚩 High-Risk Keyword Flag: '{word}' identified in text.")

      if any(domain in email_lower for domain in SUSPICIOUS_DOMAINS):
        risk_score += 20
        triggered_features.append(
            "📧 Sender Domain Alert: Public email domain (Gmail/Yahoo/Outlook) used instead of corporate server.")

      risk_score = min(risk_score, 100)

   
      st.markdown("---")
      st.subheader("🎯 Scan Evaluation Report")

      st.write(f"**Aggregated Risk Index: {risk_score}%**")
      st.progress(risk_score / 100)

      if risk_score >= 60:
        st.error("🚨 Final Classification Verdict: [ HIGH RISK / FRAUD WARNING ]")
      elif risk_score >= 30:
        st.warning("⚠️ Final Classification Verdict: [ MODERATE RISK / CAUTION REQUIRED ]")
      else:
        st.success("✅ Final Classification Verdict: [ LOW RISK / SAFE LISTING ]")

      st.markdown("### 📋 Risk Factor Analysis Breakdown")
      if triggered_features:
        for feature in triggered_features:
          st.error(feature) if risk_score >= 60 else st.warning(feature)
      else:
        st.success("✅ No critical risk vectors detected in the textual structures.")
