import csv
import math
import streamlit as st
from google import genai

# Class 12 CS Configuration & Data Assets
DATASET_FILE = "kaggle_scams.csv"
SCAM_KEYWORDS = [
    "scam",
    "fee",
    "deposit",
    "urgent",
    "pay",
    "whatsapp",
    "telegram",
    "registration",
    "rupees",
    "earn",
    "guaranteed",
]
SUSPICIOUS_DOMAINS = ["@gmail.com", "@yahoo.com", "@outlook.com"]


# 1. Dataset Reader (CSV File Handling)
@st.cache_data
def load_and_train_simulation():
  word_counts_in_scams = {word: 0 for word in SCAM_KEYWORDS}
  total_records, scam_records, safe_records = 0, 0, 0
  try:
    with open(
        DATASET_FILE, mode="r", encoding="latin-1", errors="ignore"
    ) as file:
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
        else 0
    )
    return (
        word_counts_in_scams,
        total_records,
        scam_records,
        safe_records,
        entropy,
    )
  except FileNotFoundError:
    return None


# Streamlit UI Configuration
st.set_page_config(
    page_title="InternScan AI", page_icon="🛡️", layout="centered"
)
st.title("🛡️ InternScan: Job Scam Detection System")
st.write("Class 12 Project (Powered by Heuristic Analysis & Gemini AI)")
st.markdown("---")

# Sidebar - API Key Input & Dataset Analytics
st.sidebar.header("🔑 API Settings")
user_api_key = st.sidebar.text_input(
    "Enter Gemini API Key (For AI Engine):",
    type="password",
    help="Get a free key from Google AI Studio",
)

data_results = load_and_train_simulation()

if data_results is None:
  st.error(f"❌ Error: '{DATASET_FILE}' not found in the directory!")
else:
  trained_weights, total_rec, scam_rec, safe_rec, entropy_val = data_results

  st.sidebar.markdown("---")
  st.sidebar.header("📊 Dataset Analytics Dashboard")
  st.sidebar.info(f"**Total Records Trained:** {total_rec}")
  st.sidebar.success(f"**Genuine Samples:** {safe_rec}")
  st.sidebar.error(f"**Scam Samples:** {scam_rec}")
  st.sidebar.warning(f"**Dataset Entropy:** {entropy_val:.4f}")

  # Main User Form
  st.subheader("🔍 Scan a New Job Posting / Email")
  text_input = st.text_area(
      "Paste the Job Description text here:",
      height=150,
      placeholder="Example: Urgent requirement! Earn 5000/day. Pay registration fee...",
  )
  email_input = st.text_input(
      "Recruiter's Email Address (Optional):", placeholder="hr@company.com"
  )

  if st.button("🚀 Run AI Scan Risk Analysis"):
    if not text_input.strip():
      st.warning("⚠️ Please paste job description text to analyze.")
    else:
      # Mode Selection: AI or Heuristic
      if user_api_key.strip():
        st.markdown("---")
        st.subheader("🎯 AI Deep Evaluation Report")
        try:
          # Latest google-genai SDK Syntax
          client = genai.Client(api_key=user_api_key.strip())

          prompt = f"""
                    You are an expert fraud detection AI. Analyze the following job posting and email for potential scam indicators.
                    
                    Job Description:
                    "{text_input}"

                    Recruiter Email:
                    "{email_input if email_input else 'Not Provided'}"

                    Provide a structured response:
                    1. Risk Score (0 to 100)
                    2. Risk Category (LOW RISK / MODERATE RISK / HIGH RISK)
                    3. Key Risk Factors / Red Flags identified
                    4. Advice for candidate
                    """

          with st.spinner("AI Engine Analyzing Content..."):
            response = client.models.generate_content(
                model="gemini-2.5-flash", contents=prompt
            )
            st.markdown(response.text)

        except Exception as e:
          st.error(f"AI Error: {e}")
      else:
        # Algorithmic / Heuristic Risk Scoring
        text_lower = text_input.lower()
        email_lower = email_input.lower()
        word_count = len(text_lower.split())

        risk_score = 0
        triggered_features = []

        # 1. Substring Keyword Detection
        for word in SCAM_KEYWORDS:
          if word in text_lower:
            risk_score += 40
            triggered_features.append(f"High-Risk Keyword Detected: '{word}'")

        # 2. Public Domain Email Check
        if any(domain in email_lower for domain in SUSPICIOUS_DOMAINS):
          risk_score += 25
          triggered_features.append(
              "Sender Domain Alert: Unverified public email server used."
          )

        # 3. Short / Vague Description Check
        if word_count < 10:
          risk_score += 35
          triggered_features.append(
              f"Structural Anomaly: Description is too short ({word_count}"
              " words)."
          )

        risk_score = min(risk_score, 100)

        st.markdown("---")
        st.subheader("🎯 Scan Evaluation Report (Heuristic Mode)")
        st.info(
            "💡 Tip: Enter Gemini API key in sidebar for 100% accurate AI Deep"
            " Analysis."
        )

        st.write(f"**Aggregated Risk Score: {risk_score}/100**")
        st.progress(risk_score / 100)

        if risk_score >= 60:
          st.error(
              "🚨 Final Classification Verdict: [ HIGH RISK / FRAUD WARNING ]"
          )
        elif risk_score >= 30:
          st.warning(
              "⚠️ Final Classification Verdict: [ MODERATE RISK / CAUTION"
              " REQUIRED ]"
          )
        else:
          st.success(
              "✅ Final Classification Verdict: [ LOW RISK / LIKELY SAFE ]"
          )

        with st.expander("🛠️ View System Trace Logs"):
          if triggered_features:
            for feature in triggered_features:
              st.write(f"- {feature}")
          else:
            st.write("- No obvious risk patterns found in heuristic check.")


