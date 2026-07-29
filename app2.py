import csv
import math
import re
import streamlit as st
DATASET_FILE = "kaggle_scams.csv"
SCAM_KEYWORDS = ["fee","deposit","urgent","pay","whatsapp","telegram","registration","rupees","earn","salary","guaranteed"]
PROFANITY_KEYWORDS = ["scam","fraud","abuse","fake","cheat"]
SUSPICIOUS_DOMAINS = ["@gmail.com", "@yahoo.com", "@outlook.com"]
@st.cache_data
def load_and_train_simulation():
  word_counts_in_scams = {word: 0 for word in SCAM_KEYWORDS}
  total_records, scam_records, safe_records = 0, 0, 0
  try:
    with open(DATASET_FILE, mode="r", encoding="latin-1", errors="ignore") as file:
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
    return ( word_counts_in_scams, total_records, scam_records, safe_records, entropy,)
  except FileNotFoundError:
    return None

st.set_page_config(page_title="InternScan AI", page_icon="🛡️", layout="centered")
st.title("🛡️ InternScan: Job Scam Detection System")
st.write("Class 12 Corporate Security Simulation Project (Powered by NLP & Risk Analysis)")
st.markdown("---")
data_results = load_and_train_simulation()
if data_results is None:
  st.error(f"❌ Critical Error: '{DATASET_FILE}' not found in this folder! Website cannot start.")
else:
  trained_weights, total_rec, scam_rec, safe_rec, entropy_val = data_results
  st.sidebar.header("📊 Dataset Analytics Dashboard")
  st.sidebar.info(f"**Total Records Trained:** {total_rec}")
  st.sidebar.success(f"**Genuine Samples:** {safe_rec}")
  st.sidebar.error(f"**Scam Samples:** {scam_rec}")
  st.sidebar.warning(f"**Dataset Entropy:** {entropy_val:.4f}")
  st.subheader("🔍 Scan a New Job Posting / Email")
  text_input = st.text_area(
      "Paste the Job Description text here:",
      height=150,
      placeholder=( "Example: Urgent requirement! Earn 5000/day. Pay 500 registration fee..."),email_input = st.text_input("Recruiter's Email Address:", placeholder="hr@company.com")
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
      has_frequency_payout = any(p in text_lower for p in ["per day", "daily", "per hour", "p/d"])
      if has_unrealistic_amount or (
          any(n >= 5000 for n in numbers) and has_frequency_payout
      ):
        risk_score += 65
        triggered_features.append(
            "🚨 Unrealistic Payout Anomaly: Unreasonably high financial promise/daily payout detected."
        )

      # 2. Check for Structural Anomaly (Too Short / Incomplete)
      if word_count < 10:
        risk_score += 35
        triggered_features.append(
            f"⚠️ Structural Anomaly: Description is too short ({word_count} words). Lacks job role details."
        )

      # 3. Check for Offensive / Suspicious Terms
      for bad_word in PROFANITY_KEYWORDS:
        if bad_word in text_lower or bad_word in email_lower:
          risk_score += 50
          triggered_features.append(
              f"⛔ Content Violation: High-risk/abusive term detected ('{bad_word}')."
          )

      # 4. Check Scam Keywords
      for word in SCAM_KEYWORDS:
        if word in words:
          risk_score += 20
          triggered_features.append(
              f"🚩 High-Risk Keyword Flag: '{word}' identified in text."
          )

      # 5. Check Email Domain
      if any(domain in email_lower for domain in SUSPICIOUS_DOMAINS):
        risk_score += 20
        triggered_features.append(
            "📧 Sender Domain Alert: Public email domain (Gmail/Yahoo/Outlook) used instead of corporate server."
        )

      # Cap Risk Score at 100%
      risk_score = min(risk_score, 100)

      # Output Report
      st.markdown("---")
      st.subheader("🎯 Scan Evaluation Report")

      st.write(f"**Aggregated Risk Index: {risk_score}%**")
      st.progress(risk_score / 100)

      if risk_score >= 60:
        st.error(
            "🚨 Final Classification Verdict: [ HIGH RISK / FRAUD WARNING ]"
        )
      elif risk_score >= 30:
        st.warning(
            "⚠️ Final Classification Verdict: [ MODERATE RISK / CAUTION REQUIRED ]"
        )
      else:
        st.success(
            "✅ Final Classification Verdict: [ LOW RISK / SAFE LISTING ]"
        )

      # Prominent Risk Analysis Section (Directly Visible)
      st.markdown("### 📋 Risk Factor Analysis Breakdown")
      if triggered_features:
        for feature in triggered_features:
          st.error(feature) if risk_score >= 60 else st.warning(feature)
      else:
        st.success(
            "✅ No critical risk vectors detected in the textual structures."
        )
# =====================================================
# 🚀 CAREER GROWTH HUB
# =====================================================

st.markdown("---")
st.header("🚀 Career Growth Hub")
st.write("Improve your LinkedIn profile and discover skills, projects, and certifications to increase your internship opportunities.")

# ----------------------------
# Career Data
# ----------------------------

career_data = {
    "Artificial Intelligence": {
        "skills": [
            "python", "machine learning", "deep learning",
            "pandas", "numpy", "sql", "tensorflow",
            "data analysis", "git"
        ],
        "certificates": [
            "Google AI Essentials",
            "IBM AI Fundamentals",
            "Kaggle Python",
            "AWS Machine Learning Foundations"
        ],
        "projects": [
            "Job Scam Detection",
            "House Price Prediction",
            "Chatbot",
            "Face Mask Detection"
        ]
    },

    "Data Science": {
        "skills": [
            "python", "pandas", "numpy",
            "sql", "excel", "power bi",
            "statistics", "data visualization"
        ],
        "certificates": [
            "Google Data Analytics",
            "IBM Data Science Professional Certificate",
            "Kaggle Data Cleaning",
            "Microsoft Power BI"
        ],
        "projects": [
            "Sales Dashboard",
            "Customer Segmentation",
            "Movie Recommendation System",
            "Titanic Prediction"
        ]
    },

    "Web Development": {
        "skills": [
            "html", "css", "javascript",
            "react", "git", "node.js"
        ],
        "certificates": [
            "Meta Front-End Developer",
            "freeCodeCamp Responsive Web Design",
            "JavaScript Algorithms"
        ],
        "projects": [
            "Portfolio Website",
            "Weather App",
            "Online Quiz",
            "E-commerce Website"
        ]
    },

    "Cybersecurity": {
        "skills": [
            "network security", "linux",
            "python", "wireshark",
            "ethical hacking"
        ],
        "certificates": [
            "Google Cybersecurity",
            "Cisco Networking Academy",
            "TryHackMe Beginner Path"
        ],
        "projects": [
            "Password Strength Checker",
            "Network Scanner",
            "Phishing Detection",
            "Port Scanner"
        ]
    }
}

# ----------------------------
# User Input
# ----------------------------

career = st.selectbox(
    "Select Your Career Field",
    list(career_data.keys())
)

headline = st.text_input(
    "LinkedIn Headline",
    placeholder="Example: AI Student | Python Developer"
)

skills = st.text_area(
    "Enter Your Skills (comma separated)",
    placeholder="Python, SQL, Machine Learning"
)

# ----------------------------
# Analyze Button
# ----------------------------

if st.button("🚀 Analyze LinkedIn Profile"):

    user_skills = [
        skill.strip().lower()
        for skill in skills.split(",")
        if skill.strip()
    ]

    score = 0

    # Headline Score
    if len(headline) >= 15:
        score += 30

    # Skills Score
    matched_skills = []

    for skill in career_data[career]["skills"]:
        if skill.lower() in user_skills:
            matched_skills.append(skill)

    score += min(len(matched_skills) * 5, 50)

    # Bonus Score
    if len(user_skills) >= 5:
        score += 20

    score = min(score, 100)

    # Missing Skills
    missing_skills = []

    for skill in career_data[career]["skills"]:
        if skill.lower() not in user_skills:
            missing_skills.append(skill)

    # ----------------------------
    # Output
    # ----------------------------

    st.markdown("---")

    st.subheader("📊 LinkedIn Profile Score")

    st.progress(score / 100)

    st.metric("Profile Score", f"{score}/100")

    if score >= 80:
        st.success("Excellent LinkedIn Profile! You're internship-ready.")
    elif score >= 60:
        st.info("Good profile. A few improvements can make it stronger.")
    else:
        st.warning("Your profile needs improvement to attract recruiters.")

    # ----------------------------

    st.subheader("✅ Skills Found")

    if matched_skills:
        for skill in matched_skills:
            st.success(skill.title())
    else:
        st.warning("No relevant skills detected.")

    # ----------------------------

    st.subheader("⚠ Missing Skills")

    if missing_skills:
        for skill in missing_skills:
            st.error(skill.title())
    else:
        st.success("Amazing! No important skills missing.")

    # ----------------------------

    st.subheader("🎓 Recommended Certifications")

    for cert in career_data[career]["certificates"]:
        st.write("•", cert)

    # ----------------------------

    st.subheader("💻 Recommended Projects")

    for project in career_data[career]["projects"]:
        st.write("•", project)
