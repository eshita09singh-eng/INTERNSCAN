import csv
import math
import re
import streamlit as st

DATASET_FILE = "kaggle_scams.csv"

SCAM_INDICATORS = [
    "fee", "deposit", "urgent", "pay", "whatsapp", "telegram", 
    "registra", "rupee", "earn", "salary", "guarante", "part time",
    "no experience", "daily income", "invest", "gpay", "phonepe", 
    "upi", "data entry", "form fill", "crypto", "wfh", "work from home"
]

SUSPICIOUS_DOMAINS = ["@gmail.com", "@yahoo.com", "@outlook.com", "@hotmail.com"]

def is_gibberish(text):
    words = text.split()
    if not words:
        return True
    gibberish_count = 0
    for w in words:
        clean_w = re.sub(r'[^a-zA-Z]', '', w.lower())
        if len(clean_w) > 3 and not re.search(r'[aeiouy]', clean_w):
            gibberish_count += 1
    return (gibberish_count / len(words)) > 0.3 if len(words) > 0 else False


@st.cache_data
def load_and_train_simulation():
    word_counts_in_scams = {indicator: 0 for indicator in SCAM_INDICATORS}
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
                    for indicator in SCAM_INDICATORS:
                        if indicator in row[0].lower():
                            word_counts_in_scams[indicator] += 1
                else:
                    safe_records += 1
        p_scam = scam_records / total_records if total_records > 0 else 0
        p_safe = safe_records / total_records if total_records > 0 else 0
        entropy = (
            -(p_scam * math.log2(p_scam) + p_safe * math.log2(p_safe))
            if p_scam > 0 and p_safe > 0
            else 0
        )
        return word_counts_in_scams, total_records, scam_records, safe_records, entropy
    except FileNotFoundError:
        return None


st.set_page_config(page_title="InternScan AI", page_icon="🛡️", layout="centered")
st.title("🛡️ InternScan: Advanced Job Scam Detection System")
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
        placeholder="Example: Urgent hiring! Earn 5000/day working from home. Pay registration fee via WhatsApp...",
    )

    email_input = st.text_input("Recruiter's Email Address (Optional):", placeholder="hr@company.com")

    if st.button("🚀 Run AI Scan Risk Analysis"):
        if not text_input.strip():
            st.warning("⚠️ Please paste some text content to analyze.")
        else:
            text_lower = text_input.lower()
            email_lower = email_input.lower().strip()
            words = text_lower.split()
            word_count = len(words)
            
            risk_score = 0
            triggered_features = []

            if is_gibberish(text_input):
                risk_score += 40
                triggered_features.append(
                    "⚠️ Invalid / Unstructured Text Warning: Text contains meaningless gibberish or non-standard characters."
                )

            detected_flags = [ind for ind in SCAM_INDICATORS if ind in text_lower]
            if detected_flags:
                impact = min(len(detected_flags) * 15, 45)
                risk_score += impact
                triggered_features.append(
                    f"🚩 High-Risk Contextual Flags Found: Text contains suspicious term patterns ({', '.join(detected_flags[:3])})."
                )

            has_chat = any(app in text_lower for app in ["whatsapp", "telegram", "dm me", "contact on", "inbox"])
            has_payment = any(pay in text_lower for pay in ["fee", "deposit", "pay", "registra", "charge", "invest", "upi"])
            
            if has_chat and has_payment:
                risk_score += 40
                triggered_features.append(
                    "🚨 Critical Scam Pattern: Request for payment or registration combined with off-platform contact (WhatsApp/Telegram)."
                )

            numbers = [int(n) for n in re.findall(r"\b\d+\b", text_lower)]
            has_high_amount = any(num >= 10000 for num in numbers) or "k/day" in text_lower or "lakh" in text_lower
            has_daily_payout = any(p in text_lower for p in ["per day", "daily", "per hour", "p/d", "daily earn", "every day"])
            
            if has_high_amount or (any(n >= 3000 for n in numbers) and has_daily_payout):
                risk_score += 35
                triggered_features.append(
                    "💰 Unrealistic Financial Promise: High daily payout or unreasonable salary rates detected."
                )

            if email_lower:
                if any(domain in email_lower for domain in SUSPICIOUS_DOMAINS):
                    risk_score += 25
                    triggered_features.append(
                        f"📧 Public Domain Alert: Recruiter email '{email_lower}' uses a free public provider instead of a verified company domain."
                    )
            elif "gmail.com" in text_lower or "yahoo.com" in text_lower:
                risk_score += 15
                triggered_features.append("📧 Contact email in description uses a free public domain.")

            if word_count < 12 and not is_gibberish(text_input):
                risk_score += 25
                triggered_features.append(
                    f"⚠️ Incomplete Job Listing: Description is too brief ({word_count} words). Authentic roles provide detailed responsibilities."
                )

            risk_score = min(risk_score, 100)

            st.markdown("---")
            st.subheader("🎯 Scan Evaluation Report")

            st.write(f"**Aggregated Risk Index: {risk_score}%**")
            st.progress(risk_score / 100)

            if risk_score >= 50:
                st.error("🚨 Final Classification Verdict: [ HIGH RISK / LIKELY FRAUD ]")
            elif risk_score >= 25:
                st.warning("⚠️ Final Classification Verdict: [ MODERATE RISK / CAUTION REQUIRED ]")
            else:
                st.success("✅ Final Classification Verdict: [ LOW RISK / SAFE LISTING ]")

            st.markdown("### 📋 Risk Factor Analysis Breakdown")
            if triggered_features:
                for feature in triggered_features:
                    if risk_score >= 50:
                        st.error(feature)
                    else:
                        st.warning(feature)
            else:
                st.success("✅ No suspicious risk vectors detected in the textual structures.")

st.markdown("---")
st.header("🚀 Career Growth Hub")
st.write("Improve your LinkedIn profile and discover skills, projects, and certifications to increase your internship opportunities.")

career_data = {
    "Artificial Intelligence": {
        "skills": ["python", "machine learning", "deep learning", "pandas", "numpy", "sql", "tensorflow", "data analysis", "git"],
        "certificates": ["Google AI Essentials", "IBM AI Fundamentals", "Kaggle Python", "AWS Machine Learning Foundations"],
        "projects": ["Job Scam Detection", "House Price Prediction", "Chatbot", "Face Mask Detection"],
    },
    "Data Science": {
        "skills": ["python", "pandas", "numpy", "sql", "excel", "power bi", "statistics", "data visualization"],
        "certificates": ["Google Data Analytics", "IBM Data Science Professional Certificate", "Kaggle Data Cleaning", "Microsoft Power BI"],
        "projects": ["Sales Dashboard", "Customer Segmentation", "Movie Recommendation System", "Titanic Prediction"],
    },
    "Web Development": {
        "skills": ["html", "css", "javascript", "react", "git", "node.js"],
        "certificates": ["Meta Front-End Developer", "freeCodeCamp Responsive Web Design", "JavaScript Algorithms"],
        "projects": ["Portfolio Website", "Weather App", "Online Quiz", "E-commerce Website"],
    },
    "Cybersecurity": {
        "skills": ["network security", "linux", "python", "wireshark", "ethical hacking"],
        "certificates": ["Google Cybersecurity", "Cisco Networking Academy", "TryHackMe Beginner Path"],
        "projects": ["Password Strength Checker", "Network Scanner", "Phishing Detection", "Port Scanner"],
    },
}

career = st.selectbox("Select Your Career Field", list(career_data.keys()))

headline = st.text_input("LinkedIn Headline", placeholder="Example: AI Student | Python Developer")

skills = st.text_area("Enter Your Skills (comma separated)", placeholder="Python, SQL, Machine Learning")

if st.button("🚀 Analyze LinkedIn Profile"):
    user_skills = [skill.strip().lower() for skill in skills.split(",") if skill.strip()]

    score = 0
    if len(headline) >= 15:
        score += 30

    matched_skills = [skill for skill in career_data[career]["skills"] if skill.lower() in user_skills]
    score += min(len(matched_skills) * 5, 50)

    if len(user_skills) >= 5:
        score += 20

    score = min(score, 100)
    missing_skills = [skill for skill in career_data[career]["skills"] if skill.lower() not in user_skills]

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

    st.subheader("✅ Skills Found")
    if matched_skills:
        for skill in matched_skills:
            st.success(skill.title())
    else:
        st.warning("No relevant skills detected.")

    st.subheader("⚠ Missing Skills")
    if missing_skills:
        for skill in missing_skills:
            st.error(skill.title())
    else:
        st.success("Amazing! No important skills missing.")

    st.subheader("🎓 Recommended Certifications")
    for cert in career_data[career]["certificates"]:
        st.write("•", cert)

    st.subheader("💻 Recommended Projects")
    for project in career_data[career]["projects"]:
        st.write("•", project)
