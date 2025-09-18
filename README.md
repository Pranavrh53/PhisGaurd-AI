# PhisGaurd-AI: Phishing URL Detection using Machine Learning

**PhisGaurd-AI** is an intelligent phishing detection system that leverages machine learning to identify phishing URLs in real time. This project aims to help users identify malicious URLs that may be part of phishing attacks, preventing them from being tricked into visiting malicious websites or sharing sensitive information.

---

## Features
```
- **Phishing URL Detection**: The system identifies and classifies URLs based on various features that are typical of phishing attempts.
- **ML-Based Classification**: Trained using machine learning algorithms to classify URLs as **Phishing** or **Legitimate**.
- **Extensible Framework**: Designed to allow future improvements such as email body and attachment phishing detection, real-time alerts, explainability, and more.
```
---

## Project Overview

PhisGaurd-AI uses machine learning algorithms to detect **phishing URLs** by analyzing the structural and semantic properties of URLs. The project trains a model on features extracted from a dataset of **phishing URLs** and **legitimate URLs**. The resulting model can classify new URLs as either phishing or legitimate.

---

## Future Enhancements (Planned)

While the current version of PhisGaurd-AI focuses on phishing **URL detection**, the following features are planned for future updates:

- **Full Email Detection**: Expansion of the system to analyze phishing **email content** along with **URLs**.
- **Phishing Attachment Detection**: Adding the ability to analyze email attachments and flag potential phishing content.
- **Real-Time Detection and Alerts**: Implementing a live phishing detection system that can provide **real-time notifications** when phishing URLs are detected.
- **Explainable AI (XAI)**: Adding interpretable explanations for why a particular URL is classified as phishing, using tools like **LIME** or **SHAP**.
- **Web Dashboard**: Building a dashboard to visualize phishing detection trends, statistics, and more in real time.
- **Email Integration**: Allowing integration with popular email services (e.g., Gmail, Outlook) to scan incoming emails for phishing attempts.

---

## Installation

To install and run PhisGaurd-AI locally, follow these steps:

### 1. Clone the repository:

```bash
git clone https://github.com/Pranavrh53/PhisGaurd-AI.git
cd PhisGaurd-AI
