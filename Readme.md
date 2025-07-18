
# CipherStorm: AI-Powered Fraud Detection Platform
<img width="1897" height="865" alt="image" src="https://github.com/user-attachments/assets/13f0eedf-a6dd-4b9c-8b07-48405eaf6400" />


## How It Works

CipherStorm uses multiple AI models to detect and prevent digital fraud in real time. The platform covers:
- URL phishing
- SMS scam/spam
- Vishing (voice phishing)
- Fake customer care numbers
- Transaction fraud

## Quick Start Instructions

1. **Extract the project zip**
2. **Create and activate a virtual environment**
   ```bash
   python -m venv myenv
   myenv\Scripts\activate  # (Windows)
   # or
   source myenv/bin/activate  # (Linux/Mac)
   ```
3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```
4. **Use the provided `.env` file** (already contains all API keys and configs)
5. **Start the server**
   ```bash
   uvicorn app.main:app --reload
   ```

## Using the Platform

1. **Sign up and log in**
   - ![Signup Screenshot](#)
   - ![Login Screenshot](#)
2. **Complete your profile**
   - ![Profile Screenshot](#)
3. **Access the dashboard**
   - ![Dashboard Screenshot](#)
4. **Use any service from the dashboard**
   - URL Phishing Detection
   - SMS Scam Detection
   - Vishing Detection
   - Fake Customer Care Check
   - Transaction Fraud Analysis
   - ![Services Page Screenshot](#)
5. **Get instant results and recommendations**

## Notes

- Use the test account for best results:
  - Username: `ankitkr9911` | Password: `1234`
  - (Has sample transactions for realistic testing)
- Or create a new account and add transactions using the provided SQL script.

## API Docs

See [API_DOCUMENTATION.md](API_DOCUMENTATION.md) for full API details.

## Support

For help, email support@cipherstorm.com or open an issue.
