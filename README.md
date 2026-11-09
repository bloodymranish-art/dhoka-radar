# Dhokha Radar 📡
Paste a suspicious SMS / WhatsApp / UPI message. Get a **scam score**, the **exact red flags**, and a Hinglish explanation of what to do.

Built for the BharatCode Build League. Inspired by my UPI fraud-detection project (Sentinel).

## How it works
1. **Rule engine** (`app/rules.py`): offline and explainable. It catches OTP/PIN requests, "enter PIN to *receive* money", fake KYC and bill threats, digital-arrest scripts, task/job scams, APK and remote-app pushes, and lookalike or shortened links.
2. **BharatCode model** (`app/llm.py`): turns the report into plain Hinglish advice. If the API is down or no key is set, it falls back to templates, so the verdict never depends on an LLM.
3. **Token-bucket rate limiter** (`app/ratelimit.py`): per-IP, keeps the public demo from being abused.

## Run
```bash
pip install -r requirements.txt
export BHARATCODE_API_KEY=...        # optional
export BHARATCODE_BASE_URL=...       # OpenAI-style base URL, optional
export BHARATCODE_MODEL=...          # optional
uvicorn app.main:app --reload
pytest
```

## Known rough edges (hackathon build)
- Regex rules are English/Hinglish only
- In-memory rate limiter (swap for Redis to scale)
- Assumes an OpenAI-style chat endpoint; adjust `llm.py` if BharatCode's differs

If you got scammed: call **1930** or go to cybercrime.gov.in.
