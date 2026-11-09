"""BharatCode model call. Assumes an OpenAI-style /chat/completions endpoint.
Set BHARATCODE_API_KEY, BHARATCODE_BASE_URL, BHARATCODE_MODEL (see README)."""
import os, json, httpx

SYSTEM = (
    "You are Dhokha Radar, a blunt, friendly Indian cyber-safety friend. "
    "You get a suspicious message plus a rule-engine report. Reply in simple Hinglish "
    "(Roman script), max 90 words, as JSON only: "
    '{"explain": "why this is/isn\'t a scam, 2-3 lines", "do_now": ["3 short action steps"], '
    '"reply_to_scammer": "one savage-but-safe line the user could send, or empty"}. '
    "If score is low, don't scare the user. Mention 1930 / cybercrime.gov.in only if verdict is DHOKHA."
)

def fallback(report):
    v = report["verdict"]
    if v == "LAGTA SAFE":
        return {"explain": "Koi bada red flag nahi mila. Phir bhi link ya PIN kisi ko mat do.",
                "do_now": ["Sender ko apne official app se verify karo"], "reply_to_scammer": ""}
    return {"explain": "Is message me scam wale patterns hain: " + "; ".join(s["why"] for s in report["signals"][:2]),
            "do_now": ["Link pe click mat karo", "OTP/PIN kabhi share mat karo", "Bank ke official number pe call karo; fraud ho gaya to 1930 dial karo"],
            "reply_to_scammer": "Bhai, ye script purani ho gayi. Cyber cell ko forward kar diya."}

async def explain(text, report):
    key = os.getenv("BHARATCODE_API_KEY")
    base = os.getenv("BHARATCODE_BASE_URL")
    if not key or not base:
        return fallback(report) | {"source": "offline-rules"}
    payload = {
        "model": os.getenv("BHARATCODE_MODEL", "default"),
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": json.dumps({"message": text[:1500], "report": report}, ensure_ascii=False)},
        ],
        "temperature": 0.4,
    }
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post(base.rstrip("/") + "/chat/completions", json=payload,
                             headers={"Authorization": f"Bearer {key}"})
            r.raise_for_status()
            raw = r.json()["choices"][0]["message"]["content"].strip().strip("`")
            raw = raw[4:] if raw.startswith("json") else raw
            return json.loads(raw) | {"source": "bharatcode"}
    except Exception:
        return fallback(report) | {"source": "offline-rules"}
