from app.rules import analyze
from app.ratelimit import TokenBucket

def test_kyc_scam():
    r = analyze("Dear user your SBI account will be blocked today! Update KYC urgently: http://sbi-kyc-update.xyz/login")
    assert r["verdict"] == "DHOKHA"

def test_pin_to_receive():
    assert analyze("Refund aayega, UPI PIN dalo to receive money")["verdict"] == "DHOKHA"

def test_digital_arrest():
    assert analyze("This is CBI. Your parcel has drugs. You are under digital arrest, stay on video call")["score"] >= 40

def test_safe():
    assert analyze("Hey, dinner at 8? I'll pay you back via UPI tomorrow")["verdict"] == "LAGTA SAFE"

def test_real_domain_not_flagged():
    r = analyze("Your statement is ready at https://www.hdfcbank.com/statement")
    assert r["verdict"] == "LAGTA SAFE"

def test_bucket():
    b = TokenBucket(rate_per_min=1, burst=2)
    assert b.allow("a") and b.allow("a") and not b.allow("a")
