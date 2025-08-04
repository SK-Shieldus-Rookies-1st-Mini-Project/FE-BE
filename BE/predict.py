# predict.py
import sys, joblib
import pandas as pd

model = joblib.load("models/url_model.joblib")
urls = sys.argv[1:] or [
    "https://www.google.com/",
    "http://192.0.2.10/verify-account-free-gift",
]
proba = model.predict_proba(urls)[:,1]

# 간단 위험도(0~100)로 매핑
scores = (proba * 100).round(1)

for u, p, s in zip(urls, proba, scores):
    print(f"{u}\n  prob_malicious={p:.4f}  risk_score={s}")
