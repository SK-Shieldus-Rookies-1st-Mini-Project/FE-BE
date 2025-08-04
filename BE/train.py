# train.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import roc_auc_score, classification_report
from sklearn.utils.class_weight import compute_class_weight
import numpy as np, joblib, os

# 1) 데이터 로드
df = pd.read_csv("data/한국인터넷진흥원_피싱사이트_20241231_수정본_with_top1m.csv")
X, y = df["url"].astype(str), df["label"].astype(int)

# 2) (아주 단순하게) 홀드아웃 분할
X_tr, X_te, y_tr, y_te = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# 3) 파이프라인: 문자 n-gram TF‑IDF + 로지스틱 회귀
pipe = Pipeline([
    ("tfidf", TfidfVectorizer(
        analyzer="char", ngram_range=(3,5), min_df=2  # 문자 3~5그램이 URL에 잘 맞음
    )),
    ("clf", LogisticRegression(
        max_iter=2000,
        class_weight="balanced",         # 불균형 완화
        n_jobs=-1 if hasattr(LogisticRegression, "n_jobs") else None
    ))
])

pipe.fit(X_tr, y_tr)

# 4) 평가
proba = pipe.predict_proba(X_te)[:, 1]
pred  = (proba >= 0.5).astype(int)

print("ROC-AUC:", roc_auc_score(y_te, proba))
print(classification_report(y_te, pred, digits=4))

# 5) 모델 저장
os.makedirs("models", exist_ok=True)
joblib.dump(pipe, "models/url_model.joblib")
print("Saved -> models/url_model.joblib")
