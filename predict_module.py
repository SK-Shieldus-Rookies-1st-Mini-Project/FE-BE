import pandas as pd
import joblib

def predict_from_csv(csv_path):
    # 모델 및 피처 목록 불러오기
    ml_model = joblib.load('BE/best_ml_model_v3.pkl')
    model_features = joblib.load('BE/feature_columns_v2.pkl')
    model_features = [col for col in model_features if col != 'repu']

    # CSV 불러오기
    df = pd.read_csv(csv_path)

    # # 라벨 컬럼 제거
    # for label_col in ['Unnamed: 0','Result_v1', 'repu',"html_num_tags('applet')"]:
    #     if label_col in df.columns:
    #         df = df.drop(columns=[label_col])

    # # # 누락된 컬럼 0으로 추가
    # for col in model_features:
    #     if col not in df.columns:
    #         df[col] = 0

    # # 불필요한 컬럼 제거
    # extra_cols = [col for col in df.columns if col not in model_features]
    # df = df.drop(columns=extra_cols, axis=1)

    # # 샘플 선택 (여기서는 첫 번째 행 사용)
    # simul = df.iloc[[0]]

    # df = df[model_features]

    # 예측 수행
    res = ml_model.predict(df)
    proba = ml_model.predict_proba(df)

    pred_class = res[0]
    pred_prob = proba[0][ml_model.classes_.tolist().index(pred_class)]

    print(f"예측 결과: {pred_class} (확률: {pred_prob*100:.2f}%)")
    # 결과 반환
    return pred_class, pred_prob*100