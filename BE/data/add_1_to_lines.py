url 붙이기
import pandas as pd

# 파일 경로 (필요에 따라 수정)
TOP1M_PATH = "data/top-1m.csv"
BENIGN_PATH = "benign_html.csv"
OUTPUT_PATH = "benign_html.csv"  # 덮어쓰려면 같은 이름으로 바꿔도 됨

# top-1m.csv는 헤더가 없고 "rank,url" 구조라 가정
top1m = pd.read_csv(TOP1M_PATH, header=None, names=["rank", "url"], dtype=str)

# benign_html.csv는 헤더가 있는 CSV
benign = pd.read_csv(BENIGN_PATH, dtype=str)

# 필요한 길이 맞추기: benign 행 수만큼 top1m의 url을 가져오되, 부족하면 NaN 채움
url_series = top1m["url"].reindex(range(len(benign))).reset_index(drop=True)

# 새 DataFrame: url을 맨 앞에 붙이고 기존 benign 컬럼들을 뒤로 이동
result = pd.concat([url_series.rename("url"), benign.reset_index(drop=True)], axis=1).head(1000)

# 결과 저장
result.to_csv(OUTPUT_PATH, index=False)
print(f"저장 완료: {OUTPUT_PATH} (행: {len(result)})")
