from unittest import result
import streamlit as st
import pymysql
import pandas as pd
from malicious_news import crawl_malicious_news
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import seaborn as sns
from sklearn.preprocessing import MinMaxScaler
import parsing_html
from parsing_html import getHtml, to_csv, get_csv
import predict_module
from predict_module import predict_from_csv
from sqlalchemy import create_engine


# 한글폰트 path 설정
font_path = 'C:\\windows\\Fonts\\malgun.ttf'
font_prop = fm.FontProperties(fname=font_path).get_name()
matplotlib.rc('font', family=font_prop)

#DB에 검사한 url의 이름과 feature, result를 저장
def save_data(user_url,result):
     # MariaDB 연결 엔진 생성
    engine = create_engine('mysql+pymysql://python:python@localhost:3306/python_db')
    
    # pymysql을 사용하여 DB 연결
    connection = None
    try:
        connection = pymysql.connect(
            host='localhost',
            port=3306,
            db='python_db',
            user='python',
            passwd='python',
            charset='utf8'
        )
        
        with connection.cursor() as cursor:
            # 1. URL이 이미 존재하는지 조회
            sql_check = 'SELECT url FROM feature_and_result WHERE url=%s'
            cursor.execute(sql_check, (user_url,))
            
            # 조회 결과가 있으면 (이미 데이터가 존재하면)
            if cursor.fetchone():
                print(f"'{user_url}'은(는) 이미 DB에 존재합니다. 새로운 데이터를 저장하지 않습니다.")
                return # 함수 종료
            
        # 2. URL이 존재하지 않으면 데이터프레임 생성 및 저장
        df = pd.read_csv('extract_feature.csv')
        df['url'] = user_url
        df['result'] = result

        # 3. to_sql() 메서드를 사용하여 DB에 저장
        df.to_sql(name='feature_and_result', con=engine, if_exists='append', index=False)
        print("데이터프레임이 DB에 성공적으로 저장되었습니다.")
        
    except Exception as e:
        print(f"데이터베이스 작업 중 오류 발생: {e}")
        if connection:
            connection.rollback()
    finally:
        if connection:
            connection.close()

# DB에서 특정 URL의 악성 여부 조회 함수
def get_url_result(url):
    try:
        conn = pymysql.connect(
            host='localhost',
            user='python',
            password='python',
            db='python_db',
            charset='utf8mb4'
        )
        with conn.cursor() as cursor:
            cursor.execute("SELECT result FROM feature_and_result WHERE url = %s", (url,))
            row = cursor.fetchone()
            return row[0] if row else None
    except Exception as e:
        st.error(f"❌ DB 조회 오류: {e}")
        return None
    finally:
        conn.close()

# DB 전체 기록 로드 함수, 여기서 url, url_len, url_entropy, result이 출력됩니다.
def load_from_DB():
    try:
        conn = pymysql.connect(
            host='localhost',
            user='python',
            password='python',
            db='python_db',
            charset='utf8mb4'
        )
        query = "SELECT url, url_len, url_entropy, result FROM feature_and_result"
        df = pd.read_sql(query, conn)
        return df
    except Exception as e:
        st.error(f"❌ 전체 데이터 로딩 오류: {e}")
        return pd.DataFrame()
    finally:
        conn.close()

def visualize_tag_pie_and_entropy(df):
    try:
        df_temp = df.copy()
        df_temp.columns = df_temp.columns.str.replace("html_num_tags\\('", "", regex=True).str.replace("'\\)", "", regex=True)

        # 1. URL 엔트로피 KDE 플롯
        plt.figure(figsize=(8, 5))
        sns.kdeplot(data=df[df['repu'] == 'benign']['url_entropy'], label='Benign', shade=True)
        sns.kdeplot(data=df[df['repu'] == 'malicious']['url_entropy'], label='Malicious', shade=True, color='red')
        plt.title("URL 엔트로피 값에 따른 정상/악성 사이트 분포 비교", fontsize=16)
        plt.xlabel("URL Entropy")
        plt.ylabel("Density")
        plt.legend()
        st.pyplot(plt.gcf())  # 현재 figure를 Streamlit에 출력
        plt.clf()  # plt 초기화

        # 2. 태그 비율 파이 차트
        tags_to_compare = ['script', 'iframe', 'div', 'a', 'img']
        malicious_df_tags = df_temp[df_temp['repu'] == 'malicious']
        benign_df_tags = df_temp[df_temp['repu'] == 'benign']

        malicious_tag_counts = malicious_df_tags[tags_to_compare].sum()
        benign_tag_counts = benign_df_tags[tags_to_compare].sum()

        malicious_others_count = malicious_df_tags.drop(columns=['repu']).sum().sum() - malicious_tag_counts.sum()
        benign_others_count = benign_df_tags.drop(columns=['repu']).sum().sum() - benign_tag_counts.sum()

        malicious_final_counts = malicious_tag_counts.to_dict()
        malicious_final_counts['Others'] = malicious_others_count

        benign_final_counts = benign_tag_counts.to_dict()
        benign_final_counts['Others'] = benign_others_count

        fig, axes = plt.subplots(1, 2, figsize=(18, 9))
        colors = sns.color_palette('Set3', n_colors=len(malicious_final_counts))

        axes[0].pie(malicious_final_counts.values(), labels=malicious_final_counts.keys(),
                    autopct='%1.1f%%', startangle=90, colors=colors, textprops={'fontsize': 12})
        axes[0].set_title('악성 웹사이트의 태그 비율', fontsize=16)
        axes[0].axis('equal')

        axes[1].pie(benign_final_counts.values(), labels=benign_final_counts.keys(),
                    autopct='%1.1f%%', startangle=90, colors=colors, textprops={'fontsize': 12})
        axes[1].set_title('정상 웹사이트의 태그 비율', fontsize=16)
        axes[1].axis('equal')

        plt.tight_layout()
        st.pyplot(fig)
        plt.clf()

    except Exception as e:
        st.error(f"시각화 중 오류가 발생했습니다: {e}")


def draw_radar_chart(train_csv_path, user_csv_path, features):
    try:
        # === 1. TrainData에서 benign 평균 구하기 ===
        df_train = pd.read_csv(train_csv_path)
        df_train.columns = df_train.columns.str.replace(r"html_num_tags\('", "", regex=True).str.replace(r"'\)", "", regex=True)
        df_train = df_train.dropna(subset=features + ['repu'])

        scaler = MinMaxScaler()
        df_train_scaled_values = scaler.fit_transform(df_train[features])
        df_train_scaled = pd.DataFrame(df_train_scaled_values, columns=features)
        df_train_scaled['repu'] = df_train['repu'].values

        mean_benign = df_train_scaled[df_train_scaled['repu'] == 'benign'][features].mean().values

        # === 2. 사용자 URL Feature 가져오기 ===
        df_user = pd.read_csv(user_csv_path)
        df_user.columns = df_user.columns.str.replace(r"html_num_tags\('", "", regex=True).str.replace(r"'\)", "", regex=True)

        user_values_raw = df_user[features].iloc[0].values.reshape(1, -1)
        user_values = scaler.transform(user_values_raw).flatten()

        # === 3. 레이더 차트 준비 ===
        labels = features
        num_vars = len(labels)
        angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
        angles += angles[:1]

        user_values = np.concatenate((user_values, [user_values[0]]))
        mean_benign = np.concatenate((mean_benign, [mean_benign[0]]))

        fig, ax = plt.subplots(figsize=(6, 6), subplot_kw=dict(polar=True))
        ax.plot(angles, user_values, label='사용자 URL', color='red')
        ax.plot(angles, mean_benign, label='정상 평균 (benign)', color='blue')
        ax.fill(angles, user_values, color='red', alpha=0.25)
        ax.fill(angles, mean_benign, color='blue', alpha=0.15)
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(labels)
        ax.set_title('입력 URL vs 정상 평균 Feature 비교', size=15)
        ax.legend(loc='upper right')
        st.pyplot(fig)
    except Exception as e:
        st.error(f"차트 생성 중 오류 발생: {e}")

def compare_benign_malicious_chart(train_csv_path, features):
    try:
        # === 1. TrainData에서 benign 평균 구하기 ===
        df_train = pd.read_csv(train_csv_path)
        df_train.columns = df_train.columns.str.replace(r"html_num_tags\('", "", regex=True).str.replace(r"'\)", "", regex=True)
        df_train = df_train.dropna(subset=features + ['repu'])

        scaler = MinMaxScaler()
        df_train_scaled_values = scaler.fit_transform(df_train[features])
        df_train_scaled = pd.DataFrame(df_train_scaled_values, columns=features)
        df_train_scaled['repu'] = df_train['repu'].values

        mean_benign = df_train_scaled[df_train_scaled['repu'] == 'benign'][features].mean().values
        mean_malicious = df_train_scaled[df_train_scaled['repu'] == 'malicious'][features].mean().values
        print(f'mean_benign: {df_train_scaled[df_train_scaled['repu'] == 'benign'][features]}')
        print(f'mean_malicious: {df_train_scaled[df_train_scaled['repu'] == 'malicious'][features]}')

        # === 3. 레이더 차트 준비 ===
        labels = features
        num_vars = len(labels)
        angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
        angles += angles[:1]

        mean_malicious = np.concatenate((mean_malicious, [mean_malicious[0]]))
        mean_benign = np.concatenate((mean_benign, [mean_benign[0]]))

        fig, ax = plt.subplots(figsize=(6, 6), subplot_kw=dict(polar=True))
        ax.plot(angles, mean_malicious, label='악성 평균 (malicious)', color='red')
        ax.plot(angles, mean_benign, label='정상 평균 (benign)', color='blue')
        ax.fill(angles, mean_malicious, color='red', alpha=0.25)
        ax.fill(angles, mean_benign, color='blue', alpha=0.15)
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(labels)
        ax.set_title('악성 평균 vs 정상 평균 Feature 비교', size=15)
        ax.legend(loc='upper right')
        st.pyplot(fig)
    except Exception as e:
        st.error(f"차트 생성 중 오류 발생: {e}")

# 메인 실행 함수
def main():

    
    st.set_page_config(page_title="온라인 보안 뉴스", layout="wide")
    st.sidebar.title("지키링 네비게이션")
    page = st.sidebar.selectbox("페이지를 선택하세요", ["메인", "온라인 보안 뉴스"])

    # 파일 경로
    train_csv = "BE/TrainDataAll.csv"
    user_csv = "extract_feature.csv"

    dftd = pd.read_csv("BE/TrainDataAll.csv")

    # Feature 목록
    features = [                        
                    "url_entropy",
                    "url_path_len", "url_filename_len", "url_longest_dom_token_len",
                    "url_average_dom_token_len", "url_domain_len", "url_hostname_len", 
                    "url_port",
                    "script","div"
                ]
    if page == "메인":
        st.title("지키링")
        st.write("원하는 기능을 네비게이션에서 선택하세요.")

        # 가운데 입력창
        left, center, right = st.columns([2, 4, 2])
        with center:
            user_url = st.text_input("🔎 악성 여부를 확인할 URL을 입력하세요", "")
            if user_url:

                parsing_html.get_csv(user_url)
                result, prob = predict_module.predict_from_csv(csv_path='extract_feature.csv')

                if result is None:
                    st.warning("🤔 이 URL은 아직 분석되지 않았습니다.")
                    print("예측 결과:", result)
                elif result == 1:
                    st.success(f"✅ {user_url} 사이트는 **정상 사이트입니다.**\n확률: {prob:.2f}%")
                    
                elif result == -1:
                    st.error(f"🚨 {user_url} 사이트는 **악성 사이트입니다.**\n확률: {prob:.2f}%")
                else:
                    st.info(f"⚠️ 분류되지 않은 결과값: {result}")

                try:
                    st.markdown("### 🧠 해당 URL 분석 시각화")
                    df = pd.read_csv('extract_feature.csv')

                    # 사용자가 입력한 url과 csv 파일의 'url'컬럼 값과 일치하는 행만 필터링, 
                    # csv 파일의 컬럼 명에 맞게 수정
                    df['url'] = user_url
                    matched_row = df 
                    print(df)
                    save_data(user_url,result) 

                    if not matched_row.empty:
                        # HTML 태그 관련 시각화
                        html_columns = [col for col in df.columns if "html_num_tags" in col]
                        tag_counts = matched_row.iloc[0][html_columns]
                        tag_counts = tag_counts[tag_counts > 0]

                        if not tag_counts.empty:
                            fig1, ax1 = plt.subplots(figsize=(8, 8))
                            ax1.pie(tag_counts, labels=tag_counts.index.str.extract(r"\'(\w+)\'")[0], autopct='%1.1f%%')
                            ax1.set_title("HTML 태그 비율")
                            st.pyplot(fig1)
                        else:
                            st.info("해당 URL의 HTML 태그 정보가 부족합니다.")

                        # URL 관련 컬럼 시각화
                        url_columns = [
                            'url_len', 'url_path_len', 'url_filename_len',
                            'url_domain_len', 'url_hostname_len', 'url_entropy',
                            'url_num_dots', 'url_num_slashes', 'url_num_equals'
                        ]

                        row_data = matched_row.iloc[0][url_columns].reset_index()
                        row_data.columns = ['Feature', 'Value']

                        fig2, ax2 = plt.subplots(figsize=(10, 6))
                        sns.barplot(data=row_data, x='Feature', y='Value', palette='Set2', ax=ax2)
                        ax2.set_xticklabels(ax2.get_xticklabels(), rotation=45)
                        ax2.set_title("URL 관련 값 비교")
                        plt.tight_layout()
                        st.pyplot(fig2)

                        draw_radar_chart(train_csv, user_csv, features)
                        compare_benign_malicious_chart(train_csv, features)

                    else:
                        st.info("⚠️ 입력한 URL에 대한 상세 데이터가 CSV 파일에 없습니다.")

                except Exception as e:
                    st.warning(f"⚠️ 시각화 중 오류 발생: {e}")

        with center:
            # 판별 이력 테이블
            st.subheader("📊 URL 판별 이력")
            df_history = load_from_DB()
            if not df_history.empty:
                df_history['result'] = df_history['result'].map({1: '정상', -1: '악성'}).fillna('미분류')
                st.dataframe(df_history)
            else:
                st.info("아직 저장된 URL 정보가 없습니다.")
                
            st.subheader("📊 악성 vs 정상 사이트 분석 대시보드")
            visualize_tag_pie_and_entropy(dftd)
                

    elif page == "온라인 보안 뉴스":
        st.title("온라인 보안 관련 최신 뉴스")
        st.write("실시간으로 온라인 보안 관련 뉴스를 크롤링하여 제공합니다.")

        search_query = st.text_input("뉴스 제목 검색", "")
        with st.spinner('뉴스를 불러오는 중입니다...'):
            news = crawl_malicious_news()

        if news:
            filtered_news = [n for n in news if search_query.strip() == "" or search_query.lower() in n['title'].lower()]
            if not filtered_news:
                st.info("검색어를 포함하는 뉴스가 없습니다.")
            for n in filtered_news:
                with st.container():
                    cols = st.columns([1, 4])
                    with cols[0]:
                        if n['img']:
                            st.image(n['img'], width=80)
                    with cols[1]:
                        st.markdown(f"**{n['title']}**")
                        with st.expander("본문 보기"):
                            import requests
                            from bs4 import BeautifulSoup
                            try:
                                detail = requests.get(n['link'])
                                detail_soup = BeautifulSoup(detail.text, 'html.parser')
                                content = detail_soup.select_one('.con #con')
                                if content:
                                    html = str(content)
                                    st.markdown(f"<div style='margin-bottom:10px; line-height:1.7; font-size:10px !important;'>{html}</div>", unsafe_allow_html=True)
                                else:
                                    og_desc = detail_soup.find('meta', attrs={'property': 'og:description'})
                                    if og_desc and og_desc.get('content'):
                                        st.markdown(f"<div style='margin-bottom:10px; line-height:1.7; font-size:10px !important;'>{og_desc['content']}</div>", unsafe_allow_html=True)
                                    else:
                                        st.write('본문을 불러올 수 없습니다.')
                            except Exception:
                                st.write('본문을 불러올 수 없습니다.')
        else:
            st.info("뉴스를 불러오지 못했습니다.")

if __name__ == "__main__":
    main()
