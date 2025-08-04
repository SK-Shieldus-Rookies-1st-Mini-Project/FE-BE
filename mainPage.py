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
import login
import re
from urllib.parse import urlparse
#st.set_page_config(page_title="악성 URL 판별 시스템", layout="wide")

def login_page():
    st.title("🔐 지키링 ")
    tab1, tab2 = st.tabs(["🔓 로그인", "📝 회원가입"])

    with tab1:
        st.subheader("로그인")
        # ✅ 가운데 정렬을 위해 columns 사용
        left, center, right = st.columns([2, 3, 2])
        with center:
            username = st.text_input("아이디", key="login_id")
            password = st.text_input("비밀번호", type="password", key="login_pw")
            login_clicked = st.button("로그인")
            if login_clicked:
                success, msg = login.login(username, password)
                if success:
                    st.session_state.logged_in = True
                    st.session_state.user_name = msg.split("님")[0]
                    st.session_state.page = "main"
                    st.rerun()
                else:
                    st.error(msg)

    with tab2:
        st.subheader("회원가입")
        left, center, right = st.columns([2, 3, 2])
        with center:
            name = st.text_input("이름", key="signup_name")
            new_username = st.text_input("아이디", key="signup_id")
            new_password = st.text_input("비밀번호", type="password", key="signup_pw")
            if st.button("회원가입"):
                success, msg = login.signup(name, new_username, new_password)
                if success:
                    st.success(msg)
                else:
                    st.error(msg)


# 한글폰트 path 설정
font_path = 'C:\\windows\\Fonts\\malgun.ttf'
font_prop = fm.FontProperties(fname=font_path).get_name()
matplotlib.rc('font', family=font_prop)

def create_table_if_not_exists():
    try:
        conn = pymysql.connect(
            host='localhost',
            port=3306,
            user='python',
            password='python',
            db='python_db',
            charset='utf8mb4'
        )
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS feature_and_result (
                    username VARCHAR(100),
                    url_len INT, url_num_hyphens_dom INT, url_num_dom_token INT,
                    url_path_len INT, url_filename_len INT, url_longest_dom_token_len INT,
                    url_average_dom_token_len FLOAT, url_domain_len INT, url_hostname_len INT,
                    url_num_dots INT, url_num_underscores INT, url_num_equals INT,
                    url_num_slashes INT, url_num_dash INT, url_num_semicolon INT,
                    url_num_at INT, url_num_percent INT, url_num_plus INT,
                    url_query_len INT, url_num_query_para INT, url_ip_present INT,
                    url_entropy FLOAT, url_count_consonants INT, url_num_digits INT,
                    url_port INT, url_has_https INT, url_has_ip_address INT,
                    url_num_subdomains INT, url_has_suspicious_words INT,
                    url_length_category INT, url_has_port_in_url INT,
                    url_num_special_chars INT, url_num_params INT, url_num_fragments INT,
                    url_starts_with_www INT, url_is_shortened INT, url_has_email INT,
                    `html_num_tags('iframe')` INT, `html_num_tags('script')` INT,
                    `html_num_tags('embed')` INT, `html_num_tags('object')` INT,
                    `html_num_tags('div')` INT, `html_num_tags('head')` INT,
                    `html_num_tags('body')` INT, `html_num_tags('form')` INT,
                    `html_num_tags('a')` INT, `html_num_tags('small')` INT,
                    `html_num_tags('span')` INT, `html_num_tags('input')` INT,
                    `html_num_tags('applet')` INT, `html_num_tags('img')` INT,
                    `html_num_tags('video')` INT, `html_num_tags('audio')` INT,
                    url TEXT, result INT
                )
            """)
            conn.commit()
    except Exception as e:
        print(f"[DB 오류] 테이블 생성 실패: {e}")
    finally:
        conn.close()

#DB에 검사한 url의 이름과 feature, result를 저장
def save_data(user_url, result):
    from sqlalchemy import create_engine

    engine = create_engine('mysql+pymysql://python:python@localhost:3306/python_db')
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
            sql_check = 'SELECT url FROM feature_and_result WHERE url=%s AND username=%s'
            cursor.execute(sql_check, (user_url, st.session_state.user_name))
            if cursor.fetchone():
                print(f"'{user_url}'은(는) 이미 DB에 존재합니다. 새로운 데이터를 저장하지 않습니다.")
                return

        df = pd.read_csv('extract_feature.csv')
        df['url'] = user_url
        df['result'] = result
        df['username'] = st.session_state.user_name  # ✅ 사용자 이름 컬럼 추가

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

        query = """
            SELECT url, url_len, url_entropy, result
            FROM feature_and_result
            WHERE username = %s
        """

        df = pd.read_sql(query, conn, params=(st.session_state.user_name,))
        return df

    except Exception as e:
        st.error(f"❌ 전체 데이터 로딩 오류: {e}")
        return pd.DataFrame()
    finally:
        conn.close()

def load_data_from_db(query, params=None):
    try:
        conn = pymysql.connect(
            host='localhost',
            user='python',
            password='python',
            db='python_db',
            charset='utf8mb4'
        )
        df = pd.read_sql(query, conn, params=params)
        return df
    except Exception as e:
        st.error(f"❌ DB에서 데이터 불러오기 실패: {e}")
        return pd.DataFrame()
    finally:
        conn.close()



def visualize_tag_pie_and_entropy(df):
    try:
        df_temp = df.copy()
        df_temp.columns = df_temp.columns.str.replace("html_num_tags\\('", "", regex=True).str.replace("'\\)", "", regex=True)
        left, center, right = st.columns([2, 4, 2])
        with center:
            st.image("data/URL Entropy Distribution by Class.png", use_column_width=True)

        st.markdown(f'🧪 URL 엔트로피란? ')
        st.markdown('url 문자열이 얼마나 무작위적인지 나타내는 값입니다. 피싱 사이트의 URL은 무작위적인 문자와 숫자로 구성되어 엔트로피값이 높게 나타나는 경향이 있습니다.')
        st.markdown('결과적으로, 높은 엔트로피를 가진 URL이 정상보다 악성일 확률이 더 높음을 나타냅니다.')

        # 2. 태그 비율 파이 차트
        st.markdown(" ")
        st.markdown(f"##### 🔍 악성/정상 사이트 간 태그 비율 비교")

        tags_to_compare = ['script', 'iframe', 'div', 'a', 'img']
        malicious_df_tags = df_temp[df_temp['repu'] == 'malicious']
        benign_df_tags = df_temp[df_temp['repu'] == 'benign']



        # sum 먼저, 변환은 그 다음에!
        malicious_tag_counts = malicious_df_tags[tags_to_compare].sum()
        benign_tag_counts = benign_df_tags[tags_to_compare].sum()
        malicious_tag_counts = pd.to_numeric(malicious_tag_counts, errors='coerce').fillna(0)
        benign_tag_counts = pd.to_numeric(benign_tag_counts, errors='coerce').fillna(0)
        malicious_df_tags_numeric = malicious_df_tags.drop(columns=['repu']).apply(pd.to_numeric, errors='coerce').fillna(0)
        benign_df_tags_numeric = benign_df_tags.drop(columns=['repu']).apply(pd.to_numeric, errors='coerce').fillna(0)
        malicious_others_count = malicious_df_tags_numeric.sum().sum() - malicious_tag_counts.sum()
        benign_others_count = benign_df_tags_numeric.sum().sum() - benign_tag_counts.sum()

        malicious_final_counts = malicious_tag_counts.to_dict()
        malicious_final_counts['Others'] = malicious_others_count
        benign_final_counts = benign_tag_counts.to_dict()
        benign_final_counts['Others'] = benign_others_count

        # 비율 기준 정렬
        malicious_total = sum(malicious_final_counts.values())
        benign_total = sum(benign_final_counts.values())

        malicious_final_counts = dict(sorted(malicious_final_counts.items(), key=lambda x: x[1], reverse=True))
        benign_final_counts = dict(sorted(benign_final_counts.items(), key=lambda x: x[1], reverse=True))

        fig, axes = plt.subplots(1, 2, figsize=(18, 9))
        colors_mal = sns.color_palette('Set3', n_colors=len(malicious_final_counts))
        colors_ben = sns.color_palette('Pastel1', n_colors=len(benign_final_counts))

        # === 악성 사이트 차트 ===
        mal_labels = [f"{k}: {v/malicious_total*100:.1f}%" for k, v in malicious_final_counts.items()]
        mal_patches, _ = axes[0].pie(malicious_final_counts.values(), labels=None,
                                    startangle=90, colors=colors_mal, textprops={'fontsize': 12})
        axes[0].set_title('악성 웹사이트의 태그 비율', fontsize=16)
        axes[0].axis('equal')
        axes[0].legend(mal_patches, mal_labels, loc='center left', bbox_to_anchor=(1, 0.5), title="HTML 태그")

        # === 정상 사이트 차트 ===
        ben_labels = [f"{k}: {v/benign_total*100:.1f}%" for k, v in benign_final_counts.items()]
        ben_patches, _ = axes[1].pie(benign_final_counts.values(), labels=None,
                                    startangle=90, colors=colors_ben, textprops={'fontsize': 12})
        axes[1].set_title('정상 웹사이트의 태그 비율', fontsize=16)
        axes[1].axis('equal')
        axes[1].legend(ben_patches, ben_labels, loc='center left', bbox_to_anchor=(1, 0.5), title="HTML 태그")

        plt.tight_layout()
        st.pyplot(fig)
        plt.clf()
        st.markdown(f'🧪 특정 태그(<script>, <iframe>)가 과도하게 많거나 <span>, <link>, <input> 등으로 구성된 Others의 비율이 높은 경우 악성 사이트일 가능성이 높다고 판단할 수 있습니다.')
        

    except Exception as e:
        st.error(f"시각화 중 오류가 발생했습니다: {e}")

@st.cache_data
def load_train_data(features):
    df_train = pd.read_csv("BE/TrainDataAll.csv")
    df_train.columns = df_train.columns.str.replace(r"html_num_tags\('", "", regex=True).str.replace(r"'\)", "", regex=True)
    df_train = df_train.dropna(subset=features + ['repu'])
    df_train['repu'] = df_train['repu'].astype(str)
    return df_train

def draw_radar_chart(user_url, features):
    try:
        st.markdown(" ")
        st.markdown(f"##### 🔍 입력 URL과 정상 및 악성 URL의 평균값을 비교하는 레이더 차트")

        # 1. 학습 데이터 고정된 기준으로 불러오기 + 정규화
        df_train = load_train_data(features)

        # 정규화 기준 고정
        scaler = MinMaxScaler()
        df_train_scaled_values = scaler.fit_transform(df_train[features])
        df_train_scaled = pd.DataFrame(df_train_scaled_values, columns=features)
        df_train_scaled['repu'] = df_train['repu'].values

        # 고정된 평균값 계산
        mean_benign = df_train_scaled[df_train_scaled['repu'] == 'benign'][features].mean().values
        mean_malicious = df_train_scaled[df_train_scaled['repu'] == 'malicious'][features].mean().values

        print("✔ 평균 benign:", mean_benign[:5])
        print("✔ 평균 malicious:", mean_malicious[:5])


        # 2. DB에서 사용자 데이터 가져오기
        user_query = """
            SELECT * FROM feature_and_result
            WHERE url = %s AND username = %s
            LIMIT 1
        """
        df_user = load_data_from_db(user_query, (user_url, st.session_state.get("user_name", "default_user")))

        if df_user.empty:
            st.warning(f"❗ `{user_url}` 에 해당하는 데이터가 DB에 없습니다.")
            return

        df_user.columns = df_user.columns.str.replace(r"html_num_tags\('", "", regex=True).str.replace(r"'\)", "", regex=True)

        # 사용자 URL 값 정규화
        user_values_raw = df_user[features].iloc[0].values.reshape(1, -1)
        user_values = scaler.transform(user_values_raw).flatten()

        # 3. 레이더 차트 준비
        labels = features
        num_vars = len(labels)
        angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
        angles += angles[:1]

        user_values = np.concatenate((user_values, [user_values[0]]))
        mean_benign = np.concatenate((mean_benign, [mean_benign[0]]))
        mean_malicious = np.concatenate((mean_malicious, [mean_malicious[0]]))

        fig, ax = plt.subplots(figsize=(6, 6), subplot_kw=dict(polar=True))
        ax.plot(angles, user_values, label='사용자 URL', color='green')
        ax.plot(angles, mean_benign, label='정상 평균', color='blue')
        ax.plot(angles, mean_malicious, label='악성 평균', color='red')

        ax.fill(angles, user_values, color='green', alpha=0.25)
        ax.fill(angles, mean_benign, color='blue', alpha=0.15)
        ax.fill(angles, mean_malicious, color='red', alpha=0.15)

        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(labels, fontsize=9)
        ax.set_title('입력 URL vs 정상/악성 평균 Feature 비교', size=15)
        ax.legend(loc='upper right')
        
        st.pyplot(fig)

        st.markdown(
            f'🧪 정상 URL과 악성 URL 평균 패턴과의 차이를 비교하여, '
            '현저히 다른 이상치(Outliers)가 관측될 경우 이를 악성 URL로 분류하는 근거가 됩니다.'
        )

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

        st.markdown(" ")
        st.markdown(f"##### 🔍 악성 사이트의 평균과 정상 사이트의 평균을 비교한 레이더 차트")
        # === 3. 레이더 차트 준비 ===
        labels = features
        num_vars = len(labels)
        angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
        angles += angles[:1]

        mean_malicious = np.concatenate((mean_malicious, [mean_malicious[0]]))
        mean_benign = np.concatenate((mean_benign, [mean_benign[0]]))

        fig, ax = plt.subplots(figsize=(6, 6), subplot_kw=dict(polar=True))
        ax.plot(angles, mean_malicious, label='악성 사이트 평균', color='red')
        ax.plot(angles, mean_benign, label='정상 사이트 평균', color='blue')
        ax.fill(angles, mean_malicious, color='red', alpha=0.25)
        ax.fill(angles, mean_benign, color='blue', alpha=0.15)
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(labels, fontsize=9)
        ax.set_title('악성 평균 vs 정상 평균 Feature 비교', size=15)
        ax.legend(loc='upper right')
        left, center, right = st.columns([2, 4, 2])
        with center:
            st.pyplot(fig)
        
        st.markdown(f'🧪 악성 사이트는 url_entropy, 도메인 길이, 호스트 길이, 도메인 토큰 길이 등의 값이 높아 전반적으로 URL이 복잡하고 무작위적인 구조를 가지는 반면, 정상 사이트는 www로 시작할 가능성이 높고, 비교적 정제된 URL 구조를 갖는 경향이 있습니다.')   
    
    except Exception as e:
        st.error(f"차트 생성 중 오류 발생: {e}")


def url_analysis_page(train_csv, user_csv, features):
    st.title("🔍 URL 분석")
    left, center, right = st.columns([2, 4, 2])
    with center:
        user_url = st.text_input("🔎 악성 여부를 확인할 URL을 입력하세요", "")
        search_button = st.button("검색")

        # 세션 상태 초기화
        if 'result' not in st.session_state:
            st.session_state.result = None
        if 'prob' not in st.session_state:
            st.session_state.prob = None
        if 'show_charts' not in st.session_state:
            st.session_state.show_charts = False
        
        # '검색' 버튼 클릭 시 URL 분석 및 세션 상태에 결과 저장
        if search_button:
            # URL 분석 로직
            parsing_html.get_csv(user_url)
            st.session_state.result, st.session_state.prob = predict_module.predict_from_csv(csv_path='extract_feature.csv')
            st.session_state.user_url = user_url
            
            # '검색' 버튼을 누르면 차트 숨기기 상태로 초기화
            st.session_state.show_charts = False
            
            # DB에 데이터 저장
            # save_data(user_url, st.session_state.result) # 예제에서는 주석 처리

        # 결과가 존재하면 표시
        if st.session_state.result is not None:
            if st.session_state.result == 1:
                st.success(f"### ✅ {st.session_state.user_url} 사이트는 **정상 사이트입니다.**\n###확률: {st.session_state.prob:.2f}%")
            elif st.session_state.result == 0:
                st.error(f"### 🚨 {st.session_state.user_url} 사이트는 **악성 사이트입니다.**\n###확률: {st.session_state.prob:.2f}%")
            else:
                st.info(f"⚠️ 분류되지 않은 결과값: {st.session_state.result}")

            # ✅ 차트 토글 버튼은 결과가 나온 후에 표시
            chart_button = st.button("📈 차트 보기/숨기기")
            if chart_button:
                st.session_state.show_charts = not st.session_state.show_charts

        # ✅ 차트 상태에 따라 시각화 표시
        if st.session_state.show_charts and st.session_state.result is not None:
            try:
                st.markdown("### 🧠 해당 URL 분석 시각화")
                df = pd.read_csv('extract_feature.csv')
                df['url'] = st.session_state.user_url
                matched_row = df

                if not matched_row.empty:
                    st.markdown(" ")
                    st.markdown(f"##### 🔍 HTML 태그 별 파이차트 분석")
                    # 1. HTML 태그 파이차트
                    html_columns = [col for col in matched_row.columns if "html_num_tags" in col]
                    tag_counts = matched_row.iloc[0][html_columns]
                    tag_counts = pd.to_numeric(tag_counts, errors='coerce')  # 숫자형 변환
                    tag_counts = tag_counts[tag_counts > 0]
                                            
                    if not tag_counts.empty:
                        # 정렬: 값 기준 내림차순
                        tag_counts = tag_counts.sort_values(ascending=False)
                                                
                        # 추출된 태그명 (예: html_num_tags('div') → div)
                        tag_labels = tag_counts.index.str.extract(r"\'(\w+)\'")[0]

                        fig1, ax1 = plt.subplots(figsize=(8, 8))
                                                
                        # 색상 자동 생성
                        colors = plt.cm.Set3(range(len(tag_counts)))

                        # 파이차트 그리기 (autopct 없이)
                        wedges, _ = ax1.pie(tag_counts, labels=None, startangle=90, colors=colors)

                        # 범례 라벨 생성: "태그명: 퍼센트%"
                        tag_labels = tag_counts.index.str.extract(r"\'(\w+)\'")[0]
                        legend_labels = [f"{tag}: {pct:.1f}%" for tag, pct in zip(tag_labels, tag_counts / tag_counts.sum() * 100)]

                        # 정렬된 순서로 범례 출력
                        ax1.legend(wedges, legend_labels, title="HTML 태그", loc="center left", bbox_to_anchor=(1, 0.5))

                        ax1.set_title("HTML 태그 비율")
                        st.pyplot(fig1)
                        st.markdown(f'🧭 사용자 URL의 HTML 태그 분포를 시각화하여, 악성 사이트에서 자주 사용되는 태그의 과도한 사용 여부를 분석합니다.')

                    else:
                        st.info("해당 URL의 HTML 태그 정보가 부족합니다.")
                                                
                    # 2. URL 특성 바차트
                    st.markdown(f"##### 🔍 URL 값 비교 막대그래프 ")
                    url_columns = [
                        'url_len', 'url_path_len', 'url_filename_len',
                        'url_domain_len', 'url_hostname_len', 'url_entropy',
                        'url_num_dots', 'url_num_slashes', 'url_num_equals'
                    ]
                                                    
                    url_columns_mean = [
                        'URL 전체 길이', 'URL 경로 길이', 'URL 파일 이름의 길이', 'http://와 www.을 제외한 도메인 이름의 길이',
                        '호스트 이름의 길이', 'url 엔트로피 (복잡도)', 'URL에 포함된 점(.)의 개수', 'URL에 포함된 슬래시(/)의 개수',
                        'URL에 포함된 등호(=)의 개수'
                    ]
                    row_data = matched_row.iloc[0][url_columns].reset_index()
                    row_data.columns = ['Feature', 'Value']
                    fig2, ax2 = plt.subplots(figsize=(10, 6))
                    sns.barplot(data=row_data, x='Feature', y='Value', palette='Set2', ax=ax2)
                    ax2.set_xticklabels(ax2.get_xticklabels(), rotation=45)
                    ax2.set_title("URL에 관련된 값 비교")
                    plt.tight_layout()
                    
                    st.pyplot(fig2)
                    for i, (col_name, col_mean) in enumerate(zip(url_columns, url_columns_mean)):
                        st.markdown(f"**{i+1}.** **`{col_name}`** : {col_mean}")
                    
                    st.markdown(" ")
                    st.markdown(f'🧪 악성 URL은 정상적인 URL과 유사하지만 미묘하게 다른 도메인명, 복잡한 경로, 특정 키워드 등을 통해 악성 여부를 판단합니다. ')
                    st.markdown(" ")
                    
                    #draw_radar_chart(st.session_state.user_url, features)

                else:
                    st.info("⚠️ 입력한 URL에 대한 상세 데이터가 CSV 파일에 없습니다.")

            except Exception as e:
                st.warning(f"⚠️ 시각화 중 오류 발생: {e}")
                    

def history_page(train_csv, user_csv, features):
    st.title("📜 URL 분석 이력")
    df_history = load_from_DB()

    if 'toggle_states' not in st.session_state:
        st.session_state.toggle_states = {}

    if not df_history.empty:
        df_history['result'] = df_history['result'].map({1: '정상', 0: '악성'}).fillna('미분류')

        for i, row in df_history.iterrows():
            url = row['url']
            result = row['result']

            # 색상 설정
            color = 'green' if result == '정상' else 'red'

            if url not in st.session_state.toggle_states:
                st.session_state.toggle_states[url] = False

            with st.container():
                cols = st.columns([4, 1, 1])

                cols[0].text(url)
                cols[1].markdown(f"<span style='color:{color}; font-weight:bold'>{result}</span>", unsafe_allow_html=True)

                if cols[2].button("조회", key=f"view_{i}"):
                    st.session_state.toggle_states[url] = not st.session_state.toggle_states[url]

                if st.session_state.toggle_states[url]:
                    st.markdown(f"##### 📌 상세 정보")
                    st.markdown(f"**🔗 URL:** `{url}`")
                    st.markdown(f"- 🔸 URL 길이 (`url_len`): `{row['url_len']}`")
                    st.markdown(f"- 🔸 URL 엔트로피 (`url_entropy`): `{row['url_entropy']:.4f}`")
                    st.markdown(f"- 🔸 판별 결과: `{result}`")

                    if st.button(f"🌐 링크 열기", key=f"link_{i}"):
                        if result == '악성':
                            with st.expander("🚨 **경고**: 이 사이트는 악성으로 의심됩니다. 정말 접속하시겠습니까?", expanded=True):
                                st.markdown(f"[🔗 링크 열기]({url})", unsafe_allow_html=True)
                        else:
                            st.markdown(f"[🔗 링크 열기]({url})", unsafe_allow_html=True)

                    try:
                        # 1. DB에서 해당 URL과 사용자명에 맞는 데이터 가져오기
                        query = """
                            SELECT *
                            FROM feature_and_result
                            WHERE url = %s AND username = %s
                            LIMIT 1
                        """
                        params = (url, st.session_state.get("user_name", "default_user"))
                        matched_row = load_data_from_db(query, params)

                        if not matched_row.empty:
                            st.markdown(" ")
                            
                            st.markdown(f"##### 🔍 HTML 태그 별 파이차트 분석")

                            html_columns = [col for col in matched_row.columns if "html_num_tags" in col]
                            tag_counts = matched_row.iloc[0][html_columns]
                            tag_counts = pd.to_numeric(tag_counts, errors='coerce')  # 숫자형 변환
                            tag_counts = tag_counts[tag_counts > 0]

                            if not tag_counts.empty:
                                tag_counts = tag_counts.sort_values(ascending=False)
                                tag_labels = tag_counts.index.str.extract(r"\'(\w+)\'")[0]

                                fig1, ax1 = plt.subplots(figsize=(8, 8))
                                colors = plt.cm.Set3(range(len(tag_counts)))
                                wedges, _ = ax1.pie(tag_counts, labels=None, startangle=90, colors=colors)

                                legend_labels = [f"{tag}: {pct:.1f}%" for tag, pct in zip(tag_labels, tag_counts / tag_counts.sum() * 100)]
                                ax1.legend(wedges, legend_labels, title="HTML 태그", loc="center left", bbox_to_anchor=(1, 0.5))

                                ax1.set_title("HTML 태그 비율")
                                left, center, right = st.columns([2, 4, 2])
                                with center:
                                    st.pyplot(fig1)
                                    st.markdown(f'🧭 사용자 URL의 HTML 태그 분포를 시각화하여, 악성 사이트에서 자주 사용되는 태그의 과도한 사용 여부를 분석합니다.')
                            else:
                                st.info("해당 URL의 HTML 태그 정보가 부족합니다.")

                            st.markdown(f"##### 🔍 URL 값 비교 막대그래프 ")
                            url_columns = [
                                'url_len', 'url_path_len', 'url_filename_len',
                                'url_domain_len', 'url_hostname_len', 'url_entropy',
                                'url_num_dots', 'url_num_slashes', 'url_num_equals'
                            ]

                            url_columns_mean = [
                                'URL 전체 길이', 'URL 경로 길이', 'URL 파일 이름의 길이', 'http://와 www.을 제외한 도메인 이름의 길이',
                                '호스트 이름의 길이', 'url 엔트로피 (복잡도)', 'URL에 포함된 점(.)의 개수', 'URL에 포함된 슬래시(/)의 개수',
                                'URL에 포함된 등호(=)의 개수'
                            ]

                            row_data = matched_row.iloc[0][url_columns].reset_index()
                            row_data.columns = ['Feature', 'Value']
                            fig2, ax2 = plt.subplots(figsize=(10, 6))
                            sns.barplot(data=row_data, x='Feature', y='Value', palette='Set2', ax=ax2)
                            ax2.set_xticklabels(ax2.get_xticklabels(), rotation=45)
                            ax2.set_title("URL에 관련된 값 비교")
                            plt.tight_layout()
                            left, center, right = st.columns([2, 4, 2])
                            with center:
                                st.pyplot(fig2)

                            for i, (col_name, col_mean) in enumerate(zip(url_columns, url_columns_mean)):
                                st.markdown(f"**{i+1}.** **`{col_name}`** : {col_mean}")

                            st.markdown(" ")
                            st.markdown(f'🧪 악성 URL은 정상적인 URL과 유사하지만 미묘하게 다른 도메인명, 복잡한 경로, 특정 키워드 등을 통해 악성 여부를 판단합니다. ')
                            st.markdown(" ")
                            left, center, right = st.columns([2, 4, 2])
                            with center:
                                draw_radar_chart(url, features)

                        else:
                            st.info("⚠️ 해당 URL에 대한 데이터가 DB에 없습니다.")

                    except Exception as e:
                        st.warning(f"⚠️ 조회 중 오류 발생: {e}")

    else:
        st.info("아직 저장된 URL 정보가 없습니다.")



        
def dashboard_page(train_csv, features, dftd):
    st.subheader("📊 악성 vs 정상 사이트 분석 대시보드")
    compare_benign_malicious_chart(train_csv, features)
    visualize_tag_pie_and_entropy(dftd)

# 메인 실행 함수
def main_page():
    create_table_if_not_exists()
    st.set_page_config(page_title="지키링", layout="wide")

    st.sidebar.title("지키링 네비게이션")
    with st.sidebar:
        st.markdown(f"👤 **{st.session_state.user_name} 님**")
        if st.button("🚪 로그아웃"):
            st.session_state.logged_in = False
            st.session_state.page = "login"
            st.rerun()

    page = st.sidebar.selectbox(
        "페이지를 선택하세요",
        ["URL 분석", "분석 이력", "악성 vs 정상 대시보드", "온라인 보안 뉴스"]
    )

    train_csv = "BE/TrainDataAll.csv"
    user_csv = "extract_feature.csv"
    features = [                        
        "url_entropy", "url_path_len", "url_filename_len", "url_longest_dom_token_len",
        "url_average_dom_token_len", "url_domain_len", "url_hostname_len", "url_port",
        "script", "div"
    ]

    if page == "URL 분석":
        url_analysis_page(train_csv, user_csv, features)

    elif page == "분석 이력":
        history_page(train_csv, user_csv, features)

    elif page == "악성 vs 정상 대시보드":
        dftd = pd.read_csv(train_csv)
        dftd.columns = dftd.columns.str.replace("html_num_tags\\('", "", regex=True).str.replace("'\\)", "", regex=True)
        dashboard_page(train_csv, features, dftd)

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

def main():
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'page' not in st.session_state:
        st.session_state.page = "login"

    if st.session_state.logged_in and st.session_state.page == "main":
        main_page()
    else:
        login_page()

if __name__ == "__main__":
    main()
