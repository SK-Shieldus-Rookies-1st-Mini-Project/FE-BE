import re
import math
import socket
import string
import re
import pandas as pd
from urllib.parse import urlparse
from collections import Counter
import requests
import os
from bs4 import BeautifulSoup
import pandas as pd
from bs4 import BeautifulSoup
from tqdm import tqdm
import csv

def getHtml(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    try:
        #요청 헤더 설정 : 브라우저 정보
        req_header = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
        }

        # requests 의 get() 함수 호출하기 
        res=requests.get(url,headers=req_header)
        res.encoding = 'utf-8'
        res.raise_for_status()

        # 응답(response)이 OK 이면 text 추출
        html = res.text
        return html
    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
        return "Error"
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return "Error"   

def url_len(url):
    return len(url)

def url_num_hyphens_dom(url):
    return urlparse(url).netloc.count('-')

def url_num_dom_token(url):
    return len(urlparse(url).netloc.split('.'))

def url_path_len(url):
    return len(urlparse(url).path)

def url_filename_len(url):
    return len(urlparse(url).path.split('/')[-1])

def url_longest_dom_token_len(url):
    tokens = urlparse(url).netloc.split('.')
    return max(len(t) for t in tokens)

def url_average_dom_token_len(url):
    tokens = urlparse(url).netloc.split('.')
    return sum(len(t) for t in tokens) / len(tokens)

def url_tld(url):
    tokens = urlparse(url).netloc.split('.')
    return tokens[-1] if len(tokens) > 1 else ''

def url_domain_len(url):
    return len(urlparse(url).netloc)

def url_hostname_len(url):
    return len(urlparse(url).hostname or '')

def url_num_dots(url):
    return url.count('.')

def url_num_underscores(url):
    return url.count('_')

def url_num_equals(url):
    return url.count('=')

def url_num_slashes(url):
    return url.count('/')

def url_num_dash(url):
    return url.count('-')

def url_num_semicolon(url):
    return url.count(';')

def url_num_at(url):
    return url.count('@')

def url_num_percent(url):
    return url.count('%')

def url_num_plus(url):
    return url.count('+')

def url_query_len(url):
    return len(urlparse(url).query)

def url_num_query_para(url):
    return len(urlparse(url).query.split('&')) if urlparse(url).query else 0

def url_ip_present(url):
    try:
        host = urlparse(url).netloc
        socket.inet_aton(host)
        return 1
    except:
        return 0

def url_entropy(url):
    prob = [n / len(url) for n in Counter(url).values()]
    return -sum(p * math.log2(p) for p in prob)

def url_count_consonants(url):
    consonants = set("bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ")
    return sum(1 for c in url if c in consonants)

def url_num_digits(url):
    return sum(c.isdigit() for c in url)

def url_port(url):
    return urlparse(url).port or 80  # 기본 포트 80

def url_has_https(url):
    """HTTPS 사용 여부"""
    return int(urlparse(url).scheme == 'https')

def url_has_ip_address(url):
    """도메인 대신 IP 사용 여부"""
    host = urlparse(url).netloc
    # IPv4 정규식
    return int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)))

def url_num_subdomains(url):
    """서브도메인 개수"""
    tokens = urlparse(url).hostname.split('.') if urlparse(url).hostname else []
    # 일반적으로 도메인+TLD를 제외한 나머지가 서브도메인
    return max(len(tokens) - 2, 0)

def url_has_suspicious_words(url):
    """의심 단어 포함 여부 (예: login, verify, update 등)"""
    suspicious = ['login', 'verify', 'update', 'secure', 'account', 'bank', 'signin', 'wp-admin']
    return int(any(word in url.lower() for word in suspicious))

def url_length_category(url):
    """URL 길이 구간화 (짧음/보통/김)"""
    l = len(url)
    if l < 54:
        return 0  # 짧음
    elif l < 75:
        return 1  # 보통
    else:
        return 2  # 김

def url_has_port_in_url(url):
    """URL에 포트 명시 여부"""
    return int(':' in urlparse(url).netloc)

def url_num_special_chars(url):
    """특수문자 개수"""
    special_chars = set('!#$%^&*()[]{};:,<>?\\|`~')
    return sum(1 for c in url if c in special_chars)

def url_num_params(url):
    """URL 파라미터 개수"""
    return urlparse(url).query.count('=')  # 파라미터 개수

def url_num_fragments(url):
    """URL에 #fragment 개수"""
    return url.count('#')

def url_starts_with_www(url):
    """www로 시작하는지 여부"""
    return int(urlparse(url).netloc.startswith('www.'))

def url_is_shortened(url):
    """단축 URL 여부 (일부 유명 단축 도메인 포함)"""
    shorteners = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
    netloc = urlparse(url).netloc.lower()
    return int(any(s in netloc for s in shorteners))

def url_has_email(url):
    """URL에 이메일 주소 포함 여부"""
    return int(bool(re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", url)))


def html_num_tags(html, tag):
    soup = BeautifulSoup(html, 'html.parser')
    return len(soup.find_all(tag))

def extract_url_features(url):
    return {
        "url_len": url_len(url),
        "url_num_hyphens_dom": url_num_hyphens_dom(url),
        "url_num_dom_token": url_num_dom_token(url),
        "url_path_len": url_path_len(url),
        "url_filename_len": url_filename_len(url),
        "url_longest_dom_token_len": url_longest_dom_token_len(url),
        "url_average_dom_token_len": url_average_dom_token_len(url),
        "url_domain_len": url_domain_len(url),
        "url_hostname_len": url_hostname_len(url),
        "url_num_dots": url_num_dots(url),
        "url_num_underscores": url_num_underscores(url),
        "url_num_equals": url_num_equals(url),
        "url_num_slashes": url_num_slashes(url),
        "url_num_dash": url_num_dash(url),
        "url_num_semicolon": url_num_semicolon(url),
        "url_num_at": url_num_at(url),
        "url_num_percent": url_num_percent(url),
        "url_num_plus": url_num_plus(url),
        "url_query_len": url_query_len(url),
        "url_num_query_para": url_num_query_para(url),
        "url_ip_present": url_ip_present(url),
        "url_entropy": url_entropy(url),
        "url_count_consonants": url_count_consonants(url),
        "url_num_digits": url_num_digits(url),
        "url_port": url_port(url),
        "url_has_https": url_has_https(url),
        "url_has_ip_address": url_has_ip_address(url),
        "url_num_subdomains": url_num_subdomains(url),
        "url_has_suspicious_words": url_has_suspicious_words(url),
        "url_length_category": url_length_category(url),
        "url_has_port_in_url": url_has_port_in_url(url),
        "url_num_special_chars": url_num_special_chars(url),
        "url_num_params": url_num_params(url),
        "url_num_fragments": url_num_fragments(url),
        "url_starts_with_www": url_starts_with_www(url),
        "url_is_shortened": url_is_shortened(url),
        "url_has_email": url_has_email(url),
    }

# 📌 1. HTML 태그 특성 추출 함수
def extract_html_features(html):
    soup = BeautifulSoup(str(html), 'html.parser')
    
    tags_to_count = [
        'iframe', 'script', 'embed', 'object', 'div', 'head', 'body',
        'form', 'a', 'small', 'span', 'input', 'applet', 'img', 'video', 'audio'
    ]
    
    features = {}
    for tag in tags_to_count:
        features[f"html_num_tags('{tag}')"] = len(soup.find_all(tag))
    
    return features

def to_csv(url, html):
    if html != "Error":
        csv.field_size_limit(10**7)  # 10MB로 제한 늘리기
        tqdm.pandas()  # tqdm 설정 (진행상황 보기)
        # 1. 파일 이름 설정
        file_name = "htmlCode.html"

        # 2. 'w' 모드로 파일을 엽니다. (파일이 없으면 생성, 있으면 덮어쓰기)
        #    encoding='utf-8'을 지정하여 한글이 깨지지 않게 합니다.
        with open(file_name, 'w', encoding='utf-8') as file:
            # 3. HTML 코드를 파일에 씁니다.
            file.write(html)
        
        # 📌 2. CSV 파일 불러오기
        html_path = "htmlCode.html"  # 실제 HTML 파일 경로로 수정 필요
        with open(html_path, encoding="utf-8") as f:
            html_code = f.read()

        df_html = pd.DataFrame({
            'url' : [url],
            'html_code': [html_code]
        })
        df_html.to_csv('url_and_html_and_begin.csv', index=False, encoding='utf-8')
        df = pd.read_csv('url_and_html_and_begin.csv',encoding='utf-8', engine='python')
        # 컬럼명 확인
        print("컬럼 목록:", df.columns.tolist())
        # URL 특성 추출
        url_feature_df = df['url'].progress_apply(lambda x: pd.Series(extract_url_features(x)))
        # 📌 3. HTML 특성 추출
        html_feature_df = df['html_code'].progress_apply(lambda x: pd.Series(extract_html_features(x)))

        # 📌 5. 최종 결과 결합
        result_df = pd.concat([url_feature_df, html_feature_df], axis=1)

        # 📌 6. 저장
        result_df.to_csv('extract_feature.csv', index=False)

        print(result_df)  
        print(f"HTML 코드가 '{file_name}' 파일에 성공적으로 저장되었습니다.")
    else:
        print("HTML 코드를 가져오는 데 실패하여 파일에 저장할 수 없습니다.")

def get_csv(url):
    html = getHtml(url)
    to_csv(url, html)
