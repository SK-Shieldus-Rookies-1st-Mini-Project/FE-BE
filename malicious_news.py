import requests
from bs4 import BeautifulSoup

def crawl_malicious_news():
    """
    Main_Menu.html에서 모든 뉴스 목록을 가져오고,
    각 뉴스의 detail 페이지에서 제목/이미지/본문을 추출합니다.
    """
    base_url = "https://m.boannews.com/html/"
    news_list = []
    start_idx = 138534
    count = 30

    for idx in range(start_idx, start_idx - count, -1):
        detail_url = f"{base_url}detail.html?mtype=6&tab_type=&idx={idx}"
        try:
            detail_resp = requests.get(detail_url)
            detail_soup = BeautifulSoup(detail_resp.text, 'html.parser')
            # 제목
            title_tag = detail_soup.select_one('div.tit > p')
            title = title_tag.get_text(strip=True) if title_tag else ''
            # 이미지
            img_tag = detail_soup.find('meta', attrs={'property': 'og:image'})
            img_url = img_tag['content'] if img_tag and img_tag.get('content') else ''
            # 본문
            content_tag = detail_soup.select_one('.con #con')
            content = str(content_tag) if content_tag else ''
        except Exception:
            title = ''
            img_url = ''
            content = ''
        if title:
            news_list.append({'title': title, 'img': img_url, 'link': detail_url, 'content': content})
    return news_list