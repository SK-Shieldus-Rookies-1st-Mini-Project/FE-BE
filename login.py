import streamlit as st
import pymysql

# DB 연결 정보
def get_connection():
    conn = pymysql.connect(
        host='localhost',
        user='python',
        password='python',
        db='python_db',
        charset='utf8mb4'
    )
    create_user_table_if_not_exists(conn)  # 연결 후 테이블 생성 체크
    return conn

# user_info 테이블이 없으면 생성하는 함수
def create_user_table_if_not_exists(conn):
    try:
        with conn.cursor() as cursor:
            create_table_sql = """
            CREATE TABLE IF NOT EXISTS user_info (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                username VARCHAR(100) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """
            cursor.execute(create_table_sql)
        conn.commit()
    except Exception as e:
        print(f"테이블 생성 중 오류 발생: {e}")

# 회원가입 기능
def signup(name, username, password):
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            # 아이디 중복 확인
            cursor.execute("SELECT * FROM user_info WHERE username=%s", (username,))
            if cursor.fetchone():
                return False, "이미 존재하는 아이디입니다."

            # 사용자 정보 삽입
            cursor.execute(
                "INSERT INTO user_info (name, username, password) VALUES (%s, %s, %s)",
                (name, username, password)
            )
            conn.commit()
            return True, "회원가입이 완료되었습니다."
    except Exception as e:
        return False, f"회원가입 중 오류: {e}"
    finally:
        conn.close()

# 로그인 기능
def login(username, password):
    try:
        conn = get_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM user_info WHERE username=%s AND password=%s",
                (username, password)
            )
            user = cursor.fetchone()
            if user:
                return True, f"{user[1]}님 환영합니다!"  # user[1] = name
            else:
                return False, "아이디 또는 비밀번호가 잘못되었습니다."
    except Exception as e:
        return False, f"로그인 중 오류: {e}"
    
    finally:
        conn.close()
