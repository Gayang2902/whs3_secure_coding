import sqlite3
from werkzeug.security import generate_password_hash

SCHEMA = """
-- users 테이블: 차단 여부, 잔액(balance), 소개글(intro) 추가
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT    UNIQUE NOT NULL,
    pw_hash      TEXT    NOT NULL,
    is_admin     INTEGER NOT NULL DEFAULT 0,
    is_blocked   INTEGER NOT NULL DEFAULT 0,
    balance      REAL    NOT NULL DEFAULT 0.0,
    intro        TEXT    DEFAULT ''
);

-- 상품 게시글 테이블
CREATE TABLE IF NOT EXISTS posts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    title        TEXT    NOT NULL,
    body         TEXT    NOT NULL,
    price        REAL    NOT NULL,
    user_id      INTEGER NOT NULL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_sold      INTEGER NOT NULL DEFAULT 0,
    is_blocked   INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

-- 댓글 테이블
CREATE TABLE IF NOT EXISTS comments (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    body         TEXT    NOT NULL,
    user_id      INTEGER NOT NULL,
    post_id      INTEGER NOT NULL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(post_id) REFERENCES posts(id)
);

-- 거래 내역 테이블
CREATE TABLE IF NOT EXISTS transactions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user_id   INTEGER NOT NULL,
    to_user_id     INTEGER NOT NULL,
    amount         REAL    NOT NULL,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(from_user_id) REFERENCES users(id),
    FOREIGN KEY(to_user_id)   REFERENCES users(id)
);

-- 신고 테이블
CREATE TABLE IF NOT EXISTS reports (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_id    INTEGER NOT NULL REFERENCES users(id),
    target_type    TEXT    NOT NULL CHECK(target_type IN ('post','user')),
    target_id      INTEGER NOT NULL,
    reason         TEXT    NOT NULL,
    timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(reporter_id, target_type, target_id)
);

-- 인덱스 추가
CREATE INDEX IF NOT EXISTS idx_reports_target ON reports(target_type, target_id);

-- 1:1 채팅 방 테이블
CREATE TABLE IF NOT EXISTS rooms (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_a    INTEGER NOT NULL,
    user_b    INTEGER NOT NULL,
    UNIQUE(user_a, user_b),
    FOREIGN KEY(user_a) REFERENCES users(id),
    FOREIGN KEY(user_b) REFERENCES users(id)
);

-- 채팅 메시지 테이블
-- room_id 가 NULL 이면 global 채팅, 그렇지 않으면 1:1 대화
CREATE TABLE IF NOT EXISTS messages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id       INTEGER REFERENCES rooms(id),
    sender_id     INTEGER NOT NULL REFERENCES users(id),
    content       TEXT    NOT NULL,
    timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- (옵션) FTS5 인덱스로 상품 검색 지원
CREATE VIRTUAL TABLE IF NOT EXISTS post_search
USING fts5(title, body, content='posts', content_rowid='id');
"""

def init_db(db_path: str = 'app.db'):
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SCHEMA)

        # 관리자 계정 자동 생성
        cur = conn.execute("SELECT 1 FROM users WHERE is_admin=1")
        if not cur.fetchone():
            pw_hash = generate_password_hash("admin123")
            conn.execute(
                "INSERT INTO users (username, pw_hash, is_admin, balance) VALUES (?, ?, 1, 0.0)",
                ("admin", pw_hash)
            )
            print("Created default admin account: admin / admin123")

        conn.commit()
    finally:
        conn.close()

if __name__ == '__main__':
    init_db()
