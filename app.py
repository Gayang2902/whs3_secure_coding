import os
from datetime import datetime
import sqlite3
from flask import Flask, g, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
from functools import wraps
import markdown
from flask_socketio import SocketIO, emit, join_room
import re
import bleach
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      # 자바스크립트에서 쿠키 접근 방지
    SESSION_COOKIE_SECURE=True,        # HTTPS에서만 쿠키 전송 (배포 시 필수)
    SESSION_COOKIE_SAMESITE='Lax'      # 크로스사이트 요청 제한 (또는 'Strict')
)
app.secret_key = os.getenv('SECRET_KEY', 'dev_key')
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='eventlet')
limiter = Limiter(get_remote_address, app=app)

# DB 경로
DATABASE = 'app.db'

# 업로드 폴더
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ─── 에러 핸들러 ─────────────────────────────────────
@app.errorhandler(RequestEntityTooLarge)
def on_request_entity_too_large(error):
    flash('업로드 가능한 파일 크기를 초과했습니다. (최대 50MB)')
    return redirect(request.referrer or url_for('new_post'))

# ─── DB 헬퍼 ─────────────────────────────────────────
def get_db():
    if 'db' not in g:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db:
        db.close()

# ─── 로그인 설정 ───────────────────────────────────────
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, pw_hash, is_admin, is_blocked, balance, intro):
        self.id = id
        self.username = username
        self.pw_hash = pw_hash
        self.is_admin = bool(is_admin)
        self.is_blocked = bool(is_blocked)
        self.balance = balance
        self.intro = intro

    def check_password(self, pw):
        return check_password_hash(self.pw_hash, pw)

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute(
        'SELECT * FROM users WHERE id = ?', (user_id,)
    ).fetchone()
    return User(**row) if row else None

# app.py 상단
from flask_socketio import SocketIO, join_room, emit
socketio = SocketIO(app)

# 메시지 전송 이벤트
@socketio.on('private_message')
def handle_private_message(data):
    room = data['room']               # ex. "room_3"
    sender = data['sender_id']
    content = data['content']

    # DB에 저장
    db = get_db()
    db.execute(
        'INSERT INTO messages (room_id, sender_id, content) VALUES (?, ?, ?)',
        (int(room.split('_')[1]), sender, content)
    )
    db.commit()

    # 방에 속한 클라이언트들에게 메시지 전파
    emit('new_message', {
        'room': room,
        'sender_id': sender,
        'content': content,
        'timestamp': datetime.utcnow().isoformat()
    }, room=room)

# ─── 관리자 권한 데코레이터 ─────────────────────────────
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not (current_user.is_authenticated and current_user.is_admin):
            flash('관리자만 접근 가능합니다.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

# ─── 인증 라우트 ───────────────────────────────────────
@app.route('/register', methods=('GET','POST'))
def register():
    USERNAME_RE = re.compile(r'^[a-zA-Z0-9_]{4,20}$')
    PASSWORD_RE = re.compile(r'^.{8,64}$')

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = '아이디를 입력하세요.'
        elif not password:
            error = '비밀번호를 입력하세요.'
        elif db.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone():
            error = f"'{username}' 이미 등록되었습니다."

        if not USERNAME_RE.match(username):
            error = '아이디는 영문, 숫자, 밑줄(_)만 사용 가능하며 4~20자 사이여야 합니다.'
        elif not PASSWORD_RE.match(password):
            error = '비밀번호는 최소 8자 이상이어야 합니다.'

        if error is None:
            db.execute(
                'INSERT INTO users (username, pw_hash) VALUES (?, ?)',
                (username, generate_password_hash(password))
            )
            db.commit()
            flash('회원가입 완료! 로그인해 주세요.')
            return redirect(url_for('login'))
        flash(error)
    return render_template('register.html')

@app.route('/login', methods=('GET','POST'))
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        row = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if not row:
            error = '존재하지 않는 아이디입니다.'
        elif not check_password_hash(row['pw_hash'], password):
            error = '비밀번호가 틀립니다.'
        elif row['is_blocked']:
            error = '차단된 계정입니다.'

        if error is None:
            user = User(**row)
            login_user(user)
            return redirect(url_for('index'))
        flash(error)
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# ─── 이미지 업로드 ─────────────────────────────────────
@app.route('/upload_image', methods=('POST',))
@login_required
def upload_image():
    image = request.files.get('image')
    if not image:
        return jsonify({'success': 0, 'message': 'No image'})
    filename = secure_filename(image.filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image.save(path)
    url = url_for('static', filename=f'uploads/{filename}')
    return jsonify({'success': 1, 'file': {'url': url}})

@app.route('/chats')
@login_required
def chats():
    db = get_db()
    user_id = g.user['id']
    rows = db.execute('''
      SELECT r.id,
        CASE WHEN r.user_a=? THEN r.user_b ELSE r.user_a END AS other_id
      FROM rooms r
      WHERE r.user_a=? OR r.user_b=?
    ''', (user_id, user_id, user_id)).fetchall()
    rooms = []
    for r in rows:
      other = db.execute('SELECT username FROM users WHERE id=?', (r['other_id'],)).fetchone()
      rooms.append({
        'room_name': f'room_{r["id"]}',
        'other_username': other['username']
      })
    return render_template('chats.html', rooms=rooms)

# ─── 메인(게시글 목록) ─────────────────────────────────
@app.route('/')
@login_required
def index():
    q = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page-1)*per_page

    db = get_db()
    if q:
        # 제목이나 본문에 q 포함된 게시글 검색
        rows = db.execute('''
            SELECT p.id,p.title,p.price,p.is_sold,p.created_at,u.username as author
              FROM posts p
              JOIN users u ON p.user_id=u.id
             WHERE p.is_blocked=0
               AND (p.title LIKE ? OR p.body LIKE ?)
             ORDER BY p.id DESC
             LIMIT ? OFFSET ?
        ''', (f'%{q}%', f'%{q}%', per_page, offset)).fetchall()
    else:
        rows = db.execute('''
            SELECT p.id,p.title,p.price,p.is_sold,p.created_at,u.username as author
              FROM posts p
              JOIN users u ON p.user_id=u.id
             WHERE p.is_blocked=0
             ORDER BY p.id DESC
             LIMIT ? OFFSET ?
        ''', (per_page, offset)).fetchall()

    posts = [dict(r) for r in rows]

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify(posts=posts)

    return render_template('index.html', posts=posts, q=q)

# ─── 상품 구매 처리 ──────────────────────────────────
@app.route('/purchase/<int:post_id>', methods=('POST',))
@login_required
def purchase(post_id):
    db = get_db()
    # 게시글 정보 조회
    post = db.execute(
        'SELECT id, price, user_id, is_sold FROM posts WHERE id = ?', (post_id,)
    ).fetchone()

    # 예외 처리
    if not post:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('index'))
    if post['is_sold']:
        flash('이미 판매 완료된 상품입니다.')
        return redirect(url_for('view_post', post_id=post_id))
    if post['user_id'] == current_user.id:
        flash('본인이 등록한 상품은 구매할 수 없습니다.')
        return redirect(url_for('view_post', post_id=post_id))

    # 입력 금액 확인
    amount = request.form.get('amount', type=float)
    if amount is None or amount != post['price']:
        flash('정확한 금액을 입력해주세요.')
        return redirect(url_for('view_post', post_id=post_id))

    # 잔액 확인
    if current_user.balance < amount:
        flash('잔액이 부족합니다.')
        return redirect(url_for('view_post', post_id=post_id))

    # 실제 거래 처리
    db.execute(
        'UPDATE users SET balance = balance - ? WHERE id = ?',
        (amount, current_user.id)
    )
    db.execute(
        'UPDATE users SET balance = balance + ? WHERE id = ?',
        (amount, post['user_id'])
    )
    db.execute(
        'INSERT INTO transactions (from_user_id, to_user_id, amount) VALUES (?, ?, ?)',
        (current_user.id, post['user_id'], amount)
    )
    db.execute(
        'UPDATE posts SET is_sold = 1 WHERE id = ?',
        (post_id,)
    )
    db.commit()

    flash('상품을 성공적으로 구매했습니다!')
    return redirect(url_for('view_post', post_id=post_id))

# ─── 상품 구매 (송금) ─────────────────────────────────
@app.route('/buy/<int:post_id>', methods=('POST',))
@login_required
def buy_post(post_id):
    db = get_db()
    post = db.execute(
        'SELECT id, price, user_id, is_sold FROM posts WHERE id=? AND is_blocked=0',
        (post_id,)
    ).fetchone()
    if not post or post['is_sold']:
        flash('구매할 수 없는 상품입니다.')
        return redirect(url_for('view_post', post_id=post_id))
    if current_user.id == post['user_id']:
        flash('자신의 상품은 구매할 수 없습니다.')
        return redirect(url_for('view_post', post_id=post_id))
    user_row = db.execute('SELECT balance FROM users WHERE id=?', (current_user.id,)).fetchone()
    if user_row['balance'] < post['price']:
        flash('잔액이 부족합니다.')
        return redirect(url_for('view_post', post_id=post_id))
    # 거래 처리
    db.execute('UPDATE users SET balance = balance - ? WHERE id=?', (post['price'], current_user.id))
    db.execute('UPDATE users SET balance = balance + ? WHERE id=?', (post['price'], post['user_id']))
    db.execute('UPDATE posts SET is_sold=1 WHERE id=?', (post_id,))
    db.execute('INSERT INTO transactions (from_user_id, to_user_id, amount) VALUES (?, ?, ?)',
               (current_user.id, post['user_id'], post['price']))
    db.commit()
    flash('구매가 완료되었습니다.')
    return redirect(url_for('view_post', post_id=post_id))

# ─── 새 상품 등록(게시글 쓰기) ────────────────────────────
@app.route('/post/new', methods=('GET','POST'))
@login_required
def new_post():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        raw_body = request.form.get('body', '').strip()
        body_md = bleach.clean(raw_body, tags=[], attributes={})
        price = request.form.get('price', type=float)
        error = None
        # 길이 제한 추가
        if not title:
            error = '제목을 입력해주세요.'
        elif len(title) > 100:
            error = '제목은 최대 100자까지 입력 가능합니다.'
        elif price is None or price < 0:
            error = '유효한 가격을 입력해주세요.'
        elif not body_md:
            error = '본문을 입력해주세요.'
        elif len(body_md) > 1000:
            error = '본문은 최대 1000자까지 입력 가능합니다.'
        if error:
            flash(error)
            return render_template('post_form.html', title=title, price=price, body=body_md)
        db = get_db()
        db.execute(
            'INSERT INTO posts (title, body, price, user_id) VALUES (?, ?, ?, ?)',
            (title, body_md, price, current_user.id)
        )
        db.commit()
        return redirect(url_for('index'))
    return render_template('post_form.html')

# ─── 게시글 보기 & 댓글 쓰기 ─────────────────────────────
@app.route('/post/<int:post_id>', methods=('GET','POST'))
def view_post(post_id):
    db = get_db()
    post = db.execute(
        '''
        SELECT p.id, p.title, p.body, p.price, p.is_sold, u.username AS author, p.created_at
          FROM posts p
          JOIN users u ON p.user_id = u.id
         WHERE p.id=? AND p.is_blocked=0
        ''', (post_id,)
    ).fetchone()
    if not post:
        abort(404)
    comments = db.execute(
        'SELECT c.id, c.body, u.username AS author, c.created_at FROM comments c '
        'JOIN users u ON c.user_id = u.id WHERE c.post_id=? ORDER BY c.id',
        (post_id,)
    ).fetchall()
    if request.method == 'POST' and current_user.is_authenticated:
        comment_body = request.form['comment'].strip()
        if comment_body:
            db.execute(
                'INSERT INTO comments (body, user_id, post_id) VALUES (?, ?, ?)',
                (comment_body, current_user.id, post_id)
            )
            db.commit()
        return redirect(url_for('view_post', post_id=post_id))
    body_html = markdown.markdown(post['body'], extensions=['fenced_code', 'tables'])
    return render_template('post_view.html', post=post, comments=comments, body_html=body_html)

# --게시글 신고
@app.route('/report/post/<int:post_id>', methods=['POST'])
@login_required
def report_post(post_id):
    reason = request.form.get('reason', '').strip()
    if not reason:
        flash('신고 사유를 입력하세요.')
        return redirect(url_for('view_post', post_id=post_id))

    db = get_db()
    # 중복 신고 방지
    try:
        db.execute(
            "INSERT INTO reports (reporter_id, target_type, target_id, reason) VALUES (?,?,?,?)",
            (current_user.id, 'post', post_id, reason)
        )
    except sqlite3.IntegrityError:
        flash('이미 신고하신 대상입니다.')
        return redirect(url_for('view_post', post_id=post_id))
    db.commit()

    # 게시글 누적 신고 5회 시 게시글 차단
    cnt = db.execute(
        "SELECT COUNT(*) FROM reports WHERE target_type='post' AND target_id=?",
        (post_id,)
    ).fetchone()[0]
    if cnt >= 5:
        db.execute("UPDATE posts SET is_blocked=1 WHERE id=?", (post_id,))
        db.commit()
        flash('해당 게시글이 다수 신고되어 차단되었습니다.')

    else:
        flash('게시글 신고가 접수되었습니다.')
    return redirect(url_for('view_post', post_id=post_id))

# 신고(사용자)
@app.route('/report/user/<string:username>', methods=['POST'])
@login_required
def report_user(username):
    reason = request.form.get('reason', '').strip()
    if not reason:
        flash('신고 사유를 입력하세요.')
        return redirect(url_for('user_page', username=username))

    db = get_db()
    target = db.execute(
        'SELECT id FROM users WHERE username=?', (username,)
    ).fetchone()
    if not target:
        abort(404)
    target_id = target['id']

    try:
        db.execute(
            "INSERT INTO reports (reporter_id, target_type, target_id, reason) VALUES (?,?,?,?)",
            (current_user.id, 'user', target_id, reason)
        )
    except sqlite3.IntegrityError:
        flash('이미 신고하신 대상입니다.')
        return redirect(url_for('user_page', username=username))
    db.commit()

    # 사용자 누적 신고 5회 시 사용자 차단
    cnt = db.execute(
        "SELECT COUNT(*) FROM reports WHERE target_type='user' AND target_id=?",
        (target_id,)
    ).fetchone()[0]
    if cnt >= 5:
        db.execute("UPDATE users SET is_blocked=1 WHERE id=?", (target_id,))
        db.commit()
        flash('해당 사용자가 다수 신고되어 차단되었습니다.')
    else:
        flash('사용자 신고가 접수되었습니다.')

    return redirect(url_for('user_page', username=username))

# ─── 관리자 대시보드 ─────────────────────────────────
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    db = get_db()

    # 전체 게시글
    rows_posts = db.execute(
        '''SELECT p.id, p.title, u.username AS author,
                  p.created_at, p.is_sold, p.is_blocked
           FROM posts p
           JOIN users u ON p.user_id = u.id
        '''
    ).fetchall()
    posts = [dict(r) for r in rows_posts]

    # 신고된 게시글 (target_type='post')
    rows_reported_posts = db.execute(
        '''SELECT r.id,
                  u.username      AS reporter,
                  p.id            AS target_id,
                  p.title         AS target_title,
                  r.reason,
                  r.timestamp
           FROM reports r
           JOIN users u ON r.reporter_id = u.id
           JOIN posts p ON r.target_id = p.id
          WHERE r.target_type = 'post'
          ORDER BY r.timestamp DESC
        '''
    ).fetchall()
    reported_posts = [dict(r) for r in rows_reported_posts]

    # 신고된 사용자 (target_type='user')
    rows_reported_users = db.execute(
        '''SELECT r.id,
                  u.username      AS reporter,
                  tu.username     AS target_username,
                  r.reason,
                  r.timestamp
           FROM reports r
           JOIN users  u  ON r.reporter_id = u.id
           JOIN users  tu ON r.target_id    = tu.id
          WHERE r.target_type = 'user'
          ORDER BY r.timestamp DESC
        '''
    ).fetchall()
    reported_users = [dict(r) for r in rows_reported_users]

    # 유저 목록
    rows_users = db.execute(
        'SELECT id, username, is_blocked, balance FROM users'
    ).fetchall()
    users = [dict(r) for r in rows_users]

    return render_template(
        'admin.html',
        posts=posts,
        reports=reported_posts,      # 신고된 게시글 탭에 넘기는 데이터
        users=users,
        reported_users=reported_users  # 신고된 사용자 탭에 넘기는 데이터
    )


@app.route('/admin/user/block/<int:user_id>')
@login_required
@admin_required
def block_user(user_id):
    db = get_db()
    db.execute('UPDATE users SET is_blocked=1 WHERE id=?', (user_id,))
    db.commit()
    flash('사용자가 차단되었습니다.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/unblock/<int:user_id>')
@login_required
@admin_required
def unblock_user(user_id):
    db = get_db()
    db.execute('UPDATE users SET is_blocked=0 WHERE id=?', (user_id,))
    db.commit()
    flash('차단이 해제되었습니다.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/post/block/<int:post_id>')
@login_required
@admin_required
def block_post(post_id):
    db = get_db()
    db.execute('UPDATE posts SET is_blocked=1 WHERE id=?', (post_id,))
    db.commit()
    flash('상품이 차단되었습니다.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/post/unblock/<int:post_id>')
@login_required
@admin_required
def unblock_post(post_id):
    db = get_db()
    db.execute('UPDATE posts SET is_blocked=0 WHERE id=?', (post_id,))
    db.commit()
    flash('차단이 해제되었습니다.')
    return redirect(url_for('admin_dashboard'))
# 사용자 탈퇴
@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    db = get_db()
    # 본인 또는 또 다른 관리자 삭제 방지 로직 추가 가능
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash(f'사용자 {user_id}를 탈퇴 처리했습니다.')
    return redirect(url_for('admin_dashboard'))

# 잔액 업데이트
@app.route('/admin/user/update_balance/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def update_balance(user_id):
    new_bal = request.form.get('balance', type=float)
    if new_bal is None or new_bal < 0:
        flash('유효한 잔액을 입력해주세요.')
    else:
        db = get_db()
        db.execute('UPDATE users SET balance = ? WHERE id = ?', (new_bal, user_id))
        db.commit()
        flash(f'사용자 {user_id} 잔액을 ₩{new_bal:,.2f}로 업데이트했습니다.')
    return redirect(url_for('admin_dashboard'))

# ─── 게시글 삭제 (관리자) ───────────────────────────────
@app.route('/admin/post/delete/<int:post_id>')
@login_required
@admin_required
def delete_post(post_id):
    db = get_db()
    db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    db.commit()
    flash('게시글이 삭제되었습니다.')
    return redirect(url_for('admin_dashboard'))

# 사용자 검색 페이지
@app.route('/users')
def user_search():
    q = request.args.get('q', '').strip()
    db = get_db()

    users = []
    if q:
        like = f'%{q}%'
        rows = db.execute('''
            SELECT id, username, is_blocked, balance
              FROM users
             WHERE username LIKE ?
             ORDER BY username
        ''', (like,)).fetchall()
        users = [dict(r) for r in rows]

    return render_template('user_search.html', users=users, q=q)

# ─── 마이페이지 & 프로필 조회 ─────────────────────────
@app.route('/user/<username>', methods=('GET','POST'))
@login_required
def user_page(username):
    db = get_db()
    # 1) 프로필 주인
    user = db.execute(
        'SELECT id, username, intro FROM users WHERE username = ?',
        (username,)
    ).fetchone()
    if not user:
        abort(404)

    # 2) 내가 프로필의 주인이라면 폼 처리
    if request.method == 'POST' and current_user.username == username:
        # 소개글 업데이트
        if 'intro' in request.form:
            new_intro = request.form['intro'].strip()
            db.execute(
                'UPDATE users SET intro = ? WHERE username = ?',
                (new_intro, username)
            )
            db.commit()
            flash('소개글이 업데이트되었습니다.')
            return redirect(url_for('user_page', username=username))

        # 비밀번호 변경
        if 'old_pw' in request.form:
            old_pw = request.form['old_pw']
            new_pw = request.form['new_pw']
            if not current_user.check_password(old_pw):
                flash('현재 비밀번호가 틀립니다.')
            elif not new_pw:
                flash('새 비밀번호를 입력하세요.')
            else:
                db.execute(
                    'UPDATE users SET pw_hash = ? WHERE id = ?',
                    (generate_password_hash(new_pw), current_user.id)
                )
                db.commit()
                flash('비밀번호가 변경되었습니다.')
            return redirect(url_for('user_page', username=username))

    # 3) 게시글·댓글 목록 조회
    posts = db.execute(
        'SELECT id, title, created_at FROM posts WHERE user_id = ? ORDER BY created_at DESC',
        (user['id'],)
    ).fetchall()
    comments = db.execute(
        'SELECT c.id, c.body, c.created_at, p.title AS post_title, p.id AS post_id '
        'FROM comments c '
        'JOIN posts p ON c.post_id = p.id '
        'WHERE c.user_id = ? '
        'ORDER BY c.created_at DESC',
        (user['id'],)
    ).fetchall()
    rows = db.execute(
        '''SELECT r.id AS room_id,
                  CASE WHEN r.user_a = ? THEN r.user_b ELSE r.user_a END AS other_id
           FROM rooms r
          WHERE r.user_a = ? OR r.user_b = ?''',
        (current_user.id, current_user.id, current_user.id)
    ).fetchall()
    chats = []
    for r in rows:
        other = db.execute(
            'SELECT username FROM users WHERE id = ?',
            (r['other_id'],)
        ).fetchone()
        chats.append({'room_id': r['room_id'], 'other_username': other['username']})

    return render_template(
        'user_page.html',
        profile=user,
        posts=posts,
        comments=comments,
         chats=chats 
    )
# ─── 1:1 채팅 페이지 라우트 ───────────────────────────
@app.route('/chat/<username>')
@login_required
def private_chat(username):
    db = get_db()
    other_row = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if not other_row:
        abort(404)
    other_id = other_row['id']
    a, b = sorted((current_user.id, other_id))
    room_row = db.execute('SELECT id FROM rooms WHERE user_a=? AND user_b=?', (a, b)).fetchone()
    if room_row:
        room_id = room_row['id']
    else:
        db.execute('INSERT INTO rooms(user_a, user_b) VALUES (?,?)', (a, b))
        db.commit()
        room_id = db.execute('SELECT id FROM rooms WHERE user_a=? AND user_b=?', (a, b)).fetchone()['id']
    rows = db.execute(
        'SELECT sender_id, content, timestamp FROM messages WHERE room_id=? ORDER BY timestamp ASC',
        (room_id,)
    ).fetchall()
    messages = [dict(r) for r in rows]
    return render_template('chat.html', other=username, room_id=room_id, messages=messages)

# ─── AJAX용 메시지 조회 ─────────────────────────────────
@app.route('/chat/<username>/messages')
@login_required
def chat_messages(username):
    db = get_db()
    other_row = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if not other_row:
        abort(404)
    a, b = sorted((current_user.id, other_row['id']))
    room_row = db.execute('SELECT id FROM rooms WHERE user_a=? AND user_b=?', (a, b)).fetchone()
    room_id = room_row['id'] if room_row else None
    rows = db.execute(
        'SELECT sender_id, content, timestamp FROM messages WHERE room_id=? ORDER BY timestamp ASC',
        (room_id,)
    ).fetchall()
    return jsonify(messages=[dict(r) for r in rows])

# ─── AJAX용 메시지 전송 ─────────────────────────────────
@app.route('/chat/<username>/message', methods=['POST'])
@login_required
@limiter.limit("10 per second")
def post_chat_message(username):
    data = request.get_json() or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify(error='Empty content'), 400
    db = get_db()
    other_row = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if not other_row:
        abort(404)
    a, b = sorted((current_user.id, other_row['id']))
    room_row = db.execute('SELECT id FROM rooms WHERE user_a=? AND user_b=?', (a, b)).fetchone()
    if not room_row:
        db.execute('INSERT INTO rooms(user_a, user_b) VALUES (?,?)', (a, b))
        db.commit()
        room_row = db.execute('SELECT id FROM rooms WHERE user_a=? AND user_b=?', (a, b)).fetchone()
    room_id = room_row['id']
    db.execute(
        'INSERT INTO messages(room_id, sender_id, content) VALUES (?,?,?)',
        (room_id, current_user.id, content)
    )
    db.commit()
    return jsonify(success=True)

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

@socketio.on('global message')
def handle_global_message(msg):
    user = current_user.username if current_user.is_authenticated else '익명'
    emit('global message', {'user': user, 'msg': msg}, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True)
