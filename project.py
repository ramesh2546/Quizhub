"""
Online Quiz and Result Management System
----------------------------------------
Pure Python (standard library only): http.server + sqlite3.

Run:   python app.py
Open:  http://localhost:8000
Admin: username "admin", password "admin123"  (change after first login!)
"""
import csv
import hashlib
import hmac
import html
import io
import re
import secrets
import sqlite3
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DB_FILE = "quiz.db"
PORT = 8000
HOST_NAME = "quiz-making"
ADMIN_USER = "Anits"
ADMIN_PASS = "Anits123"
SESSIONS = {}

esc = html.escape


# ----------------------------------------------------------------- database
def connect():
    con = sqlite3.connect(DB_FILE)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def query(sql, args=(), one=False):
    con = connect()
    try:
        rows = con.execute(sql, args).fetchall()
    finally:
        con.close()
    if one:
        return rows[0] if rows else None
    return rows


def execute(sql, args=()):
    con = connect()
    try:
        cur = con.execute(sql, args)
        con.commit()
        return cur.lastrowid
    finally:
        con.close()


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()


def create_user(username, password, role="student"):
    salt = secrets.token_hex(8)
    return execute(
        "INSERT INTO users(username, password, salt, role) VALUES (?,?,?,?)",
        (username, hash_password(password, salt), salt, role),
    )


def ensure_admin():
    """Create the admin account, or update the existing one to ADMIN_USER / ADMIN_PASS."""
    row = query("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1", one=True)
    if row is None:
        create_user(ADMIN_USER, ADMIN_PASS, "admin")
        return
    salt = secrets.token_hex(8)
    try:
        execute(
            "UPDATE users SET username=?, password=?, salt=? WHERE id=?",
            (ADMIN_USER, hash_password(ADMIN_PASS, salt), salt, row["id"]),
        )
    except sqlite3.IntegrityError:
        print(f"Could not rename admin: a student already uses the username '{ADMIN_USER}'.")


def init_db():
    con = connect()
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student');
        CREATE TABLE IF NOT EXISTS quizzes(
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS questions(
            id INTEGER PRIMARY KEY,
            quiz_id INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
            text TEXT NOT NULL,
            a TEXT NOT NULL, b TEXT NOT NULL, c TEXT NOT NULL, d TEXT NOT NULL,
            correct TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS results(
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            quiz_id INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
            score INTEGER NOT NULL,
            total INTEGER NOT NULL,
            taken_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        """
    )
    con.commit()
    has_admin = con.execute("SELECT 1 FROM users WHERE role='admin'").fetchone()
    has_quiz = con.execute("SELECT 1 FROM quizzes").fetchone()
    con.close()

    ensure_admin()
    if not has_quiz:
        qid = execute("INSERT INTO quizzes(title) VALUES (?)", ("Python Basics",))
        sample = [
            ("Which keyword defines a function in Python?", "func", "def", "function", "lambda", "b"),
            ("What is the output of len([1, 2, 3])?", "2", "3", "4", "Error", "b"),
            ("Which data type is immutable?", "list", "dict", "tuple", "set", "c"),
            ("Which symbol starts a comment in Python?", "//", "#", "/*", "--", "b"),
            ("What does 'pip' stand for?", "Pip Installs Packages", "Python Install Program",
             "Package Install Python", "None of these", "a"),
        ]
        for s in sample:
            execute(
                "INSERT INTO questions(quiz_id,text,a,b,c,d,correct) VALUES (?,?,?,?,?,?,?)",
                (qid, *s),
            )


# -------------------------------------------------------------------- views
CSS = """
body{font-family:system-ui,Arial,sans-serif;background:#f4f6fb;margin:0;color:#222}
nav{background:#2d3a8c;color:#fff;padding:12px 24px;display:flex;gap:16px;align-items:center}
nav a{color:#fff;text-decoration:none} nav .sp{flex:1}
main{max-width:860px;margin:24px auto;padding:0 16px}
.card{background:#fff;border-radius:10px;padding:20px;margin-bottom:16px;box-shadow:0 1px 4px #0001}
table{width:100%;border-collapse:collapse} th,td{padding:8px;border-bottom:1px solid #e5e7ee;text-align:left}
input[type=text],input[type=password]{width:100%;padding:8px;margin:4px 0 12px;box-sizing:border-box}
button,.btn{background:#2d3a8c;color:#fff;border:0;border-radius:6px;padding:8px 16px;cursor:pointer;text-decoration:none;display:inline-block}
button.danger{background:#b3261e}
.ok{color:#1b7f3b;font-weight:600}.bad{color:#b3261e;font-weight:600}
.err{background:#fde7e7;color:#b3261e;padding:10px;border-radius:6px;margin-bottom:12px}
label.opt{display:block;padding:4px 0}
"""


def page(title, body, user=None):
    nav = "<a href='/'><b>QuizHub</b></a>"
    if user:
        if user["role"] == "admin":
            nav += "<a href='/admin'>Manage quizzes</a><a href='/admin/results'>All results</a>"
        nav += f"<span class='sp'></span><span>{esc(user['username'])} ({user['role']})</span>"
        nav += "<a href='/logout'>Logout</a>"
    return f"""<!doctype html><html><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>{esc(title)}</title><style>{CSS}</style></head>
<body><nav>{nav}</nav><main>{body}</main></body></html>"""


def auth_form(kind, error=""):
    title = "Login" if kind == "login" else "Register"
    alt = (
        "<p>No account? <a href='/register'>Register</a></p>"
        if kind == "login"
        else "<p>Have an account? <a href='/login'>Login</a></p>"
    )
    err = f"<div class='err'>{esc(error)}</div>" if error else ""
    return f"""<div class='card'><h2>{title}</h2>{err}
<form method='post'>
<label>Username</label><input type='text' name='username' required>
<label>Password</label><input type='password' name='password' required>
<button>{title}</button></form>{alt}</div>"""


def student_home(user):
    quizzes = query(
        "SELECT q.id, q.title, (SELECT COUNT(*) FROM questions WHERE quiz_id=q.id) AS n "
        "FROM quizzes q ORDER BY q.id"
    )
    rows = "".join(
        f"<tr><td>{esc(q['title'])}</td><td>{q['n']}</td>"
        f"<td><a class='btn' href='/quiz/{q['id']}'>Start</a></td></tr>"
        for q in quizzes
        if q["n"] > 0
    ) or "<tr><td colspan=3>No quizzes available yet.</td></tr>"
    history = query(
        "SELECT r.score, r.total, r.taken_at, q.title FROM results r "
        "JOIN quizzes q ON q.id=r.quiz_id WHERE r.user_id=? ORDER BY r.id DESC",
        (user["id"],),
    )
    hrows = "".join(
        f"<tr><td>{esc(h['title'])}</td><td>{h['score']}/{h['total']}</td>"
        f"<td>{h['score'] * 100 // h['total']}%</td><td>{h['taken_at']}</td></tr>"
        for h in history
    ) or "<tr><td colspan=4>You haven't taken any quiz yet.</td></tr>"
    return f"""<div class='card'><h2>Available quizzes</h2>
<table><tr><th>Quiz</th><th>Questions</th><th></th></tr>{rows}</table></div>
<div class='card'><h2>My results</h2>
<table><tr><th>Quiz</th><th>Score</th><th>Percent</th><th>Date (UTC)</th></tr>{hrows}</table></div>"""


def quiz_page(quiz, questions):
    blocks = ""
    for i, q in enumerate(questions, 1):
        opts = "".join(
            f"<label class='opt'><input type='radio' name='q{q['id']}' value='{k}' required> "
            f"{esc(q[k])}</label>"
            for k in "abcd"
        )
        blocks += f"<div class='card'><b>Q{i}. {esc(q['text'])}</b>{opts}</div>"
    return f"<h2>{esc(quiz['title'])}</h2><form method='post'>{blocks}<button>Submit quiz</button></form>"


def result_page(quiz, questions, answers, score):
    total = len(questions)
    pct = score * 100 // total
    review = ""
    for i, q in enumerate(questions, 1):
        given = answers.get(q["id"])
        good = given == q["correct"]
        mark = "<span class='ok'>Correct</span>" if good else "<span class='bad'>Wrong</span>"
        given_txt = esc(q[given]) if given else "Not answered"
        review += (
            f"<tr><td>{i}. {esc(q['text'])}</td><td>{given_txt}</td>"
            f"<td>{esc(q[q['correct']])}</td><td>{mark}</td></tr>"
        )
    return f"""<div class='card'><h2>{esc(quiz['title'])} - Result</h2>
<h1>{score} / {total} ({pct}%)</h1>
<p>{'Great job!' if pct >= 60 else 'Keep practising, you can do better!'}</p>
<a class='btn' href='/'>Back to dashboard</a></div>
<div class='card'><h3>Answer review</h3>
<table><tr><th>Question</th><th>Your answer</th><th>Correct answer</th><th></th></tr>{review}</table></div>"""


def admin_home():
    quizzes = query(
        "SELECT q.id, q.title, (SELECT COUNT(*) FROM questions WHERE quiz_id=q.id) AS n, "
        "(SELECT COUNT(*) FROM results WHERE quiz_id=q.id) AS taken FROM quizzes q ORDER BY q.id"
    )
    rows = "".join(
        f"<tr><td>{esc(q['title'])}</td><td>{q['n']}</td><td>{q['taken']}</td>"
        f"<td><a class='btn' href='/admin/quiz/{q['id']}'>Edit</a> "
        f"<form method='post' action='/admin/quiz/{q['id']}/delete' style='display:inline' "
        f"onsubmit=\"return confirm('Delete this quiz and its results?')\">"
        f"<button class='danger'>Delete</button></form></td></tr>"
        for q in quizzes
    ) or "<tr><td colspan=4>No quizzes yet.</td></tr>"
    return f"""<div class='card'><h2>Quizzes</h2>
<table><tr><th>Title</th><th>Questions</th><th>Attempts</th><th></th></tr>{rows}</table></div>
<div class='card'><h3>Create a quiz</h3><form method='post' action='/admin/quiz/add'>
<input type='text' name='title' placeholder='Quiz title' required><button>Create</button></form></div>"""


def admin_quiz(quiz):
    qs = query("SELECT * FROM questions WHERE quiz_id=? ORDER BY id", (quiz["id"],))
    rows = "".join(
        f"<tr><td>{esc(q['text'])}<br><small>A) {esc(q['a'])} | B) {esc(q['b'])} | "
        f"C) {esc(q['c'])} | D) {esc(q['d'])}</small></td><td>{q['correct'].upper()}</td>"
        f"<td><form method='post' action='/admin/question/{q['id']}/delete'>"
        f"<button class='danger'>Delete</button></form></td></tr>"
        for q in qs
    ) or "<tr><td colspan=3>No questions yet.</td></tr>"
    return f"""<div class='card'><h2>{esc(quiz['title'])}</h2>
<table><tr><th>Question</th><th>Answer</th><th></th></tr>{rows}</table></div>
<div class='card'><h3>Add a question</h3>
<form method='post' action='/admin/quiz/{quiz['id']}/question'>
<input type='text' name='text' placeholder='Question' required>
<input type='text' name='a' placeholder='Option A' required>
<input type='text' name='b' placeholder='Option B' required>
<input type='text' name='c' placeholder='Option C' required>
<input type='text' name='d' placeholder='Option D' required>
<label>Correct option</label>
<select name='correct'><option value='a'>A</option><option value='b'>B</option>
<option value='c'>C</option><option value='d'>D</option></select>
<p><button>Add question</button></p></form></div>"""


RESULTS_SQL = (
    "SELECT u.username, q.title, r.score, r.total, r.taken_at FROM results r "
    "JOIN users u ON u.id=r.user_id JOIN quizzes q ON q.id=r.quiz_id "
    "{where} ORDER BY r.id DESC"
)


def admin_results(search):
    if search:
        rows = query(RESULTS_SQL.format(where="WHERE u.username LIKE ? OR q.title LIKE ?"),
                     (f"%{search}%", f"%{search}%"))
    else:
        rows = query(RESULTS_SQL.format(where=""))
    trs = "".join(
        f"<tr><td>{esc(r['username'])}</td><td>{esc(r['title'])}</td>"
        f"<td>{r['score']}/{r['total']}</td><td>{r['score'] * 100 // r['total']}%</td>"
        f"<td>{r['taken_at']}</td></tr>"
        for r in rows
    ) or "<tr><td colspan=5>No results found.</td></tr>"
    stats = ""
    if rows:
        avg = sum(r["score"] * 100 / r["total"] for r in rows) / len(rows)
        stats = f"<p>Attempts: <b>{len(rows)}</b> &nbsp; Average: <b>{avg:.1f}%</b></p>"
    return f"""<div class='card'><h2>All results</h2>
<form method='get'><input type='text' name='search' placeholder='Search student or quiz'
value='{esc(search)}'><button>Search</button>
<a class='btn' href='/admin/results.csv'>Export CSV</a></form>{stats}
<table><tr><th>Student</th><th>Quiz</th><th>Score</th><th>Percent</th><th>Date (UTC)</th></tr>
{trs}</table></div>"""


# ------------------------------------------------------------------ handler
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # keep the console quiet

    # ---- helpers
    def user(self):
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        sid = jar["sid"].value if "sid" in jar else None
        uid = SESSIONS.get(sid)
        if uid is None:
            return None
        return query("SELECT * FROM users WHERE id=?", (uid,), one=True)

    def form(self):
        length = int(self.headers.get("Content-Length") or 0)
        data = parse_qs(self.rfile.read(length).decode(), keep_blank_values=True)
        return {k: v[0].strip() for k, v in data.items()}

    def send(self, body, status=200, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, where, extra=None):
        self.send_response(303)
        self.send_header("Location", where)
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()

    def need_login(self, admin=False):
        u = self.user()
        if not u:
            self.redirect("/login")
            return None
        if admin and u["role"] != "admin":
            self.send(page("Forbidden", "<div class='card'><h2>403 - Admins only</h2></div>", u), 403)
            return None
        return u

    def not_found(self):
        self.send(page("Not found", "<div class='card'><h2>404 - Page not found</h2></div>", self.user()), 404)

    # ---- routing
    def do_GET(self):
        url = urlparse(self.path)
        path, qs = url.path, parse_qs(url.query)

        if path == "/":
            u = self.need_login()
            if u:
                if u["role"] == "admin":
                    return self.redirect("/admin")
                self.send(page("Dashboard", student_home(u), u))
        elif path == "/login":
            self.send(page("Login", auth_form("login")))
        elif path == "/register":
            self.send(page("Register", auth_form("register")))
        elif path == "/logout":
            jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            if "sid" in jar:
                SESSIONS.pop(jar["sid"].value, None)
            self.redirect("/login", [("Set-Cookie", "sid=; Max-Age=0; Path=/")])
        elif m := re.fullmatch(r"/quiz/(\d+)", path):
            u = self.need_login()
            if u:
                quiz = query("SELECT * FROM quizzes WHERE id=?", (m[1],), one=True)
                qs_ = query("SELECT * FROM questions WHERE quiz_id=? ORDER BY id", (m[1],))
                if not quiz or not qs_:
                    return self.not_found()
                self.send(page(quiz["title"], quiz_page(quiz, qs_), u))
        elif path == "/admin":
            u = self.need_login(admin=True)
            if u:
                self.send(page("Admin", admin_home(), u))
        elif m := re.fullmatch(r"/admin/quiz/(\d+)", path):
            u = self.need_login(admin=True)
            if u:
                quiz = query("SELECT * FROM quizzes WHERE id=?", (m[1],), one=True)
                if not quiz:
                    return self.not_found()
                self.send(page("Edit quiz", admin_quiz(quiz), u))
        elif path == "/admin/results":
            u = self.need_login(admin=True)
            if u:
                search = qs.get("search", [""])[0].strip()
                self.send(page("Results", admin_results(search), u))
        elif path == "/admin/results.csv":
            u = self.need_login(admin=True)
            if u:
                buf = io.StringIO()
                w = csv.writer(buf)
                w.writerow(["student", "quiz", "score", "total", "percent", "taken_at_utc"])
                for r in query(RESULTS_SQL.format(where="")):
                    w.writerow([r["username"], r["title"], r["score"], r["total"],
                                r["score"] * 100 // r["total"], r["taken_at"]])
                self.send(buf.getvalue(), ctype="text/csv",
                          extra=[("Content-Disposition", "attachment; filename=results.csv")])
        else:
            self.not_found()

    def do_POST(self):
        path = urlparse(self.path).path
        f = self.form()

        if path == "/login":
            row = query("SELECT * FROM users WHERE username=?", (f.get("username", ""),), one=True)
            if row and hmac.compare_digest(
                row["password"], hash_password(f.get("password", ""), row["salt"])
            ):
                sid = secrets.token_hex(16)
                SESSIONS[sid] = row["id"]
                return self.redirect("/", [("Set-Cookie", f"sid={sid}; HttpOnly; Path=/")])
            self.send(page("Login", auth_form("login", "Invalid username or password.")), 401)
        elif path == "/register":
            name, pw = f.get("username", ""), f.get("password", "")
            if not re.fullmatch(r"\w{3,20}", name):
                err = "Username must be 3-20 letters, digits or underscores."
            elif len(pw) < 6:
                err = "Password must be at least 6 characters."
            elif query("SELECT 1 FROM users WHERE username=?", (name,), one=True):
                err = "That username is already taken."
            else:
                create_user(name, pw)
                return self.redirect("/login")
            self.send(page("Register", auth_form("register", err)), 400)
        elif m := re.fullmatch(r"/quiz/(\d+)", path):
            u = self.need_login()
            if not u:
                return
            quiz = query("SELECT * FROM quizzes WHERE id=?", (m[1],), one=True)
            qs_ = query("SELECT * FROM questions WHERE quiz_id=? ORDER BY id", (m[1],))
            if not quiz or not qs_:
                return self.not_found()
            answers = {q["id"]: f.get(f"q{q['id']}") for q in qs_}
            score = sum(1 for q in qs_ if answers[q["id"]] == q["correct"])
            execute("INSERT INTO results(user_id, quiz_id, score, total) VALUES (?,?,?,?)",
                    (u["id"], quiz["id"], score, len(qs_)))
            self.send(page("Result", result_page(quiz, qs_, answers, score), u))
        elif path == "/admin/quiz/add":
            if self.need_login(admin=True):
                if f.get("title"):
                    qid = execute("INSERT INTO quizzes(title) VALUES (?)", (f["title"],))
                    return self.redirect(f"/admin/quiz/{qid}")
                self.redirect("/admin")
        elif m := re.fullmatch(r"/admin/quiz/(\d+)/delete", path):
            if self.need_login(admin=True):
                execute("DELETE FROM quizzes WHERE id=?", (m[1],))
                self.redirect("/admin")
        elif m := re.fullmatch(r"/admin/quiz/(\d+)/question", path):
            if self.need_login(admin=True):
                needed = ("text", "a", "b", "c", "d", "correct")
                if all(f.get(k) for k in needed) and f["correct"] in "abcd":
                    execute(
                        "INSERT INTO questions(quiz_id,text,a,b,c,d,correct) VALUES (?,?,?,?,?,?,?)",
                        (m[1], *[f[k] for k in needed]),
                    )
                self.redirect(f"/admin/quiz/{m[1]}")
        elif m := re.fullmatch(r"/admin/question/(\d+)/delete", path):
            if self.need_login(admin=True):
                row = query("SELECT quiz_id FROM questions WHERE id=?", (m[1],), one=True)
                execute("DELETE FROM questions WHERE id=?", (m[1],))
                self.redirect(f"/admin/quiz/{row['quiz_id']}" if row else "/admin")
        else:
            self.not_found()


if __name__ == "__main__":
    init_db()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Quiz system running at http://{HOST_NAME}:{PORT}  (Ctrl+C to stop)")
    print(f"(also works at http://localhost:{PORT})")
    print(f"Admin login -> username: {ADMIN_USER} | password: {ADMIN_PASS}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")