from __future__ import annotations
import os

import sqlite3
import base64
from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.environ.get("DATA_DIR", "."), "app.db")
TZ = ZoneInfo("America/Sao_Paulo")

app = Flask(__name__)
app.secret_key = "TROQUE-ISSO-POR-UMA-CHAVE-BEM-GRANDE"

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


# ---------------- DB helpers ----------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------- Time window rule ----------------
def is_closed_now(now: datetime | None = None) -> tuple[bool, str]:
    """
    Closed on Wednesday and Saturday from 19:00 to 23:00 (inclusive start, exclusive end).
    """
    if now is None:
        now = datetime.now(TZ)

    weekday = now.weekday()  # Mon=0 ... Sun=6
    current_t = now.time()

    start = time(19, 0)
    end = time(23, 0)

    is_wed = (weekday == 2)
    is_sat = (weekday == 5)

    if (is_wed or is_sat) and (start <= current_t < end):
        day_name = "quarta-feira" if is_wed else "sábado"
        return True, f"Jogo fechado agora ({day_name} 19:00–23:00). Volta a abrir às 23:00."
    return False, ""


def current_round_key(now: datetime | None = None) -> str:
    """
    Define o 'ciclo' atual pelo último reset (quarta ou sábado às 23:00).
    """
    if now is None:
        now = datetime.now(TZ)

    candidates: list[datetime] = []
    for back in range(0, 9):
        d = now.date().fromordinal(now.date().toordinal() - back)
        wd = datetime(d.year, d.month, d.day, tzinfo=TZ).weekday()
        if wd in (2, 5):  # Wed or Sat
            dt = datetime(d.year, d.month, d.day, 23, 0, 0, tzinfo=TZ)
            if dt <= now:
                candidates.append(dt)

    last_reset = max(candidates) if candidates else now.replace(hour=0, minute=0, second=0, microsecond=0)
    return last_reset.isoformat(timespec="seconds")


def round_label_from_key(round_key: str) -> str:
    """
    Converte round_key em label:
      - Se começou na quarta 23:00 -> "Sorteio de sábado dd-mm-aa" (fecha sábado 19:00)
      - Se começou no sábado 23:00 -> "Sorteio de quarta dd-mm-aa" (fecha quarta 19:00)
    """
    try:
        start = datetime.fromisoformat(round_key).astimezone(TZ)
    except Exception:
        return f"Ciclo ({round_key})"

    if start.weekday() == 2:  # Wed start
        close_day = start.date() + timedelta(days=(5 - start.weekday()))
        close_dt = datetime(close_day.year, close_day.month, close_day.day, 19, 0, 0, tzinfo=TZ)
        return f"Sorteio de sábado {close_dt.strftime('%d-%m-%y')}"
    if start.weekday() == 5:  # Sat start
        close_day = start.date() + timedelta(days=4)  # sat -> wed
        close_dt = datetime(close_day.year, close_day.month, close_day.day, 19, 0, 0, tzinfo=TZ)
        return f"Sorteio de quarta {close_dt.strftime('%d-%m-%y')}"

    return f"Ciclo {start.strftime('%d-%m-%y')}"


# --------- round_key safe for URL ----------
def encode_round_key(round_key: str) -> str:
    b = round_key.encode("utf-8")
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def decode_round_key(encoded: str) -> str:
    pad = "=" * (-len(encoded) % 4)
    b = base64.urlsafe_b64decode((encoded + pad).encode("ascii"))
    return b.decode("utf-8")


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS picks_v2 (
            user_id INTEGER NOT NULL,
            round_key TEXT NOT NULL,
            number INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (user_id, round_key, number),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Migra tabela antiga "picks" se existir
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='picks'")
    has_old = cur.fetchone() is not None

    if has_old:
        cols = [r["name"] for r in cur.execute("PRAGMA table_info(picks)").fetchall()]
        rk = current_round_key()
        now_iso = datetime.now(TZ).isoformat(timespec="seconds")
        if "round_key" not in cols:
            cur.execute("""
                INSERT OR IGNORE INTO picks_v2 (user_id, round_key, number, created_at)
                SELECT user_id, ?, number, ? FROM picks
            """, (rk, now_iso))
            cur.execute("ALTER TABLE picks RENAME TO picks_old")
        else:
            cur.execute("""
                INSERT OR IGNORE INTO picks_v2 (user_id, round_key, number, created_at)
                SELECT user_id, round_key, number, COALESCE(created_at, ?) FROM picks
            """, (now_iso,))
            cur.execute("ALTER TABLE picks RENAME TO picks_old")

    conn.commit()
    conn.close()


init_db()


# ---------------- Auth ----------------
class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self.password_hash = row["password_hash"]


@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return User(row) if row else None


@app.route("/setup_create_user", methods=["POST"])
def setup_create_user():
    """
    Endpoint simples pra criar usuário.
    IMPORTANTE: quando hospedar em produção, remova ou proteja isso.
    """
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if not username or not password:
        return "username e password obrigatórios", 400

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password))
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return "Esse username já existe", 400

    conn.close()
    return "Usuário criado com sucesso!", 200


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if not row:
            flash("Usuário não encontrado.")
            return redirect(url_for("login"))

        user = User(row)
        if not check_password_hash(user.password_hash, password):
            flash("Senha incorreta.")
            return redirect(url_for("login"))

        login_user(user)
        return redirect(url_for("home"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ---------------- Picks UI ----------------
@app.route("/")
@login_required
def home():
    closed, msg = is_closed_now()
    rk = current_round_key()
    label = round_label_from_key(rk)

    conn = get_db()
    rows = conn.execute(
        "SELECT number FROM picks_v2 WHERE user_id = ? AND round_key = ? ORDER BY number",
        (current_user.id, rk)
    ).fetchall()
    conn.close()

    picked_set = set(r["number"] for r in rows)
    picked_list = sorted(picked_set)
    picked_strs = [f"{n:03d}" for n in picked_list]

    return render_template(
        "home.html",
        picked=picked_set,
        picked_strs=picked_strs,
        picked_count=len(picked_list),
        closed=closed,
        closed_msg=msg,
        round_label=label
    )


@app.route("/toggle", methods=["POST"])
@login_required
def toggle():
    closed, msg = is_closed_now()
    if closed:
        return jsonify({"ok": False, "error": msg}), 403

    data = request.get_json(silent=True) or {}
    n = data.get("number")

    try:
        n = int(n)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "Número inválido"}), 400

    if n < 0 or n > 999:
        return jsonify({"ok": False, "error": "Número fora do range 000–999"}), 400

    rk = current_round_key()
    now_iso = datetime.now(TZ).isoformat(timespec="seconds")

    conn = get_db()
    cur = conn.cursor()

    exists = cur.execute(
        "SELECT 1 FROM picks_v2 WHERE user_id = ? AND round_key = ? AND number = ?",
        (current_user.id, rk, n)
    ).fetchone()

    if exists:
        cur.execute(
            "DELETE FROM picks_v2 WHERE user_id = ? AND round_key = ? AND number = ?",
            (current_user.id, rk, n)
        )
        conn.commit()
    else:
        cur.execute(
            "INSERT INTO picks_v2 (user_id, round_key, number, created_at) VALUES (?, ?, ?, ?)",
            (current_user.id, rk, n, now_iso)
        )
        conn.commit()

    rows = cur.execute(
        "SELECT number FROM picks_v2 WHERE user_id = ? AND round_key = ? ORDER BY number",
        (current_user.id, rk)
    ).fetchall()
    conn.close()

    nums = [f"{r['number']:03d}" for r in rows]
    return jsonify({"ok": True, "picked": (not bool(exists)), "numbers": nums, "count": len(nums)})


@app.route("/confirm")
@login_required
def confirm():
    rk = current_round_key()
    label = round_label_from_key(rk)

    conn = get_db()
    rows = conn.execute(
        "SELECT number FROM picks_v2 WHERE user_id = ? AND round_key = ? ORDER BY number",
        (current_user.id, rk)
    ).fetchall()
    conn.close()

    nums = [f"{r['number']:03d}" for r in rows]
    return {"round": label, "username": current_user.username, "count": len(nums), "numbers": nums}


@app.route("/history")
@login_required
def history():
    conn = get_db()
    rounds = conn.execute(
        """
        SELECT round_key, COUNT(*) as cnt
        FROM picks_v2
        WHERE user_id = ?
        GROUP BY round_key
        ORDER BY round_key DESC
        """,
        (current_user.id,)
    ).fetchall()
    conn.close()

    items = []
    for r in rounds:
        rk = r["round_key"]
        items.append({
            "id": encode_round_key(rk),
            "label": round_label_from_key(rk),
            "count": int(r["cnt"])
        })

    return render_template("history.html", items=items)


@app.route("/history/view/<round_id>")
@login_required
def history_view(round_id: str):
    try:
        rk = decode_round_key(round_id)
    except Exception:
        abort(404)

    conn = get_db()
    exists = conn.execute(
        "SELECT 1 FROM picks_v2 WHERE user_id = ? AND round_key = ? LIMIT 1",
        (current_user.id, rk)
    ).fetchone()

    # Se não existe nenhum número naquele ciclo (ou não é dele), ainda pode existir um ciclo vazio,
    # então não vamos 404: vamos apenas mostrar vazio se for ciclo do histórico.
    # Mas se o round_id for inválido, aborta antes.
    rows = conn.execute(
        "SELECT number FROM picks_v2 WHERE user_id = ? AND round_key = ? ORDER BY number",
        (current_user.id, rk)
    ).fetchall()
    conn.close()

    nums_int = [int(x["number"]) for x in rows]
    nums_str = [f"{n:03d}" for n in nums_int]
    label = round_label_from_key(rk)

    # Só permite editar (apagar) se:
    # - NÃO estiver no período fechado agora
    # - e o ciclo for o ciclo ATUAL (ou seja, ainda está "valendo")
    closed, _ = is_closed_now()
    can_edit = (not closed) and (rk == current_round_key())

    return render_template(
        "history_view.html",
        label=label,
        count=len(nums_str),
        nums_str=nums_str,
        round_id=round_id,
        can_edit=can_edit
    )


@app.route("/history/remove/<round_id>", methods=["POST"])
@login_required
def history_remove(round_id: str):
    # Só deixa remover no ciclo atual e fora do horário fechado
    closed, msg = is_closed_now()
    if closed:
        return jsonify({"ok": False, "error": msg}), 403

    try:
        rk = decode_round_key(round_id)
    except Exception:
        return jsonify({"ok": False, "error": "round inválido"}), 400

    if rk != current_round_key():
        return jsonify({"ok": False, "error": "Esse histórico já está fechado (somente leitura)."}), 403

    data = request.get_json(silent=True) or {}
    n = data.get("number")

    try:
        n = int(n)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "Número inválido"}), 400

    if n < 0 or n > 999:
        return jsonify({"ok": False, "error": "Número fora do range 000–999"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM picks_v2 WHERE user_id = ? AND round_key = ? AND number = ?",
        (current_user.id, rk, n)
    )
    conn.commit()

    rows = cur.execute(
        "SELECT number FROM picks_v2 WHERE user_id = ? AND round_key = ? ORDER BY number",
        (current_user.id, rk)
    ).fetchall()
    conn.close()

    nums = [f"{r['number']:03d}" for r in rows]
    return jsonify({"ok": True, "numbers": nums, "count": len(nums)})


if __name__ == "__main__":
    app.run(debug=True)
