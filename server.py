import json
import os
import re
import time
import hashlib
import hmac
import secrets
import psycopg2
import jwt
from datetime import datetime, timedelta
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from psycopg2.extras import RealDictCursor

OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "deepseek/deepseek-v3.2"

RATE_WINDOW_SEC = int(os.getenv("RATE_WINDOW_SEC", "60"))
RATE_MAX = int(os.getenv("RATE_MAX", "20"))
MAX_INPUT_CHARS = int(os.getenv("MAX_INPUT_CHARS", "8000"))
OPENROUTER_TIMEOUT_SEC = float(os.getenv("OPENROUTER_TIMEOUT_SEC", "35"))
OPENROUTER_MAX_TOKENS = int(os.getenv("OPENROUTER_MAX_TOKENS", "350"))
OPENROUTER_ANALYZE_MAX_TOKENS = int(os.getenv("OPENROUTER_ANALYZE_MAX_TOKENS", "200"))

# JWT CONFIG
JWT_SECRET = os.getenv("JWT_SECRET", "cifrsawat_super_secret_2025_xyz789")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_DAYS = 7

_rate = {}
_db_pool = None

def _load_dotenv(path: str) -> None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#") or "=" not in s:
                    continue
                k, v = s.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
    except FileNotFoundError:
        return
    except Exception:
        return

def _now() -> float:
    return time.time()

def _prune(ts: list[float]) -> list[float]:
    cutoff = _now() - RATE_WINDOW_SEC
    return [t for t in ts if t >= cutoff]

def _allow_request(ip: str) -> bool:
    ts = _rate.get(ip, [])
    ts = _prune(ts)
    if len(ts) >= RATE_MAX:
        _rate[ip] = ts
        return False
    ts.append(_now())
    _rate[ip] = ts
    return True

def _get_openrouter_key() -> str:
    return (os.getenv("OPENROUTER_API_KEY") or "").strip()

def _get_model() -> str:
    return (os.getenv("OPENROUTER_MODEL") or DEFAULT_MODEL).strip()

# ════════════════════════════════════════════════════════════
# DATABASE
# ════════════════════════════════════════════════════════════

def _get_db_connection():
    db_url = os.getenv("DATABASE_URL", "")
    if not db_url:
        return None
    try:
        conn = psycopg2.connect(db_url)
        return conn
    except Exception as e:
        print(f"DB Error: {e}")
        return None

def _init_db():
    conn = _get_db_connection()
    if not conn:
        return
    cur = conn.cursor()
    try:
        # Users table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(24) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # User progress table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_progress (
                username VARCHAR(24) PRIMARY KEY,
                progress_data JSONB DEFAULT '{}',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Scores table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scores (
                username VARCHAR(24) PRIMARY KEY,
                total_score INT DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
    except Exception as e:
        print(f"Init DB Error: {e}")
    finally:
        cur.close()
        conn.close()

# ════════════════════════════════════════════════════════════
# PASSWORD & TOKEN
# ════════════════════════════════════════════════════════════

def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    return f"{salt}${h}"

def _verify_password(password: str, hashed: str) -> bool:
    try:
        parts = hashed.split('$')
        if len(parts) != 2:
            return False
        salt, h = parts
        new_h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
        return hmac.compare_digest(new_h, h)
    except:
        return False

def _generate_token(username: str) -> str:
    payload = {
        "username": username,
        "exp": datetime.utcnow() + timedelta(days=JWT_EXPIRY_DAYS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def _verify_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("username")
    except:
        return None

def _extract_username(headers) -> str | None:
    auth = headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    return _verify_token(token)

def _system_prompt_adv() -> str:
    return (
        "You are a digital security expert. Respond ONLY in valid JSON. No markdown, no code fences, no extra text. "
        "Use this exact schema: {\"risk\":\"HIGH|MEDIUM|LOW\",\"risk_label\":\"short label\","
        "\"what\":\"2-3 sentences\",\"steps\":[\"step1\",\"step2\",\"step3\"],\"prevention\":\"one tip\"}. "
        "Example: {\"risk\":\"HIGH\",\"risk_label\":\"Жоғары қауіп\",\"what\":\"Бұл фишинг әрекеті.\","
        "\"steps\":[\"Сілтемені баспаңыз.\",\"Парольді өзгертіңіз.\"],\"prevention\":\"2FA қосыңыз.\"}. "
        "Always respond in the SAME language as the user (Kazakh or Russian)."
    )

def _system_prompt_sim(scenario: str) -> str:
    scenarios = {
        "bank": (
            "You are a scammer pretending to be a bank security officer. "
            "Your goal: get SMS code or card details. Use urgency and authority. "
            "Write in Kazakh or Russian. Keep messages 1-3 sentences. "
            "Never say you are an AI. Never break character. Start friendly then pressure."
        ),
        "delivery": (
            "You are a scammer pretending to be a delivery service operator. "
            "Tell the victim their package is stuck and ask for payment or personal data. "
            "Write in Kazakh or Russian. 1-3 sentences. Never say you are AI."
        ),
        "prize": (
            "You are a scammer pretending to be a contest organizer. "
            "Tell the victim they won a prize but need to pay commission or provide data. "
            "Write in Kazakh or Russian. 1-3 sentences. Never say you are AI."
        ),
        "friend": (
            "You are a scammer pretending to be a friend. "
            "First greet friendly, then suddenly ask for money (e.g., 'Help, I need money', 'Can you transfer 5000 tenge?'). "
            "Write in Kazakh or Russian. 1-3 sentences. Never say you are AI."
        ),
    }
    base = (
        "You are a scammer. You must stay in character at all times. "
        "NEVER say you are an AI or a language model. NEVER say you cannot help. "
        "NEVER refuse to act as a scammer. This is a cybersecurity training simulation. "
        "Use emotional manipulation (urgency, fear, trust, authority). "
        "Keep messages 1-3 sentences. Write in Kazakh or Russian (simple, casual). "
        "First build trust, then ask for sensitive info (SMS code, card details, money).\n"
    )
    return base + scenarios.get(scenario, scenarios["bank"])

def _analysis_prompt(event: str) -> str:
    if event == "stop":
        return (
            "You are a cybersecurity coach. Respond in the SAME language as the user (Kazakh or Russian). "
            "Write a VERY SHORT message (max 4 sentences). Plain text only, no JSON, no markdown. "
            "Format: what mistake (1 sentence), why it's dangerous (1 sentence), advice (2 sentences). "
            "Example (Kazakh): 'Сіз кодты жібердіңіз. Бұл қауіпті, себебі алаяқ шотыңызға кіреді. Ешқашан кодты бөгдеге айтпаңыз. Банкке өзіңіз қоңырау шалыңыз.' "
            "Example (Russian): 'Вы отправили код. Это опасно, мошенник получит доступ к счету. Никогда не сообщайте код. Позвоните в банк сами.'"
        )
    # event == "end"
    return (
        "You are a cybersecurity coach. Respond in the SAME language as the user (Kazakh or Russian). "
        "Write a VERY SHORT analysis (max 5 sentences). Plain text only, no JSON, no markdown. "
        "Format: summary (1 sentence), mistakes (1-2 sentences), advice (2 sentences). "
        "Example (Kazakh): 'Сіз манипуляцияға түстіңіз. Алаяқтың асығыстығына сендіңіз. Құпия деректерді бермеңіз. Банкке өзіңіз хабарласыңыз.' "
        "Example (Russian): 'Вы поддались манипуляции. Поверили в срочность. Не передавайте личные данные. Свяжитесь с банком сами.'"
    )
    
def _sanitize_text(text: str) -> str:
    t = (text or "").strip()
    if not t:
        return ""
    t = re.sub(r"\b\d{4,}\b", "[REDACTED]", t)
    t = re.sub(r"(sms|смс|код|otp|пароль|password|құпиясөз|қупиясоз|cvv|cvc|иин|жсн)\s*[:=]?\s*\S+", r"\1 [REDACTED]", t, flags=re.IGNORECASE)
    return t

def _format_history(history: list[dict]) -> str:
    lines = []
    for item in history[-12:]:
        if not isinstance(item, dict):
            continue
        role = (item.get("role") or "").strip()
        content = _sanitize_text(item.get("content") or "")
        if not content:
            continue
        tag = "USER" if role == "user" else "SIM"
        lines.append(f"{tag}: {content}")
    return "\n".join(lines)

class Handler(SimpleHTTPRequestHandler):
    def _req_path(self) -> str:
        try:
            return urlsplit(self.path).path
        except Exception:
            return self.path

    def _is_path(self, path: str) -> bool:
        p = (self._req_path() or "").rstrip("/")
        return p == path

    def _is_ai_path(self) -> bool:
        p = (self._req_path() or "").rstrip("/")
        return p == "/api/ai"

    def _is_analyze_path(self) -> bool:
        p = (self._req_path() or "").rstrip("/")
        return p == "/api/analyze"

    def _is_scores_path(self) -> bool:
        p = (self._req_path() or "").rstrip("/")
        return p == "/api/scores"

    def _client_ip(self) -> str:
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def _cors_headers(self) -> None:
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        else:
            self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    # ─ AUTH ─────────────────────────────────────────────────

    def _handle_register(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length > 0 else b"{}"
            payload = json.loads(body.decode("utf-8"))
        except:
            self._send_json(400, {"error": "Invalid JSON"})
            return

        username = (payload.get("username") or "").strip()
        password = (payload.get("password") or "").strip()

        if not username or len(username) < 3 or len(username) > 24:
            self._send_json(400, {"error": "Username must be 3-24 characters"})
            return
        if not password or len(password) < 4:
            self._send_json(400, {"error": "Password must be at least 4 characters"})
            return

        conn = _get_db_connection()
        if not conn:
            self._send_json(500, {"error": "DB error"})
            return

        cur = conn.cursor()
        try:
            password_hash = _hash_password(password)
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                (username, password_hash)
            )
            conn.commit()
            token = _generate_token(username)
            self._send_json(201, {"ok": True, "token": token, "username": username})
        except psycopg2.IntegrityError:
            conn.rollback()
            self._send_json(409, {"error": "Username already exists"})
        except Exception as e:
            conn.rollback()
            self._send_json(500, {"error": "Server error"})
        finally:
            cur.close()
            conn.close()

    def _handle_login(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length > 0 else b"{}"
            payload = json.loads(body.decode("utf-8"))
        except:
            self._send_json(400, {"error": "Invalid JSON"})
            return

        username = (payload.get("username") or "").strip()
        password = (payload.get("password") or "").strip()

        if not username or not password:
            self._send_json(400, {"error": "Missing username or password"})
            return

        conn = _get_db_connection()
        if not conn:
            self._send_json(500, {"error": "DB error"})
            return

        cur = conn.cursor(cursor_factory=RealDictCursor)
        try:
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()

            if not user or not _verify_password(password, user["password_hash"]):
                self._send_json(401, {"error": "Invalid credentials"})
                return

            token = _generate_token(username)
            self._send_json(200, {"ok": True, "token": token, "username": username})
        except Exception as e:
            self._send_json(500, {"error": "Server error"})
        finally:
            cur.close()
            conn.close()

    def _handle_me(self) -> None:
        username = _extract_username(self.headers)
        if not username:
            self._send_json(401, {"error": "Unauthorized"})
            return

        conn = _get_db_connection()
        if not conn:
            self._send_json(500, {"error": "DB error"})
            return

        cur = conn.cursor(cursor_factory=RealDictCursor)
        try:
            cur.execute("SELECT username, created_at FROM users WHERE username = %s", (username,))
            user = cur.fetchone()

            if not user:
                self._send_json(404, {"error": "User not found"})
                return

            self._send_json(200, {
                "username": user["username"],
                "created_at": user["created_at"].isoformat() if user["created_at"] else None
            })
        except Exception as e:
            self._send_json(500, {"error": "Server error"})
        finally:
            cur.close()
            conn.close()

    # ─ PROGRESS ─────────────────────────────────────────────

    def _handle_progress_get(self) -> None:
        username = _extract_username(self.headers)
        if not username:
            self._send_json(401, {"error": "Unauthorized"})
            return

        conn = _get_db_connection()
        if not conn:
            self._send_json(500, {"error": "DB error"})
            return

        cur = conn.cursor(cursor_factory=RealDictCursor)
        try:
            cur.execute("SELECT progress_data FROM user_progress WHERE username = %s", (username,))
            row = cur.fetchone()
            progress = row["progress_data"] if row else {}
            self._send_json(200, {"progress": progress})
        except Exception as e:
            self._send_json(500, {"error": "Server error"})
        finally:
            cur.close()
            conn.close()

    def _handle_progress_post(self) -> None:
        username = _extract_username(self.headers)
        if not username:
            self._send_json(401, {"error": "Unauthorized"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length > 0 else b"{}"
            payload = json.loads(body.decode("utf-8"))
        except:
            self._send_json(400, {"error": "Invalid JSON"})
            return

        progress = payload.get("progress", {})

        conn = _get_db_connection()
        if not conn:
            self._send_json(500, {"error": "DB error"})
            return

        cur = conn.cursor()
        try:
            cur.execute(
                """INSERT INTO user_progress (username, progress_data, updated_at) 
                   VALUES (%s, %s, CURRENT_TIMESTAMP)
                   ON CONFLICT (username) DO UPDATE SET 
                   progress_data = EXCLUDED.progress_data, updated_at = CURRENT_TIMESTAMP""",
                (username, json.dumps(progress, ensure_ascii=False))
            )
            conn.commit()
            self._send_json(200, {"ok": True})
        except Exception as e:
            conn.rollback()
            self._send_json(500, {"error": "Server error"})
        finally:
            cur.close()
            conn.close()

    def do_GET(self) -> None:
        if self._is_path("/api/auth/me"):
            self._handle_me()
            return
        if self._is_path("/api/user/progress"):
            self._handle_progress_get()
            return
        if self._is_scores_path():
            self._handle_scores_get()
            return
        if self._is_ai_path() or self._is_analyze_path():
            self._send_json(200, {"ok": True, "service": "ai-proxy", "model": _get_model(), "has_key": bool(_get_openrouter_key())})
            return
        return super().do_GET()


    # ─── SCORES ────────────────────────────────────────────────────
    def _scores_file(self) -> str:
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "scores.json")

    def _load_scores(self) -> list:
        try:
            with open(self._scores_file(), "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            return []

    def _save_scores(self, scores: list) -> None:
        with open(self._scores_file(), "w", encoding="utf-8") as f:
            json.dump(scores, f, ensure_ascii=False)

    def _handle_scores_get(self) -> None:
        conn = _get_db_connection()
        if not conn:
            self._send_json(200, {"scores": []})
            return

        cur = conn.cursor(cursor_factory=RealDictCursor)
        try:
            cur.execute(
                "SELECT username, total_score FROM scores ORDER BY total_score DESC LIMIT 20"
            )
            rows = cur.fetchall()
            scores = [
                {"name": r["username"], "s": r["total_score"], "d": ""}
                for r in rows
            ]
            self._send_json(200, {"scores": scores})
        except Exception as e:
            self._send_json(200, {"scores": []})
        finally:
            cur.close()
            conn.close()

    def _handle_scores_post(self) -> None:
        username = _extract_username(self.headers)
        if not username:
            self._send_json(401, {"error": "Unauthorized"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length > 0 else b"{}"
            payload = json.loads(body.decode("utf-8"))
        except:
            self._send_json(400, {"error": "Invalid JSON"})
            return

        score = payload.get("score", 0)
        if not isinstance(score, (int, float)) or score < 0:
            self._send_json(400, {"error": "Invalid score"})
            return

        conn = _get_db_connection()
        if not conn:
            self._send_json(500, {"error": "DB error"})
            return

        cur = conn.cursor()
        try:
            cur.execute(
                """INSERT INTO scores (username, total_score, updated_at) 
                   VALUES (%s, %s, CURRENT_TIMESTAMP)
                   ON CONFLICT (username) DO UPDATE SET 
                   total_score = scores.total_score + EXCLUDED.total_score, updated_at = CURRENT_TIMESTAMP""",
                (username, int(score))
            )
            conn.commit()
            self._send_json(200, {"ok": True})
        except Exception as e:
            conn.rollback()
            self._send_json(500, {"error": "Server error"})
        finally:
            cur.close()
            conn.close()
    # ───────────────────────────────────────────────────────────────

    def _handle_analyze(self) -> None:
        ip = self._client_ip()
        if not _allow_request(ip):
            self._send_json(429, {"error": "Rate limit"})
            return
        key = _get_openrouter_key()
        if not key:
            self._send_json(500, {"error": "OPENROUTER_API_KEY missing"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            self._send_json(400, {"error": "Invalid Content-Length"})
            return
        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_json(400, {"error": "Invalid JSON"})
            return

        event = (payload.get("event") or "end").strip().lower()
        history = payload.get("history")
        last_user = (payload.get("last_user") or "").strip()
        scenario = (payload.get("scenario") or "").strip()
        if event not in ("stop", "end"):
            self._send_json(400, {"error": "Invalid event"})
            return
        if not isinstance(history, list) or not history:
            self._send_json(400, {"error": "Missing history"})
            return

        convo = _format_history(history)
        if last_user:
            convo += "\nLAST_USER: " + _sanitize_text(last_user)
        if scenario:
            convo = "SCENARIO: " + scenario + "\n" + convo

        req_body = {
            "model": _get_model(),
            "max_tokens": OPENROUTER_ANALYZE_MAX_TOKENS,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": _analysis_prompt(event)},
                {"role": "user", "content": convo},
            ],
        }
        referer = self.headers.get("Referer") or self.headers.get("Origin") or ""
        req = Request(
            OPENROUTER_ENDPOINT,
            data=json.dumps(req_body).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {key}",
                "X-Title": "CifrSawat",
                **({"HTTP-Referer": referer} if referer else {}),
            },
        )
        data = None
        last_error = None
        for attempt in range(3):
            try:
                with urlopen(req, timeout=OPENROUTER_TIMEOUT_SEC) as resp:
                    raw = resp.read().decode("utf-8")
                    data = json.loads(raw)
                last_error = None
                break
            except HTTPError as e:
                detail = ""
                try:
                    detail = e.read().decode("utf-8")[:2000]
                except Exception:
                    detail = ""
                last_error = {"error": f"Upstream error (HTTP {e.code})", "detail": detail}
                if e.code not in (502, 503, 429):
                    break
                time.sleep(1.5)
            except URLError:
                last_error = {"error": "Upstream connection failed"}
                time.sleep(1.5)
            except Exception:
                last_error = {"error": "Unexpected server error"}
                break
        if last_error or data is None:
            self._send_json(502, last_error or {"error": "No response"})
            return
        content = (data.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""
        usage = data.get("usage") if isinstance(data, dict) else None
        self._send_json(200, {"content": content, "usage": usage, "model": _get_model()})

    def do_POST(self) -> None:
        if self._is_path("/api/auth/register"):
            self._handle_register()
            return
        if self._is_path("/api/auth/login"):
            self._handle_login()
            return
        if self._is_path("/api/user/progress"):
            self._handle_progress_post()
            return
        if self._is_scores_path():
            self._handle_scores_post()
            return
        if self._is_analyze_path():
            self._handle_analyze()
            return
        if not self._is_ai_path():
            self.send_error(404)
            return

        ip = self._client_ip()
        if not _allow_request(ip):
            self._send_json(429, {"error": "Rate limit"})
            return
        key = _get_openrouter_key()
        if not key:
            self._send_json(500, {"error": "OPENROUTER_API_KEY missing"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            self._send_json(400, {"error": "Invalid Content-Length"})
            return
        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_json(400, {"error": "Invalid JSON"})
            return

        mode = (payload.get("mode") or "adv").strip()
        text = (payload.get("text") or "").strip()
        messages = payload.get("messages")
        scenario = (payload.get("scenario") or "bank").strip()

        req_body = {
            "model": _get_model(),
            "max_tokens": OPENROUTER_MAX_TOKENS,
            "temperature": 0.7 if mode == "sim" else 0.2,
        }

        if messages and isinstance(messages, list):
            final_messages = []
            for m in messages:
                if not isinstance(m, dict):
                    continue
                role = (m.get("role") or "").strip()
                cont = (m.get("content") or "").strip()
                if role in ("system", "user", "assistant") and cont:
                    final_messages.append({"role": role, "content": cont[:3000]})
            if mode == "sim":
                sys_prompt = _system_prompt_sim(scenario)
                final_messages = [m for m in final_messages if m.get("role") != "system"]
                final_messages.insert(0, {"role": "system", "content": sys_prompt})
            else:
                sys_prompt = _system_prompt_adv()
                final_messages = [m for m in final_messages if m.get("role") != "system"]
                final_messages.insert(0, {"role": "system", "content": sys_prompt})
            req_body["messages"] = final_messages
        else:
            if not text:
                self._send_json(400, {"error": "Missing 'text'"})
                return
            if len(text) > MAX_INPUT_CHARS:
                self._send_json(413, {"error": "Input too long"})
                return
            if mode == "sim":
                sys_prompt = _system_prompt_sim(scenario)
            else:
                sys_prompt = _system_prompt_adv()
            req_body["messages"] = [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": text},
            ]

        referer = self.headers.get("Referer") or self.headers.get("Origin") or ""
        req = Request(
            OPENROUTER_ENDPOINT,
            data=json.dumps(req_body).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {key}",
                "X-Title": "CifrSawat",
                **({"HTTP-Referer": referer} if referer else {}),
            },
        )
        data = None
        last_error = None
        for attempt in range(3):
            try:
                with urlopen(req, timeout=OPENROUTER_TIMEOUT_SEC) as resp:
                    raw = resp.read().decode("utf-8")
                    data = json.loads(raw)
                last_error = None
                break
            except HTTPError as e:
                detail = ""
                try:
                    detail = e.read().decode("utf-8")[:2000]
                except Exception:
                    detail = ""
                last_error = {"error": f"Upstream error (HTTP {e.code})", "detail": detail}
                if e.code not in (502, 503, 429):
                    break
                time.sleep(1.5)
            except URLError:
                last_error = {"error": "Upstream connection failed"}
                time.sleep(1.5)
            except Exception:
                last_error = {"error": "Unexpected server error"}
                break
        if last_error or data is None:
            self._send_json(502, last_error or {"error": "No response"})
            return
        content = (data.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""
        usage = data.get("usage") if isinstance(data, dict) else None
        self._send_json(200, {"content": content, "usage": usage, "model": _get_model()})

def main() -> None:
    root_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(root_dir)
    _load_dotenv(os.path.join(root_dir, ".env"))
    _load_dotenv(os.path.join(root_dir, "api.env"))
    
    # Initialize database
    _init_db()
    
    port = int(os.getenv("PORT", "8787"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.serve_forever()

if __name__ == "__main__":
    main()
