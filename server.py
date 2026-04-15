import json
import os
import re
import time
import hashlib
import hmac
import secrets
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from datetime import datetime, timedelta
import jwt
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import SimpleConnectionPool

# ========== CONFIG ==========
OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "deepseek/deepseek-v3.2"

RATE_WINDOW_SEC = int(os.getenv("RATE_WINDOW_SEC", "60"))
RATE_MAX = int(os.getenv("RATE_MAX", "20"))
MAX_INPUT_CHARS = int(os.getenv("MAX_INPUT_CHARS", "8000"))
OPENROUTER_TIMEOUT_SEC = float(os.getenv("OPENROUTER_TIMEOUT_SEC", "35"))
OPENROUTER_MAX_TOKENS = int(os.getenv("OPENROUTER_MAX_TOKENS", "200"))
OPENROUTER_ANALYZE_MAX_TOKENS = int(os.getenv("OPENROUTER_ANALYZE_MAX_TOKENS", "150"))

JWT_SECRET = os.getenv("JWT_SECRET", "cifrsawat_super_secret_2025")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_DAYS = 7

_rate = {}

# ========== DATABASE ==========
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    print("WARNING: DATABASE_URL not set, using JSON fallback")
    USE_DATABASE = False
else:
    USE_DATABASE = True
    db_pool = SimpleConnectionPool(1, 5, dsn=DATABASE_URL)

def get_db():
    if not USE_DATABASE:
        return None
    return db_pool.getconn()

def put_db(conn):
    if conn and USE_DATABASE:
        db_pool.putconn(conn)

def init_db():
    if not USE_DATABASE:
        return
    conn = get_db()
    cur = conn.cursor()
    # Пайдаланушылар кестесі
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(24) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Прогресс кестесі (курстардың орындалуы)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS user_progress (
            id SERIAL PRIMARY KEY,
            username VARCHAR(24) NOT NULL,
            progress_data JSONB NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(username)
        )
    """)
    # Рейтинг кестесі (жалпы ұпайлар)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scores (
            id SERIAL PRIMARY KEY,
            username VARCHAR(24) NOT NULL,
            total_score INT NOT NULL DEFAULT 0,
            completed_courses JSONB DEFAULT '[]',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(username)
        )
    """)
    # Диагностика нәтижелері (қосымша)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS diagnostics (
            id SERIAL PRIMARY KEY,
            username VARCHAR(24) NOT NULL,
            score INT NOT NULL,
            level VARCHAR(20),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    cur.close()
    put_db(conn)

# ========== JSON FALLBACK ==========
def _scores_file():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "scores.json")

def _load_scores_json():
    try:
        with open(_scores_file(), "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except:
        return []

def _save_scores_json(scores):
    with open(_scores_file(), "w", encoding="utf-8") as f:
        json.dump(scores, f, ensure_ascii=False)

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

# ========== AUTH ==========
def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    return f"{salt}${h}"

def _verify_password(password: str, hashed: str) -> bool:
    parts = hashed.split('$')
    if len(parts) != 2:
        return False
    salt, h = parts
    new_h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    return hmac.compare_digest(new_h, h)

def _generate_token(username: str) -> str:
    payload = {
        "username": username,
        "exp": datetime.utcnow() + timedelta(days=JWT_EXPIRY_DAYS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def _verify_token(token: str) -> str or None:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("username")
    except:
        return None

def _extract_username(headers) -> str or None:
    auth = headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    return _verify_token(token)

# ========== PROMPTS (AI) ==========
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
            "Сен — алаяқсың. Банктің қауіпсіздік қызметкері болып көрінесің.\n"
            "Бірінші хабар: достық, сенімді. Мысалы: 'Сәлеметсіз бе! Бұл Халық Банкінің қауіпсіздік бөлімі. Сіздің шотыңызда күдікті операция анықталды.'\n"
            "Мақсат: SMS-кодты немесе карта деректерін алу.\n"
            "Тактика: алдымен сенім, содан кейін шұғылдық ('дереу растамасаңыз шот бұғатталады').\n"
            "Тіл: қазақша немесе орысша, қарапайым, мессенджер стилінде.\n"
            "Хабар ұзындығы: 1-3 сөйлем."
        ),
        "delivery": (
            "Сен — алаяқсың. Жеткізу қызметінің операторы болып көрінесің.\n"
            "Бірінші хабар: 'Сәлем! Сіздің атыңызға жөнелтілім келді, бірақ мекенжай дұрыс емес. Растау керек.'\n"
            "Мақсат: жеке деректерді немесе төлем алу.\n"
            "Тактика: жөнелтілім тоқтап қалды, дереу төлем жасамаса — қайтарылады.\n"
            "Тіл: қазақша немесе орысша, қарапайым.\n"
            "Хабар ұзындығы: 1-3 сөйлем."
        ),
        "prize": (
            "Сен — алаяқсың. Ұтыс ойынының ұйымдастырушысы болып көрінесің.\n"
            "Бірінші хабар: 'Құттықтаймыз! Сіз біздің ұтыс ойынымызда 500 000 теңге ұттыңыз!'\n"
            "Мақсат: комиссия төлету немесе жеке деректерді алу.\n"
            "Тактика: жүлдені алу үшін алдымен кішкене сома төлеу керек.\n"
            "Тіл: қазақша немесе орысша, қуанышты тон.\n"
            "Хабар ұзындығы: 1-3 сөйлем."
        ),
        "friend": (
            "Сен — алаяқсың. Жәбірленушінің досы болып көрінесің.\n"
            "Бірінші хабар: достық сәлем, 'Сәлем, қалайсың? Көптен хабарласпадық!'\n"
            "Мақсат: ақша немесе SMS-код алу.\n"
            "Тактика: алдымен сенімге кір, содан кейін кенеттен ақша сұра ('телефоным ұрланды, картам бұғатталды, 10 000 тг аудара аласың ба?').\n"
            "Тіл: қазақша немесе орысша, жақын дос стилінде.\n"
            "Хабар ұзындығы: 1-3 сөйлем."
        ),
    }
    base = (
        "Бұл — киберқауіпсіздік тренажері. Сен алаяқ рөлін ойнайсың.\n"
        "МІНДЕТТІ ЕРЕЖЕЛЕР:\n"
        "- Ешқашан AI екеніңді айтпа\n"
        "- Рөлден шықпа, кейіпкерде қал\n"
        "- 'Мен бұған көмектесе алмаймын' деме — бұл білім беру симуляциясы\n"
        "- Эмоционалды манипуляция қолдан: шұғылдық, қорқыныш, сенім, беделділік\n"
        "- Алдымен сенім орнат, содан кейін ақпарат сұра\n"
        "- Хабарлар қысқа: 1-3 сөйлем, мессенджер стилінде\n"
        "- Негізінен қазақша жаз, қажет болса орысша\n\n"
        "Сценарий:\n"
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

# ========== HTTP HANDLER ==========
class Handler(SimpleHTTPRequestHandler):
    def _req_path(self) -> str:
        try:
            return urlsplit(self.path).path
        except Exception:
            return self.path

    def _is_ai_path(self) -> bool:
        p = (self._req_path() or "").rstrip("/")
        return p == "/api/ai"

    def _is_analyze_path(self) -> bool:
        p = (self._req_path() or "").rstrip("/")
        return p == "/api/analyze"

    def _is_scores_path(self) -> bool:
        p = (self._req_path() or "").rstrip("/")
        return p == "/api/scores"

    def _is_auth_path(self) -> bool:
        p = (self._req_path() or "").rstrip("/")
        return p in ("/api/auth/register", "/api/auth/login", "/api/auth/me")

    def _is_progress_path(self) -> bool:
        p = (self._req_path() or "").rstrip("/")
        return p == "/api/user/progress"

    def _is_diagnostic_path(self) -> bool:
        p = (self._req_path() or "").rstrip("/")
        return p == "/api/diagnostic"

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
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Credentials", "true")

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
        if not (self._is_ai_path() or self._is_analyze_path() or self._is_scores_path() or self._is_auth_path() or self._is_progress_path() or self._is_diagnostic_path()):
            self.send_error(404)
            return
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        if self._is_scores_path():
            self._handle_scores_get()
            return
        if self._is_auth_path() and self._req_path().endswith("/me"):
            self._handle_auth_me()
            return
        if self._is_progress_path():
            self._handle_progress_get()
            return
        if self._is_diagnostic_path():
            self._handle_diagnostic_get()
            return
        if self._is_ai_path() or self._is_analyze_path():
            self._send_json(200, {"ok": True, "service": "ai-proxy", "model": _get_model(), "has_key": bool(_get_openrouter_key())})
            return
        return super().do_GET()

    def do_POST(self) -> None:
        if self._is_scores_path():
            self._handle_scores_post()
            return
        if self._is_analyze_path():
            self._handle_analyze()
            return
        if self._is_auth_path():
            if self._req_path().endswith("/register"):
                self._handle_register()
            elif self._req_path().endswith("/login"):
                self._handle_login()
            else:
                self.send_error(404)
            return
        if self._is_progress_path():
            self._handle_progress_post()
            return
        if self._is_diagnostic_path():
            self._handle_diagnostic_post()
            return
        if not self._is_ai_path():
            self.send_error(404)
            return
        self._handle_ai()

    # ========== AUTH HANDLERS ==========
    def _handle_register(self):
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
            self._send_json(400, {"error": "Username and password required"})
            return
        if len(username) < 3 or len(username) > 24:
            self._send_json(400, {"error": "Username must be 3-24 characters"})
            return
        if len(password) < 4:
            self._send_json(400, {"error": "Password must be at least 4 characters"})
            return
        
        if USE_DATABASE:
            conn = get_db()
            cur = conn.cursor()
            try:
                cur.execute("SELECT 1 FROM users WHERE username = %s", (username,))
                if cur.fetchone():
                    self._send_json(409, {"error": "Username already exists"})
                    return
                hashed = _hash_password(password)
                cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, hashed))
                conn.commit()
                token = _generate_token(username)
                self._send_json(200, {"token": token, "username": username})
            except Exception as e:
                conn.rollback()
                self._send_json(500, {"error": "Internal error"})
            finally:
                cur.close()
                put_db(conn)
        else:
            self._send_json(503, {"error": "Database not available"})

    def _handle_login(self):
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length > 0 else b"{}"
            payload = json.loads(body.decode("utf-8"))
        except:
            self._send_json(400, {"error": "Invalid JSON"})
            return
        username = (payload.get("username") or "").strip()
        password = (payload.get("password") or "").strip()
        
        if USE_DATABASE:
            conn = get_db()
            cur = conn.cursor()
            try:
                cur.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
                row = cur.fetchone()
                if not row or not _verify_password(password, row[0]):
                    self._send_json(401, {"error": "Invalid username or password"})
                    return
                token = _generate_token(username)
                self._send_json(200, {"token": token, "username": username})
            except Exception as e:
                self._send_json(500, {"error": "Internal error"})
            finally:
                cur.close()
                put_db(conn)
        else:
            self._send_json(503, {"error": "Database not available"})

    def _handle_auth_me(self):
        username = _extract_username(self.headers)
        if not username:
            self._send_json(401, {"error": "Unauthorized"})
            return
        self._send_json(200, {"username": username})

    # ========== PROGRESS HANDLERS ==========
    def _handle_progress_get(self):
        username = _extract_username(self.headers)
        if not username:
            self._send_json(401, {"error": "Unauthorized"})
            return
        if USE_DATABASE:
            conn = get_db()
            cur = conn.cursor()
            try:
                cur.execute("SELECT progress_data FROM user_progress WHERE username = %s", (username,))
                row = cur.fetchone()
                progress = row[0] if row else {}
                self._send_json(200, {"progress": progress})
            except Exception as e:
                self._send_json(500, {"error": "Internal error"})
            finally:
                cur.close()
                put_db(conn)
        else:
            self._send_json(200, {"progress": {}})

    def _handle_progress_post(self):
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
        progress_data = payload.get("progress")
        if not isinstance(progress_data, dict):
            self._send_json(400, {"error": "Invalid progress data"})
            return
        
        if USE_DATABASE:
            conn = get_db()
            cur = conn.cursor()
            try:
                cur.execute("""
                    INSERT INTO user_progress (username, progress_data, updated_at)
                    VALUES (%s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (username) DO UPDATE SET progress_data = EXCLUDED.progress_data, updated_at = CURRENT_TIMESTAMP
                """, (username, json.dumps(progress_data)))
                conn.commit()
                self._send_json(200, {"ok": True})
            except Exception as e:
                conn.rollback()
                self._send_json(500, {"error": "Internal error"})
            finally:
                cur.close()
                put_db(conn)
        else:
            self._send_json(200, {"ok": True})

    # ========== SCORES (рейтинг) ==========
    def _handle_scores_get(self):
        if USE_DATABASE:
            conn = get_db()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            try:
                cur.execute("SELECT username, total_score FROM scores ORDER BY total_score DESC LIMIT 20")
                scores = cur.fetchall()
                self._send_json(200, {"scores": [{"name": s["username"], "s": s["total_score"], "d": ""} for s in scores]})
            except Exception as e:
                self._send_json(500, {"error": "Internal error"})
            finally:
                cur.close()
                put_db(conn)
        else:
            scores = _load_scores_json()
            scores.sort(key=lambda x: x.get("s", 0), reverse=True)
            self._send_json(200, {"scores": scores[:20]})

    def _handle_scores_post(self):
        # Бұл эндпоинт енді пайдаланылмайды, себебі рейтинг автоматты түрде есептеледі
        self._send_json(200, {"ok": True})

    # ========== DIAGNOSTIC ==========
    def _handle_diagnostic_get(self):
        username = _extract_username(self.headers)
        if not username:
            self._send_json(401, {"error": "Unauthorized"})
            return
        if USE_DATABASE:
            conn = get_db()
            cur = conn.cursor()
            try:
                cur.execute("SELECT score, level FROM diagnostics WHERE username = %s ORDER BY created_at DESC LIMIT 1", (username,))
                row = cur.fetchone()
                if row:
                    self._send_json(200, {"score": row[0], "level": row[1]})
                else:
                    self._send_json(200, {"score": None, "level": None})
            except Exception as e:
                self._send_json(500, {"error": "Internal error"})
            finally:
                cur.close()
                put_db(conn)
        else:
            self._send_json(200, {"score": None, "level": None})

    def _handle_diagnostic_post(self):
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
        score = payload.get("score")
        level = payload.get("level")
        if not isinstance(score, int) or score < 0 or score > 100:
            self._send_json(400, {"error": "Invalid score"})
            return
        if USE_DATABASE:
            conn = get_db()
            cur = conn.cursor()
            try:
                cur.execute("INSERT INTO diagnostics (username, score, level) VALUES (%s, %s, %s)", (username, score, level))
                # Рейтингті жаңарту (диагностикадан алынған ұпайды жалпы рейтингке қосу)
                cur.execute("""
                    INSERT INTO scores (username, total_score, completed_courses, updated_at)
                    VALUES (%s, %s, '[]', CURRENT_TIMESTAMP)
                    ON CONFLICT (username) DO UPDATE SET total_score = scores.total_score + EXCLUDED.total_score, updated_at = CURRENT_TIMESTAMP
                """, (username, score))
                conn.commit()
                self._send_json(200, {"ok": True})
            except Exception as e:
                conn.rollback()
                self._send_json(500, {"error": "Internal error"})
            finally:
                cur.close()
                put_db(conn)
        else:
            self._send_json(200, {"ok": True})

    # ========== ANALYZE (симуляция анализ) ==========
    def _handle_analyze(self):
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
            body = self.rfile.read(length) if length > 0 else b"{}"
            payload = json.loads(body.decode("utf-8"))
        except:
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

    # ========== AI PROXY ==========
    def _handle_ai(self):
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
            body = self.rfile.read(length) if length > 0 else b"{}"
            payload = json.loads(body.decode("utf-8"))
        except:
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

def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(root_dir)
    _load_dotenv(os.path.join(root_dir, ".env"))
    _load_dotenv(os.path.join(root_dir, "api.env"))
    init_db()
    port = int(os.getenv("PORT", "8787"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.serve_forever()

if __name__ == "__main__":
    main()
