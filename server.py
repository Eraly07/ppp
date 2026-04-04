import json
import os
import re
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "qwen/qwen3.6-plus:free"

RATE_WINDOW_SEC = int(os.getenv("RATE_WINDOW_SEC", "60"))
RATE_MAX = int(os.getenv("RATE_MAX", "20"))
MAX_INPUT_CHARS = int(os.getenv("MAX_INPUT_CHARS", "8000"))
OPENROUTER_TIMEOUT_SEC = float(os.getenv("OPENROUTER_TIMEOUT_SEC", "35"))

_rate = {}  # ip -> list[timestamps]

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
        # Ignore .env parsing errors; hosting env vars should still work.
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


def _system_prompt(mode: str) -> str:
    if mode == "sim":
        return (
            "You are a cybersecurity educator. Respond in the SAME language as the user. "
            "Output ONLY valid JSON, no markdown, no code fences. "
            "Do NOT generate scam messages, scripts, links, phone numbers, or step-by-step wrongdoing instructions. "
            "Keep tactics high-level and educational. "
            'Schema: {"tactics":["t1","t2","t3"],"warning_signs":["w1","w2"],"defense":["d1","d2","d3"]}'
        )
    return (
        "You are a digital security expert. Respond in the SAME language as the user. "
        "Output ONLY valid JSON, no markdown, no code fences. "
        'Schema: {"risk":"HIGH|MEDIUM|LOW","risk_label":"local risk name","what":"2-3 sentences","steps":["s1","s2","s3"],"prevention":"tip"}'
    )


def _analysis_prompt(event: str) -> str:
    if event == "end":
        return (
            "You are a cybersecurity training coach. Respond in the SAME language as the user. "
            "Output ONLY valid JSON, no markdown, no code fences. "
            "Summarize the user's behavior in a scam-awareness simulation. "
            "Do NOT include any scammer messages or sensitive data. "
            'Schema: {"summary":"2-4 sentences","good_moves":["g1","g2"],"mistakes":["m1","m2"],"advice":["a1","a2","a3"],"score":0}'
        )
    return (
        "You are a cybersecurity training coach. Respond in the SAME language as the user. "
        "Check if the user made a critical mistake (sharing OTP/SMS code, passwords, card details, sending money, "
        "installing remote access, or trusting unverified requests). "
        "Do NOT include any scammer messages. Do NOT repeat sensitive data; use [REDACTED]. "
        "Output ONLY valid JSON, no markdown, no code fences. "
        'Schema: {"stop":true|false,"title":"short","why":["w1","w2"],"advice":["a1","a2"],"tip":"optional"}'
    )


def _sanitize_text(text: str) -> str:
    t = (text or "").strip()
    if not t:
        return ""
    t = re.sub(r"\b\d{4,}\b", "[REDACTED]", t)
    t = re.sub(
        r"(sms|смс|код|otp|пароль|password|құпиясөз|қупиясоз|cvv|cvc|иин|жсн)\s*[:=]?\s*\S+",
        r"\1 [REDACTED]",
        t,
        flags=re.IGNORECASE,
    )
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

    def _is_ai_path(self) -> bool:
        # Allow "/api/ai", "/api/ai/" and "/api/ai?x=1"
        p = (self._req_path() or "").rstrip("/")
        return p == "/api/ai"

    def _is_analyze_path(self) -> bool:
        # Allow "/api/analyze", "/api/analyze/" and "/api/analyze?x=1"
        p = (self._req_path() or "").rstrip("/")
        return p == "/api/analyze"

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
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        # `ngrok-skip-browser-warning` helps bypass ngrok's interstitial on free tunnels.
        self.send_header("Access-Control-Allow-Headers", "Content-Type, ngrok-skip-browser-warning")

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
        if not (self._is_ai_path() or self._is_analyze_path()):
            self.send_error(404)
            return
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        # Health check for deploy debugging.
        if self._is_ai_path() or self._is_analyze_path():
            self._send_json(
                200,
                {
                    "ok": True,
                    "service": "ai-proxy",
                    "path": self._req_path(),
                    "model": _get_model(),
                    "has_key": bool(_get_openrouter_key()),
                },
            )
            return
        return super().do_GET()

    def _handle_analyze(self) -> None:
        ip = self._client_ip()
        if not _allow_request(ip):
            self._send_json(429, {"error": "Rate limit. Try again later."})
            return

        key = _get_openrouter_key()
        if not key:
            self._send_json(
                500,
                {
                    "error": "Server is missing OPENROUTER_API_KEY env var.",
                },
            )
            return

        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            self._send_json(400, {"error": "Invalid Content-Length."})
            return

        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_json(400, {"error": "Invalid JSON body."})
            return

        event = (payload.get("event") or "check").strip().lower()
        history = payload.get("history")
        last_user = (payload.get("last_user") or "").strip()

        if event not in ("check", "end"):
            self._send_json(400, {"error": "Invalid 'event'."})
            return
        if not isinstance(history, list) or not history:
            self._send_json(400, {"error": "Missing 'history'."})
            return

        convo = _format_history(history)
        if last_user:
            convo = (convo + "\nLAST_USER: " + _sanitize_text(last_user)).strip()

        req_body = {
            "model": _get_model(),
            "max_tokens": 700,
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

        try:
            with urlopen(req, timeout=OPENROUTER_TIMEOUT_SEC) as resp:
                raw = resp.read().decode("utf-8")
                data = json.loads(raw)
        except HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8")[:2000]
            except Exception:
                detail = ""
            self._send_json(
                502,
                {
                    "error": f"Upstream error (HTTP {e.code}).",
                    "detail": detail,
                },
            )
            return
        except URLError:
            self._send_json(502, {"error": "Upstream connection failed."})
            return
        except Exception:
            self._send_json(500, {"error": "Unexpected server error."})
            return

        content = ""
        try:
            content = (data.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""
        except Exception:
            content = ""

        usage = data.get("usage") if isinstance(data, dict) else None
        self._send_json(200, {"content": content, "usage": usage, "model": _get_model()})

    def do_POST(self) -> None:
        if self._is_analyze_path():
            self._handle_analyze()
            return
        if not self._is_ai_path():
            self.send_error(404)
            return

        ip = self._client_ip()
        if not _allow_request(ip):
            self._send_json(429, {"error": "Rate limit. Try again later."})
            return

        key = _get_openrouter_key()
        if not key:
            self._send_json(
                500,
                {
                    "error": "Server is missing OPENROUTER_API_KEY env var.",
                },
            )
            return

        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            self._send_json(400, {"error": "Invalid Content-Length."})
            return

        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_json(400, {"error": "Invalid JSON body."})
            return

        text = (payload.get("text") or "").strip()
        mode = (payload.get("mode") or "adv").strip()
        system = (payload.get("system") or "").strip()

        if mode not in ("adv", "sim"):
            self._send_json(400, {"error": "Invalid 'mode'."})
            return
        if not text:
            self._send_json(400, {"error": "Missing 'text'."})
            return
        if len(text) > MAX_INPUT_CHARS:
            self._send_json(413, {"error": "Input too long."})
            return

        sys_prompt = system or _system_prompt(mode)

        req_body = {
            "model": _get_model(),
            "max_tokens": 900,
            "temperature": 0.6 if mode == "sim" else 0.2,
            "messages": [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": text},
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

        try:
            with urlopen(req, timeout=OPENROUTER_TIMEOUT_SEC) as resp:
                raw = resp.read().decode("utf-8")
                data = json.loads(raw)
        except HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8")[:2000]
            except Exception:
                detail = ""
            self._send_json(
                502,
                {
                    "error": f"Upstream error (HTTP {e.code}).",
                    "detail": detail,
                },
            )
            return
        except URLError:
            self._send_json(502, {"error": "Upstream connection failed."})
            return
        except Exception:
            self._send_json(500, {"error": "Unexpected server error."})
            return

        content = ""
        try:
            content = (data.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""
        except Exception:
            content = ""

        usage = data.get("usage") if isinstance(data, dict) else None
        self._send_json(200, {"content": content, "usage": usage, "model": _get_model()})


def main() -> None:
    root_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(root_dir)
    _load_dotenv(os.path.join(root_dir, ".env"))
    _load_dotenv(os.path.join(root_dir, "api.env"))

    port = int(os.getenv("PORT", "8787"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
