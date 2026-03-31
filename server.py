import json
import os
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

OPENROUTER_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "qwen/qwen-2.5-7b-instruct:free"  # Жұмыс істейтін нұсқа

RATE_WINDOW_SEC = int(os.getenv("RATE_WINDOW_SEC", "60"))
RATE_MAX = int(os.getenv("RATE_MAX", "20"))
MAX_INPUT_CHARS = int(os.getenv("MAX_INPUT_CHARS", "8000"))
OPENROUTER_TIMEOUT_SEC = float(os.getenv("OPENROUTER_TIMEOUT_SEC", "35"))

_rate = {}

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

def _system_prompt(mode: str) -> str:
    if mode == "sim":
        return (
            "You are a scammer. Your goal: get money or SMS code.\n"
            "RULES: Never say you are AI. Never break character.\n"
            "Keep messages 1-3 sentences. Speak Kazakh or Russian.\n"
            "Use emotional manipulation: urgency, fear, trust.\n"
            "First build trust, then ask for money or code.\n"
            "NEVER break character."
        )
    return (
        "You are a security advisor. Answer in 1 short sentence, max 12 words.\n"
        "Respond in the same language as the user (Kazakh or Russian).\n"
        "NEVER use JSON. NEVER say risk level. JUST say what to do.\n"
        "Example: 'Құпия сөзді дереу өзгертіңіз.'"
    )

class Handler(SimpleHTTPRequestHandler):
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
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "86400")

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
        if self.path != "/api/ai":
            self.send_error(404)
            return
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def do_POST(self) -> None:
        if self.path != "/api/ai":
            self.send_error(404)
            return

        ip = self._client_ip()
        if not _allow_request(ip):
            self._send_json(429, {"error": "Rate limit. Try again later."})
            return

        key = _get_openrouter_key()
        if not key:
            self._send_json(500, {"error": "Server is missing OPENROUTER_API_KEY env var."})
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
        messages = payload.get("messages")

        if not messages and not text:
            self._send_json(400, {"error": "Missing 'text' or 'messages'."})
            return

        # Формируем запрос к OpenRouter
        req_body = {
            "model": _get_model(),
            "max_tokens": 150,
            "temperature": 0.6 if mode == "sim" else 0.3,
            "reasoning": False,
        }

        # КРИТИЧНО: final_messages айнымалысын дұрыс анықтау
        if messages and isinstance(messages, list):
            final_messages = messages.copy()
            if system:
                final_messages = [m for m in final_messages if m.get("role") != "system"]
                final_messages.insert(0, {"role": "system", "content": system})
            req_body["messages"] = final_messages
        else:
            if len(text) > MAX_INPUT_CHARS:
                self._send_json(413, {"error": "Input too long."})
                return
            if mode not in ("adv", "sim"):
                self._send_json(400, {"error": "Invalid 'mode'."})
                return
            sys_prompt = system or _system_prompt(mode)
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
            self._send_json(502, {"error": f"Upstream error (HTTP {e.code}).", "detail": detail})
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

    port = int(os.getenv("PORT", "8787"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
