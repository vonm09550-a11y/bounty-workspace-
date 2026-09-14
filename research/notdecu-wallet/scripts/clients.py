"""Thin, paced, disk-caching clients for phase 2. No data pull is started by importing this.

- GmgnActivity: walks `gmgn-cli portfolio activity` by cursor (server caps 20 rows/page, weight 3).
- Helius: parseTransactions in batches of <=100 signatures (2 req/s on the free plan), plus raw RPC.

Every response page is appended to a JSONL file so a rerun resumes instead of refetching.
"""
import json
import os
import subprocess
import time
import urllib.error
import urllib.request

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
GMGN_GAP_S = 0.5          # weight 3 per call; measured 2.1: 0.35 s tripped 429s every few minutes,
                          # consistent with the rate=10/capacity=10 bucket in docs/cli-usage.md
HELIUS_ENH_GAP_S = 0.55   # free plan: 2 enhanced-API req/s
HELIUS_RPC_GAP_S = 0.12   # free plan: 10 RPC req/s


def load_env():
    env = {}
    p = os.path.expanduser("~/.config/gmgn/.env")
    if os.path.exists(p):
        for line in open(p):
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                env[k] = v.strip('"')
    return env


GMGN_HOST = "https://openapi.gmgn.ai"


def slot_cursor(slot):
    """GMGN activity cursors decode to '<slot><8-digit index>:0::'. Build one to start a walk
    just below a given slot (measured 2.0: slot 368_000_000 -> Sept 2025)."""
    import base64
    return base64.b64encode(f"{slot}00000000:0::".encode()).decode()


class GmgnActivity:
    """Resumable walk of a wallet's trade rows, newest first.

    Uses the OpenAPI directly (exist auth: X-APIKEY header + timestamp/client_id query) instead of
    spawning gmgn-cli per page: measured 1.25 s/page via the CLI vs the network round trip alone.
    Server caps a page at 20 rows regardless of `limit`.
    """

    def __init__(self, wallet, chain="sol", types=("buy", "sell"), out=None, direct=True):
        self.wallet, self.chain, self.types, self.direct = wallet, chain, types, direct
        self.key = load_env().get("GMGN_API_KEY")
        self.out = out or os.path.join(DATA, "activity", f"{wallet[:8]}_{'-'.join(types)}.jsonl")
        os.makedirs(os.path.dirname(self.out), exist_ok=True)
        self.state = self.out + ".state"

    def _url(self, cursor, token=None):
        """Auth query is valid for ±5 s (AUTH_TIMESTAMP_EXPIRED otherwise), so it is rebuilt per attempt."""
        import uuid
        import urllib.parse
        q = [("chain", self.chain), ("wallet_address", self.wallet), ("limit", "100"),
             ("timestamp", str(int(time.time()))), ("client_id", str(uuid.uuid4()))]
        q += [("type", t) for t in self.types]
        if cursor:
            q.append(("cursor", cursor))
        if token:
            q.append(("token_address", token))
        return f"{GMGN_HOST}/v1/user/wallet_activity?{urllib.parse.urlencode(q)}"

    def _http(self, cursor, token=None, retries=6):
        for i in range(retries):
            req = urllib.request.Request(self._url(cursor, token),
                                         headers={"X-APIKEY": self.key, "Content-Type": "application/json",
                                                  "User-Agent": "gmgn-cli/1.6.2"})
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    d = json.loads(r.read().decode())
                    return d.get("data", d)
            except urllib.error.HTTPError as e:
                body = e.read().decode()[:300]
                if e.code == 429:
                    reset = None
                    try:
                        reset = float(e.headers.get("x-ratelimit-reset") or json.loads(body).get("reset_at"))
                    except Exception:  # noqa: BLE001
                        pass
                    # never land exactly on the reset instant: that extends a ban by 5 s
                    wait = max(3.0, (reset - time.time() + 2.0) if reset else 5.0 * (i + 1))
                    self.last_429 = {"at": time.time(), "wait": wait, "body": body}
                    time.sleep(min(wait, 330))
                    continue
                if e.code == 401 and "TIMESTAMP" in body:
                    continue  # clock skew on one attempt; rebuilt on the next loop
                raise RuntimeError(f"HTTP {e.code}: {body}")
        raise RuntimeError("rate-limited repeatedly; stop and resume later")

    def _cli(self, cursor):
        args = ["gmgn-cli", "portfolio", "activity", "--chain", self.chain, "--wallet", self.wallet, "--limit", "100"]
        for t in self.types:
            args += ["--type", t]
        if cursor:
            args += ["--cursor", cursor]
        args.append("--raw")
        r = subprocess.run(args, capture_output=True, text=True, timeout=60,
                           env={**os.environ, "GMGN_RATE_LIMIT_AUTO_RETRY_MAX_WAIT_MS": "90000"})
        if r.returncode != 0 or not r.stdout.strip():
            raise RuntimeError((r.stderr or "empty stdout (soft rate limit)")[:300])
        d = json.loads(r.stdout)
        return d.get("data", d)

    def walk(self, stop_before_ts=None, max_pages=None, start_cursor=None):
        """Yield rows; stop when rows are older than stop_before_ts (unix) or max_pages reached.
        Resumes from the saved cursor; `start_cursor` (e.g. slot_cursor(slot)) is used only when
        no state file exists yet."""
        cursor = json.load(open(self.state))["cursor"] if os.path.exists(self.state) else start_cursor
        pages = 0
        with open(self.out, "a") as f:
            while True:
                d = self._http(cursor) if self.direct else self._cli(cursor)
                rows = d.get("activities") or []
                for a in rows:
                    f.write(json.dumps(a) + "\n")
                    yield a
                pages += 1
                cursor = d.get("next")
                json.dump({"cursor": cursor, "pages": pages, "ts": time.time()}, open(self.state, "w"))
                if not rows or not cursor:
                    break
                if stop_before_ts and float(rows[-1]["timestamp"]) < stop_before_ts:
                    break
                if max_pages and pages >= max_pages:
                    break
                time.sleep(GMGN_GAP_S)


class GmgnToken:
    """Direct `GET /v1/token/info` (exist auth, weight 1). Returns the data object or None on 404-style empties."""

    def __init__(self, chain="sol"):
        self.chain = chain
        self.key = load_env().get("GMGN_API_KEY")

    def info(self, address, retries=6):
        import uuid
        import urllib.parse
        for i in range(retries):
            q = [("chain", self.chain), ("address", address), ("timestamp", str(int(time.time()))), ("client_id", str(uuid.uuid4()))]
            req = urllib.request.Request(f"{GMGN_HOST}/v1/token/info?{urllib.parse.urlencode(q)}",
                                         headers={"X-APIKEY": self.key, "Content-Type": "application/json", "User-Agent": "gmgn-cli/1.6.2"})
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    d = json.loads(r.read().decode())
                    return d.get("data", d)
            except urllib.error.HTTPError as e:
                body = e.read().decode()[:300]
                if e.code == 429:
                    reset = None
                    try:
                        reset = float(e.headers.get("x-ratelimit-reset") or json.loads(body).get("reset_at"))
                    except Exception:  # noqa: BLE001
                        pass
                    time.sleep(min(max(3.0, (reset - time.time() + 2.0) if reset else 5.0 * (i + 1)), 330))
                    continue
                if e.code == 401 and "TIMESTAMP" in body:
                    continue
                if e.code in (400, 404):
                    return {"_error": e.code, "_body": body}
                raise RuntimeError(f"HTTP {e.code}: {body}")
        raise RuntimeError("rate-limited repeatedly")


class Helius:
    def __init__(self, key=None):
        self.key = key or load_env().get("HELIUS_API_KEY")
        if not self.key:
            raise RuntimeError("HELIUS_API_KEY not configured")
        self._last = {"enh": 0.0, "rpc": 0.0}

    def _pace(self, kind, gap):
        wait = self._last[kind] + gap - time.time()
        if wait > 0:
            time.sleep(wait)
        self._last[kind] = time.time()

    def _post(self, url, body, retries=4):
        for i in range(retries):
            # default "Python-urllib" UA is rejected (403) by api.helius.xyz's CDN
            req = urllib.request.Request(url, method="POST", data=json.dumps(body).encode(),
                                         headers={"content-type": "application/json",
                                                  "User-Agent": "notdecu-research/0.1"})
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    return json.loads(r.read().decode())
            except urllib.error.HTTPError as e:  # noqa: F821
                if e.code == 429 and i < retries - 1:
                    time.sleep(2 ** (i + 1))
                    continue
                raise

    def parse(self, signatures, cache=None):
        """Parse up to 100 signatures per call; caches by signature in a JSONL file."""
        cache = cache or os.path.join(DATA, "helius", "parsed.jsonl")
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        have = set()
        if os.path.exists(cache):
            for line in open(cache):
                have.add(json.loads(line)["signature"])
        todo = [s for s in dict.fromkeys(signatures) if s not in have]
        with open(cache, "a") as f:
            for i in range(0, len(todo), 100):
                self._pace("enh", HELIUS_ENH_GAP_S)
                out = self._post(f"https://api.helius.xyz/v0/transactions?api-key={self.key}",
                                 {"transactions": todo[i:i + 100]})
                for t in out:
                    f.write(json.dumps(t) + "\n")
        return cache

    def rpc(self, method, params):
        self._pace("rpc", HELIUS_RPC_GAP_S)
        return self._post(f"https://mainnet.helius-rpc.com/?api-key={self.key}",
                          {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})["result"]
