"""Shared, domain-scoped memory store for several Hermes agents (profiles).

Pure Python + sqlite3, no Hermes imports, so it is unit-testable on its own.

Model
-----
* agent   : a Hermes profile name. Unknown agents have no access (fail closed).
* domain  : a named partition ("home", "projects/3d", ...). Access is granted per
            agent and per domain: read, or read+write.
* fact    : a short statement in a domain about a subject. Every fact an agent
            writes is ``proposed``; only a human (slash command) can move it to
            ``verified``, ``rejected`` or ``forgotten``. Provenance (who proposed it,
            from where) is recorded separately and never promotes a fact by itself.
* revoke  : immediate and sticky. A later ``grant`` does not re-open a revoked
            agent: only an explicit, audited ``reinstate`` does, and it reports the
            grants it re-activates (or drops them with ``keep_grants=False``).
* audit   : writes and human decisions are audited in the same transaction as the
            change. Reads, recalls and read denials are audited best-effort: if the
            database stays busy for more than ~0.2 s that audit line is skipped.

Database ownership: the file is stamped with ``PRAGMA application_id``. A missing or
empty file is initialised and stamped; any other file (another application's SQLite
database, a non-SQLite file) is refused BEFORE anything is written to it.

Honest limits: this is *cooperative* access control inside the Hermes process. It is
not an OS sandbox: any code running as the same OS user can open the SQLite file.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import time
import unicodedata
from contextlib import contextmanager
from pathlib import Path

SCHEMA_VERSION = 1
APPLICATION_ID = 0x53484D44          # "SHMD": marks a database created by this plugin
SQLITE_MAGIC = b"SQLite format 3\x00"
EXPECTED_TABLES = {"meta", "agents", "grants", "facts", "audit", "sqlite_sequence"}

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")       # same alphabet as Hermes profile ids
DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}(/[a-z0-9][a-z0-9_.-]{0,62}){0,3}$")
MAX_SUBJECT = 120
MAX_CONTENT = 2000
MAX_SOURCE = 300
MAX_LIMIT = 50

# Characters that start a new visual line, and bidi controls that reorder what a human reads.
LINE_BREAKS = "\n\r\x0b\x0c\x85\u2028\u2029"
BIDI_CONTROLS = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f"

WRITE_RETRY_S = 5.0          # writes / decisions: give up after this long if the db stays locked
REVOKE_RETRY_S = 10.0        # revocation tries harder: it must not fail because others are busy
BEST_EFFORT_RETRY_S = 0.2    # read-side audit lines: never stall a read for longer than this


class AccessDenied(Exception):
    """The agent may not perform this operation (unknown, revoked, or not granted)."""


class InvalidInput(ValueError):
    """Malformed name, domain, number or content."""


class ForeignDatabase(RuntimeError):
    """db_path points at a file this plugin did not create. Nothing was written to it."""


def _now() -> float:
    return time.time()


def normalize(text: str) -> str:
    """Canonical form used for the dedup hash and search: NFKC, casefold, collapsed whitespace."""
    text = unicodedata.normalize("NFKC", text).casefold()
    return " ".join(text.split())


def content_hash(domain: str, subject: str, content: str) -> str:
    key = json.dumps([domain, normalize(subject), normalize(content)], ensure_ascii=False)
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def one_line(text: str) -> str:
    """Render stored text on ONE visual line, so a proposal cannot fake extra lines in
    `pending`, `search` or the recall block. Line breaks become a visible '⏎', tabs a space."""
    out = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\r" and i + 1 < len(text) and text[i + 1] == "\n":
            i += 1
            ch = "\n"
        if ch in LINE_BREAKS:
            out.append(" ⏎ ")
        elif ch == "\t":
            out.append(" ")
        elif ch in BIDI_CONTROLS or ord(ch) < 32 or ch == "\x7f":
            out.append("\ufffd")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def check_name(name: str, what: str = "agent") -> str:
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise InvalidInput(f"invalid {what} name {name!r}: use a-z, 0-9, '_', '-' (max 63, lowercase)")
    return name


def check_domain(domain: str) -> str:
    if not isinstance(domain, str) or not DOMAIN_RE.match(domain):
        raise InvalidInput(f"invalid domain {domain!r}: e.g. 'home' or 'projects/3d' (lowercase)")
    return domain


def check_limit(limit, default: int = 10) -> int:
    if limit is None:
        return default
    if isinstance(limit, bool) or not isinstance(limit, (int, str)):
        raise InvalidInput("limit must be an integer between 1 and 50")
    try:
        value = int(limit)
    except ValueError:
        raise InvalidInput("limit must be an integer between 1 and 50") from None
    return max(1, min(value, MAX_LIMIT))


def _check_text(value, field: str, limit: int, required: bool = True, multiline: bool = False) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str) or (required and not value.strip()):
        raise InvalidInput(f"{field} must be a non-empty string")
    value = value.strip()
    if len(value) > limit:
        raise InvalidInput(f"{field} is too long ({len(value)} > {limit} characters)")
    allowed = "\n\t" if multiline else ""
    for ch in value:
        if (ord(ch) < 32 or ch in "\x7f\x85\u2028\u2029") and ch not in allowed:
            raise InvalidInput(f"{field} contains a line break or control character"
                               + ("" if multiline else " (not allowed in this field)"))
        if ch in BIDI_CONTROLS:
            raise InvalidInput(f"{field} contains a bidirectional-text control character")
    return value


def inspect_file(path: Path) -> str:
    """'new' (absent or empty: safe to initialise) or 'ours' (stamped by this plugin).
    Raises ForeignDatabase otherwise. Reads at most 100 bytes; never writes."""
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return "new"
    if not path.is_file():
        raise ForeignDatabase(f"{path} is not a regular file")
    if size == 0:
        return "new"
    with open(path, "rb") as f:
        header = f.read(100)
    if len(header) < 100 or header[:16] != SQLITE_MAGIC:
        raise ForeignDatabase(f"{path} is not a SQLite database created by shared-memory-domains")
    app_id = int.from_bytes(header[68:72], "big")
    if app_id != APPLICATION_ID:
        raise ForeignDatabase(f"{path} belongs to another application (application_id={app_id:#x}); "
                              "refusing to touch it. Point db_path at a new file.")
    return "ours"


class Store:
    """Thread-safe store. One instance per database file per process."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        state = inspect_file(self.path)              # refuse foreign files before ANY write
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), timeout=0, isolation_level=None,
                                     check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.execute("PRAGMA busy_timeout=5000")   # initialisation only
            if state == "new":
                self._initialise()
            self._check_ownership()
            self._conn.execute("PRAGMA foreign_keys=ON")
            # Retries are explicit and bounded in _tx(); SQLite itself must not wait.
            self._conn.execute("PRAGMA busy_timeout=0")
        except BaseException:
            self._conn.close()     # foreign / unreadable / newer schema: fail closed, leak nothing
            raise

    # ------------------------------------------------------------------ setup
    def _initialise(self) -> None:
        # Stamp application_id while still in rollback-journal mode, so it lands in the main
        # file header at once (in WAL mode it could sit in the -wal file until a checkpoint).
        # executescript() commits any open transaction itself, so the DDL carries BEGIN/COMMIT.
        with self._lock:
            self._conn.executescript(f"""
            BEGIN IMMEDIATE;
            PRAGMA application_id={APPLICATION_ID};
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS agents (
                agent TEXT PRIMARY KEY,
                status TEXT NOT NULL CHECK (status IN ('active','revoked')),
                created_at REAL NOT NULL,
                revoked_at REAL
            );
            CREATE TABLE IF NOT EXISTS grants (
                agent TEXT NOT NULL REFERENCES agents(agent),
                domain TEXT NOT NULL,
                can_write INTEGER NOT NULL CHECK (can_write IN (0,1)),
                granted_at REAL NOT NULL,
                PRIMARY KEY (agent, domain)
            );
            CREATE TABLE IF NOT EXISTS facts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                subject TEXT NOT NULL,
                content TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('proposed','verified','rejected','forgotten')),
                proposed_by TEXT NOT NULL,
                proposed_at REAL NOT NULL,
                source TEXT NOT NULL DEFAULT '',
                decided_by TEXT,
                decided_at REAL,
                UNIQUE (content_hash)
            );
            CREATE INDEX IF NOT EXISTS facts_domain_status ON facts(domain, status);
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                outcome TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT ''
            );
            INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version','{SCHEMA_VERSION}');
            COMMIT;
            """)
            self._conn.execute("PRAGMA journal_mode=WAL")

    def _check_ownership(self) -> None:
        app_id = self._conn.execute("PRAGMA application_id").fetchone()[0]
        if app_id != APPLICATION_ID:
            raise ForeignDatabase(f"{self.path}: application_id {app_id:#x} is not ours")
        tables = {r[0] for r in self._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if tables != EXPECTED_TABLES:
            raise ForeignDatabase(f"{self.path}: unexpected tables {sorted(tables ^ EXPECTED_TABLES)}")
        row = self._conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if row is None or int(row["value"]) > SCHEMA_VERSION:
            raise ForeignDatabase(f"{self.path}: schema version {row['value'] if row else 'missing'} "
                                  f"is not supported by this plugin ({SCHEMA_VERSION})")

    # ------------------------------------------------------------ transactions
    @contextmanager
    def _tx(self, mode: str = "IMMEDIATE", retry_s: float = WRITE_RETRY_S):
        """BEGIN <mode> ... COMMIT; rollback on any error. Serialised in-process by an RLock.

        IMMEDIATE = write transaction. DEFERRED with no write = one consistent WAL read snapshot,
        which never waits for writers. busy_timeout is 0, so a locked BEGIN fails at once and is
        retried here until ``retry_s`` has elapsed: the total wait is bounded by ``retry_s``
        (+ one 20 ms sleep), not by retry_s plus SQLite's own timeout."""
        with self._lock:
            deadline = time.monotonic() + retry_s
            while True:
                try:
                    self._conn.execute(f"BEGIN {mode}")
                    break
                except sqlite3.OperationalError as e:
                    busy = "locked" in str(e) or "busy" in str(e)
                    if not busy or time.monotonic() >= deadline:
                        raise
                    time.sleep(0.02)
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            try:
                self._conn.execute("COMMIT")
            except BaseException:
                # A failed COMMIT can leave the transaction open on this shared connection, which
                # would make every later BEGIN fail until restart. Roll back, then re-raise.
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

    def _audit_best_effort(self, actor: str, action: str, outcome: str, **detail) -> bool:
        """Audit for read paths. Returns False (and skips the line) if the db stays busy."""
        try:
            with self._tx(retry_s=BEST_EFFORT_RETRY_S) as c:
                self._audit(c, actor, action, outcome, **detail)
            return True
        except sqlite3.OperationalError:
            return False

    def record(self, actor: str, action: str, outcome: str, **detail) -> None:
        """Audit a decision taken outside the store (e.g. a refused admin command).
        May raise sqlite3.OperationalError if the database stays locked for WRITE_RETRY_S."""
        with self._tx() as c:
            self._audit(c, actor, action, outcome, **detail)

    def bind_root(self, root: str) -> None:
        """Bind this database to ONE Hermes root on first use. Agent names are profile names, which
        are only unique inside one root (every root has its own 'default'), so a second Hermes
        installation pointing at the same file is refused instead of sharing identities."""
        with self._tx() as c:
            row = c.execute("SELECT value FROM meta WHERE key='hermes_root'").fetchone()
            if row is None:
                c.execute("INSERT INTO meta(key,value) VALUES('hermes_root',?)", (root,))
                self._audit(c, "plugin", "bind_root", "ok", root=root)
                return
            bound = row["value"]
        if bound != root:
            raise ForeignDatabase(f"{self.path} is bound to another Hermes installation ({bound}); "
                                  "profile names are only unique within one installation")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _audit(c, actor: str, action: str, outcome: str, **detail) -> None:
        c.execute("INSERT INTO audit(ts,actor,action,outcome,detail) VALUES(?,?,?,?,?)",
                  (_now(), actor, action, outcome, json.dumps(detail, ensure_ascii=False, sort_keys=True)))

    @staticmethod
    def _active(c, agent: str) -> bool:
        row = c.execute("SELECT status FROM agents WHERE agent=?", (agent,)).fetchone()
        return row is not None and row["status"] == "active"

    def _readable_domains(self, c, agent: str) -> list[str]:
        if not self._active(c, agent):
            return []
        return [r["domain"] for r in c.execute("SELECT domain FROM grants WHERE agent=? ORDER BY domain", (agent,))]

    @staticmethod
    def _can_write(c, agent: str, domain: str) -> bool:
        row = c.execute("""SELECT g.can_write FROM grants g JOIN agents a ON a.agent=g.agent
                           WHERE g.agent=? AND g.domain=? AND a.status='active'""", (agent, domain)).fetchone()
        return bool(row and row["can_write"])

    @staticmethod
    def _grants(c, agent: str) -> list[dict]:
        return [dict(domain=g["domain"], access="read+write" if g["can_write"] else "read")
                for g in c.execute("SELECT * FROM grants WHERE agent=? ORDER BY domain", (agent,))]

    @staticmethod
    def _fact(row) -> dict:
        return {k: row[k] for k in ("id", "domain", "subject", "content", "status", "proposed_by",
                                    "proposed_at", "source", "decided_by", "decided_at")}

    # ------------------------------------------------------------ admin (human)
    def grant(self, admin: str, agent: str, domain: str, write: bool) -> dict:
        check_name(agent); check_domain(domain)
        seen = True
        with self._tx() as c:
            row = c.execute("SELECT status FROM agents WHERE agent=?", (agent,)).fetchone()
            if row is not None and row["status"] == "revoked":
                self._audit(c, admin, "grant", "refused", agent=agent, domain=domain,
                            reason="agent is revoked; use reinstate explicitly")
                refused = True
            else:
                refused = False
                # "never seen": not registered, and never appeared in the audit log as an actor
                admin_prefix = f"human@{agent}:"
                seen = row is not None or admin.startswith(admin_prefix) or c.execute(
                    "SELECT 1 FROM audit WHERE actor=? OR substr(actor, 1, ?)=? LIMIT 1",
                    (agent, len(admin_prefix), admin_prefix)).fetchone() is not None
                if row is None:
                    c.execute("INSERT INTO agents(agent,status,created_at) VALUES(?, 'active', ?)", (agent, _now()))
                c.execute("""INSERT INTO grants(agent,domain,can_write,granted_at) VALUES(?,?,?,?)
                             ON CONFLICT(agent,domain) DO UPDATE SET can_write=excluded.can_write,
                             granted_at=excluded.granted_at""", (agent, domain, int(bool(write)), _now()))
                self._audit(c, admin, "grant", "ok", agent=agent, domain=domain, write=bool(write),
                            new_agent=not seen)
        if refused:     # raised after COMMIT so that the refusal stays in the audit log
            raise AccessDenied(f"agent {agent!r} is revoked: run 'reinstate {agent}' first (audited)")
        return {"agent": agent, "domain": domain, "access": "read+write" if write else "read",
                "new_agent": not seen}

    def ungrant(self, admin: str, agent: str, domain: str) -> dict:
        check_name(agent); check_domain(domain)
        with self._tx() as c:
            n = c.execute("DELETE FROM grants WHERE agent=? AND domain=?", (agent, domain)).rowcount
            self._audit(c, admin, "ungrant", "ok" if n else "noop", agent=agent, domain=domain)
        return {"agent": agent, "domain": domain, "removed": bool(n)}

    def revoke(self, admin: str, agent: str) -> dict:
        """Immediate and sticky. Grants are kept for the record but no longer honoured."""
        check_name(agent)
        with self._tx(retry_s=REVOKE_RETRY_S) as c:
            row = c.execute("SELECT status FROM agents WHERE agent=?", (agent,)).fetchone()
            if row is None:
                # Pre-register as revoked: a revoked-before-known agent stays closed.
                c.execute("INSERT INTO agents(agent,status,created_at,revoked_at) VALUES(?, 'revoked', ?, ?)",
                          (agent, _now(), _now()))
            else:
                c.execute("UPDATE agents SET status='revoked', revoked_at=? WHERE agent=?", (_now(), agent))
            self._audit(c, admin, "revoke", "ok", agent=agent, was=row["status"] if row else "unknown")
        return {"agent": agent, "status": "revoked"}

    def reinstate(self, admin: str, agent: str, keep_grants: bool = True) -> dict:
        """Re-activate a revoked agent. Returns the grants that become live again
        (keep_grants=True) or that were dropped (keep_grants=False)."""
        check_name(agent)
        with self._tx() as c:
            row = c.execute("SELECT status FROM agents WHERE agent=?", (agent,)).fetchone()
            if row is None or row["status"] != "revoked":
                self._audit(c, admin, "reinstate", "noop", agent=agent)
                return {"agent": agent, "status": row["status"] if row else "unknown", "grants": [], "dropped": []}
            grants = self._grants(c, agent)
            if not keep_grants:
                c.execute("DELETE FROM grants WHERE agent=?", (agent,))
            c.execute("UPDATE agents SET status='active', revoked_at=NULL WHERE agent=?", (agent,))
            self._audit(c, admin, "reinstate", "ok", agent=agent, keep_grants=keep_grants,
                        grants=[f"{g['domain']}={g['access']}" for g in grants])
        return {"agent": agent, "status": "active",
                "grants": grants if keep_grants else [], "dropped": [] if keep_grants else grants}

    def decide(self, admin: str, fact_id: int, decision: str) -> dict:
        """Human decision on a fact: verified | rejected | forgotten (tombstone, content kept for audit)."""
        if decision not in ("verified", "rejected", "forgotten"):
            raise InvalidInput("decision must be verified, rejected or forgotten")
        with self._tx() as c:
            row = c.execute("SELECT * FROM facts WHERE id=?", (int(fact_id),)).fetchone()
            if row is None:
                raise InvalidInput(f"no fact #{fact_id}")
            if row["status"] == "forgotten":
                raise InvalidInput(f"fact #{fact_id} is forgotten; propose it again instead")
            c.execute("UPDATE facts SET status=?, decided_by=?, decided_at=? WHERE id=?",
                      (decision, admin, _now(), int(fact_id)))
            self._audit(c, admin, decision, "ok", fact=int(fact_id), domain=row["domain"], was=row["status"])
        return {"id": int(fact_id), "status": decision}

    # ------------------------------------------------- admin read views (snapshot)
    def agents(self) -> list[dict]:
        with self._tx("DEFERRED") as c:
            return [dict(agent=a["agent"], status=a["status"], grants=self._grants(c, a["agent"]))
                    for a in c.execute("SELECT * FROM agents ORDER BY agent").fetchall()]

    def pending(self, domain: str | None = None, limit=50) -> list[dict]:
        q, p = "SELECT * FROM facts WHERE status='proposed'", []
        if domain:
            q += " AND domain=?"; p.append(check_domain(domain))
        q += " ORDER BY proposed_at LIMIT ?"; p.append(check_limit(limit, 50))
        with self._tx("DEFERRED") as c:
            return [self._fact(r) for r in c.execute(q, p).fetchall()]

    def audit_tail(self, limit=20) -> list[dict]:
        with self._tx("DEFERRED") as c:
            rows = c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (check_limit(limit, 20),)).fetchall()
        return [dict(id=r["id"], ts=r["ts"], actor=r["actor"], action=r["action"], outcome=r["outcome"],
                     detail=json.loads(r["detail"] or "{}")) for r in rows]

    def stats(self) -> dict:
        with self._tx("DEFERRED") as c:
            facts = {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) n FROM facts GROUP BY status")}
            agents = {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) n FROM agents GROUP BY status")}
            domains = [r["domain"] for r in c.execute("SELECT DISTINCT domain FROM facts ORDER BY domain")]
        return dict(path=str(self.path), facts=facts, agents=agents, domains=domains)

    # ------------------------------------------------------------- agent side
    def access(self, agent: str) -> dict:
        check_name(agent)
        with self._tx("DEFERRED") as c:
            row = c.execute("SELECT status FROM agents WHERE agent=?", (agent,)).fetchone()
            grants = self._grants(c, agent)
        status = row["status"] if row else "unknown"
        return dict(agent=agent, status=status, grants=grants if status == "active" else [])

    def propose(self, agent: str, domain: str, subject: str, content: str, source: str = "") -> dict:
        """Returns {'id','status','duplicate'}. A proposal identical (after normalisation) to an
        existing fact that is proposed, verified OR rejected returns that fact with duplicate=True:
        a rejected fact cannot be re-proposed. Only a forgotten fact can be proposed again."""
        check_name(agent); check_domain(domain)
        subject = _check_text(subject, "subject", MAX_SUBJECT)
        content = _check_text(content, "content", MAX_CONTENT, multiline=True)
        source = _check_text(source, "source", MAX_SOURCE, required=False)
        h = content_hash(domain, subject, content)
        with self._tx() as c:
            if not self._can_write(c, agent, domain):
                self._audit(c, agent, "propose", "denied", domain=domain, reason="no write access")
                denied = True
            else:
                denied = False
                existing = c.execute("SELECT * FROM facts WHERE content_hash=?", (h,)).fetchone()
                if existing is not None and existing["status"] != "forgotten":
                    self._audit(c, agent, "propose", "duplicate", domain=domain, fact=existing["id"])
                    return {"id": existing["id"], "status": existing["status"], "duplicate": True}
                if existing is not None:   # re-proposing a forgotten fact starts a fresh review
                    c.execute("""UPDATE facts SET status='proposed', proposed_by=?, proposed_at=?, source=?,
                                 decided_by=NULL, decided_at=NULL WHERE id=?""", (agent, _now(), source, existing["id"]))
                    fid = existing["id"]
                else:
                    fid = c.execute("""INSERT INTO facts(domain,subject,content,content_hash,status,proposed_by,
                                       proposed_at,source) VALUES(?,?,?,?, 'proposed', ?,?,?)""",
                                    (domain, subject, content, h, agent, _now(), source)).lastrowid
                self._audit(c, agent, "propose", "ok", domain=domain, fact=fid)
        if denied:
            raise AccessDenied(f"agent {agent!r} has no write access to domain {domain!r}")
        return {"id": fid, "status": "proposed", "duplicate": False}

    def search(self, agent: str, query: str = "", domain: str | None = None,
               include_proposed: bool = False, limit=10, audit_action: str | None = "search") -> list[dict]:
        """Facts the agent may read. The access check and the read happen in ONE read snapshot,
        so a concurrent revoke is either fully before (nothing returned) or fully after.
        audit_action: 'search' (tool / command), 'recall' (automatic injection; only audited when
        something is injected or access is denied) or None (no audit line)."""
        check_name(agent)
        if domain is not None:
            check_domain(domain)
        limit = check_limit(limit)
        words = [w for w in normalize(query or "").split() if len(w) > 2][:12]
        denied_reason = None
        doms: list[str] = []
        result: list[dict] = []
        with self._tx("DEFERRED") as c:
            readable = self._readable_domains(c, agent)
            if domain is not None and domain not in readable:
                denied_reason = dict(domain=domain, reason="no read access")
            elif not readable:
                denied_reason = dict(reason="no active grant")
            else:
                doms = [domain] if domain else readable
                states = ("verified", "proposed") if include_proposed else ("verified",)
                q = (f"SELECT * FROM facts WHERE domain IN ({','.join('?' * len(doms))}) "
                     f"AND status IN ({','.join('?' * len(states))})")
                rows = c.execute(q, [*doms, *states]).fetchall()
                scored = []
                for r in rows:
                    hay = normalize(r["subject"] + " " + r["content"])
                    score = sum(hay.count(w) for w in words) if words else 1
                    if score:
                        scored.append((score, r["status"] == "verified", r["proposed_at"], r))
                scored.sort(key=lambda t: (t[0], t[1], t[2]), reverse=True)
                result = [self._fact(t[3]) for t in scored[:limit]]
        if denied_reason is not None:
            if audit_action:
                self._audit_best_effort(agent, audit_action, "denied", **denied_reason)
            raise AccessDenied(f"agent {agent!r} may not read {'domain ' + repr(domain) if domain else 'any domain'}")
        if audit_action and (result or audit_action == "search"):
            self._audit_best_effort(agent, audit_action, "ok", domains=doms, facts=[f["id"] for f in result])
        return result
