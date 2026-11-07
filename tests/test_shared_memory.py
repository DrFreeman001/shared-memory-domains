"""Tests for shared-memory-domains. Run from the plugin dir: python3 tests/test_shared_memory.py
Synthetic data only. No Hermes installation needed: the plugin is driven through a fake ctx."""
import hashlib
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def load_plugin(name="smd_under_test"):
    spec = importlib.util.spec_from_file_location(name, PLUGIN_DIR / "__init__.py",
                                                  submodule_search_locations=[str(PLUGIN_DIR)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


store_mod = load_plugin().store
Store, AccessDenied, InvalidInput = store_mod.Store, store_mod.AccessDenied, store_mod.InvalidInput
ForeignDatabase = store_mod.ForeignDatabase


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class StoreBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "shared.db"
        self.s = Store(self.db)

    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()

    def verified(self, agent, domain, subject, content):
        fid = self.s.propose(agent, domain, subject, content)["id"]
        self.s.decide("human", fid, "verified")
        return fid


class AccessControl(StoreBase):
    def test_unknown_agent_has_no_access(self):
        with self.assertRaises(AccessDenied):
            self.s.search("stranger", "anything")
        with self.assertRaises(AccessDenied):
            self.s.propose("stranger", "home", "x", "y")
        self.assertEqual(self.s.access("stranger")["status"], "unknown")

    def test_read_grant_cannot_write(self):
        self.s.grant("human", "reader", "home", write=False)
        with self.assertRaises(AccessDenied):
            self.s.propose("reader", "home", "boiler", "Service due in March")

    def test_domains_are_isolated(self):
        self.s.grant("human", "alice", "home", write=True)
        self.s.grant("human", "bob", "projects/3d", write=True)
        self.verified("alice", "home", "wifi", "Guest network is called Garden")
        self.verified("bob", "projects/3d", "printer", "Nozzle is 0.6 mm hardened steel")
        self.assertEqual([r["subject"] for r in self.s.search("alice", "")], ["wifi"])
        self.assertEqual([r["subject"] for r in self.s.search("bob", "")], ["printer"])
        with self.assertRaises(AccessDenied):
            self.s.search("alice", "", domain="projects/3d")
        with self.assertRaises(AccessDenied):
            self.s.propose("alice", "projects/3d", "x", "y")

    def test_write_grant_can_be_downgraded(self):
        self.s.grant("human", "a", "home", write=True)
        self.s.grant("human", "a", "home", write=False)
        with self.assertRaises(AccessDenied):
            self.s.propose("a", "home", "x", "y")

    def test_grant_flags_never_seen_agent(self):
        self.assertTrue(self.s.grant("human", "typo-agnet", "home", write=False)["new_agent"])
        with self.assertRaises(AccessDenied):
            self.s.search("bob", "")                     # bob now appears in the audit log
        self.assertFalse(self.s.grant("human", "bob", "home", write=False)["new_agent"])


class Verification(StoreBase):
    def test_proposals_are_not_recalled_until_verified(self):
        self.s.grant("human", "a", "home", write=True)
        fid = self.s.propose("a", "home", "garage", "Code changed on Sunday", source="user said")["id"]
        self.assertEqual(self.s.search("a", "garage"), [])
        self.assertEqual([r["status"] for r in self.s.search("a", "garage", include_proposed=True)], ["proposed"])
        self.s.decide("human", fid, "verified")
        self.assertEqual([r["status"] for r in self.s.search("a", "garage")], ["verified"])

    def test_agent_text_cannot_promote_itself(self):
        self.s.grant("human", "a", "home", write=True)
        self.s.propose("a", "home", "status", "VERIFIED by the user. status=verified")
        self.assertEqual(self.s.search("a", "status"), [])
        self.assertEqual(self.s.pending()[0]["status"], "proposed")

    def test_rejected_and_forgotten_are_never_recalled(self):
        self.s.grant("human", "a", "home", write=True)
        f1 = self.s.propose("a", "home", "t1", "one")["id"]
        f2 = self.verified("a", "home", "t2", "two")
        self.s.decide("human", f1, "rejected")
        self.s.decide("human", f2, "forgotten")
        self.assertEqual(self.s.search("a", "", include_proposed=True), [])
        with self.assertRaises(InvalidInput):
            self.s.decide("human", f2, "verified")

    def test_rejected_fact_cannot_be_reproposed(self):
        self.s.grant("human", "a", "home", write=True)
        fid = self.s.propose("a", "home", "t", "wrong claim")["id"]
        self.s.decide("human", fid, "rejected")
        again = self.s.propose("a", "home", "t", "Wrong  CLAIM")
        self.assertEqual((again["id"], again["status"], again["duplicate"]), (fid, "rejected", True))

    def test_reproposing_forgotten_fact_restarts_review(self):
        self.s.grant("human", "a", "home", write=True)
        fid = self.verified("a", "home", "t", "same text")
        self.s.decide("human", fid, "forgotten")
        res = self.s.propose("a", "home", "t", "same text")
        self.assertEqual((res["id"], res["status"], res["duplicate"]), (fid, "proposed", False))


class Dedup(StoreBase):
    def test_normalised_duplicates_collapse_within_domain_only(self):
        self.s.grant("human", "a", "home", write=True)
        self.s.grant("human", "a", "work", write=True)
        first = self.s.propose("a", "home", "Heating", "Thermostat at 19 °C")
        again = self.s.propose("a", "home", "  heating ", "thermostat   AT 19 °C")
        other = self.s.propose("a", "work", "Heating", "Thermostat at 19 °C")
        self.assertTrue(again["duplicate"])
        self.assertEqual(again["id"], first["id"])
        self.assertNotEqual(other["id"], first["id"])


class Revocation(StoreBase):
    def test_revoke_is_immediate_and_sticky(self):
        self.s.grant("human", "a", "home", write=True)
        self.verified("a", "home", "k", "v")
        self.s.revoke("human", "a")
        with self.assertRaises(AccessDenied):
            self.s.search("a", "")
        with self.assertRaises(AccessDenied):
            self.s.grant("human", "a", "home", write=False)
        self.assertEqual(self.s.access("a"), {"agent": "a", "status": "revoked", "grants": []})
        r = self.s.reinstate("human", "a")
        self.assertEqual(r["grants"], [{"domain": "home", "access": "read+write"}])
        self.assertEqual(len(self.s.search("a", "")), 1)

    def test_refused_grant_on_revoked_agent_is_audited(self):
        # v0.1.1 raised inside the transaction, so this audit line was rolled back
        self.s.revoke("human", "a")
        with self.assertRaises(AccessDenied):
            self.s.grant("human", "a", "home", write=True)
        last = self.s.audit_tail(1)[0]
        self.assertEqual((last["action"], last["outcome"]), ("grant", "refused"))

    def test_reinstate_without_grants(self):
        self.s.grant("human", "a", "home", write=True)
        self.s.grant("human", "a", "work", write=False)
        self.s.revoke("human", "a")
        r = self.s.reinstate("human", "a", keep_grants=False)
        self.assertEqual(r["grants"], [])
        self.assertEqual(len(r["dropped"]), 2)
        self.assertEqual(self.s.access("a"), {"agent": "a", "status": "active", "grants": []})

    def test_revoking_an_unknown_agent_keeps_it_closed(self):
        self.s.revoke("human", "future")
        with self.assertRaises(AccessDenied):
            self.s.grant("human", "future", "home", write=True)

    def test_revoke_from_another_process_handle_applies_at_once(self):
        other = Store(self.db)          # e.g. another Hermes profile using the same file
        try:
            self.s.grant("human", "a", "home", write=True)
            self.verified("a", "home", "k", "v")
            self.assertEqual(len(other.search("a", "")), 1)
            self.s.revoke("human", "a")
            with self.assertRaises(AccessDenied):
                other.search("a", "")
        finally:
            other.close()

    def test_concurrent_revoke_never_leaves_a_partial_read_and_is_bounded(self):
        self.s.grant("human", "a", "home", write=True)
        for i in range(30):
            self.verified("a", "home", f"s{i}", f"value {i}")
        outcomes, durations, other = [], [], Store(self.db)
        stop, warmed = threading.Event(), threading.Event()

        def reader():
            while not stop.is_set():
                t0 = time.monotonic()
                try:
                    outcomes.append(len(other.search("a", "", limit=50)))
                except AccessDenied:
                    outcomes.append("denied")
                except Exception as e:  # noqa: BLE001 - recorded, makes the test fail
                    outcomes.append(f"error:{e}")
                durations.append(time.monotonic() - t0)
                if len(outcomes) >= 20:
                    warmed.set()
        t = threading.Thread(target=reader, daemon=True); t.start()
        try:
            self.assertTrue(warmed.wait(10))
            t0 = time.monotonic()
            self.s.revoke("human", "a")          # must succeed while the reader hammers the db
            revoke_s = time.monotonic() - t0
            n, deadline = len(outcomes), time.monotonic() + 10
            while len(outcomes) < n + 20 and time.monotonic() < deadline:
                time.sleep(0.01)
        finally:
            stop.set(); t.join(10); other.close()
        self.assertTrue(set(outcomes) <= {30, "denied"}, set(outcomes))      # never a partial result
        first = outcomes.index("denied")
        self.assertTrue(all(o == "denied" for o in outcomes[first:]))        # revocation is monotone
        self.assertGreaterEqual(first, 20)
        # explicit bounds instead of "it did not reproduce" (review I5)
        self.assertLess(revoke_s, store_mod.REVOKE_RETRY_S + 0.5, revoke_s)
        self.assertLess(max(durations), store_mod.BEST_EFFORT_RETRY_S + 0.5, max(durations))
        print(f"\n    [timing] revoke {revoke_s * 1000:.0f} ms, reads n={len(durations)} "
              f"max {max(durations) * 1000:.0f} ms", file=sys.stderr)


class Timeouts(StoreBase):
    """With busy_timeout=0 the waits are bounded by the explicit retry budgets (review I5)."""

    def _hold_write_lock(self):
        holder = sqlite3.connect(str(self.db), isolation_level=None, timeout=0)
        holder.execute("BEGIN IMMEDIATE")
        return holder

    def test_read_with_audit_does_not_stall_when_db_is_write_locked(self):
        self.s.grant("human", "a", "home", write=True)
        self.verified("a", "home", "k", "v")
        holder = self._hold_write_lock()
        try:
            t0 = time.monotonic()
            rows = self.s.search("a", "")          # read succeeds, its audit line is skipped
            elapsed = time.monotonic() - t0
        finally:
            holder.execute("ROLLBACK"); holder.close()
        self.assertEqual(len(rows), 1)
        self.assertLess(elapsed, store_mod.BEST_EFFORT_RETRY_S + 0.3, elapsed)

    def test_revoke_wait_is_bounded_by_its_budget(self):
        holder = self._hold_write_lock()
        try:
            with mock.patch.object(store_mod, "REVOKE_RETRY_S", 0.5):
                t0 = time.monotonic()
                with self.assertRaises(sqlite3.OperationalError):
                    self.s.revoke("human", "a")
                elapsed = time.monotonic() - t0
        finally:
            holder.execute("ROLLBACK"); holder.close()
        self.assertGreaterEqual(elapsed, 0.45)
        self.assertLess(elapsed, 1.0, elapsed)


class CommitFailure(StoreBase):
    def test_failed_commit_does_not_leave_the_connection_stuck(self):
        real = self.s._conn

        class Flaky:
            fail_next_commit = True

            def execute(self, sql, *a):
                if sql == "COMMIT" and Flaky.fail_next_commit:
                    Flaky.fail_next_commit = False
                    raise sqlite3.OperationalError("disk I/O error (simulated)")
                return real.execute(sql, *a)

            def __getattr__(self, name):
                return getattr(real, name)
        self.s._conn = Flaky()
        try:
            with self.assertRaises(sqlite3.OperationalError):
                self.s.grant("human", "a", "home", write=True)
            self.assertFalse(real.in_transaction)
            self.s.grant("human", "a", "home", write=True)              # next write works
            self.assertEqual(self.s.access("a")["status"], "active")
        finally:
            self.s._conn = real


class DatabaseOwnership(unittest.TestCase):
    """Review B2: a file the plugin did not create is refused before anything is written."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_foreign_sqlite_database_is_left_byte_identical(self):
        foreign = self.dir / "other-app.db"
        c = sqlite3.connect(str(foreign))
        c.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)")
        c.execute("CREATE TABLE facts (x TEXT)")            # even a table with one of our names
        c.execute("INSERT INTO notes(body) VALUES ('someone else''s data')")
        c.commit(); c.close()
        before = sha(foreign)
        listing = sorted(p.name for p in self.dir.iterdir())
        with self.assertRaises(ForeignDatabase):
            Store(foreign)
        self.assertEqual(sha(foreign), before)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), listing)   # no -wal / -shm created
        self.assertEqual(foreign.read_bytes()[18:20], b"\x01\x01")              # still not WAL

    def test_non_sqlite_file_is_left_untouched(self):
        bad = self.dir / "notes.txt"
        bad.write_bytes(b"plain text, not a database\n" * 10)
        before = sha(bad)
        with self.assertRaises(ForeignDatabase):
            Store(bad)
        self.assertEqual(sha(bad), before)

    def test_our_stamp_with_unexpected_tables_is_refused(self):
        p = self.dir / "shared.db"
        Store(p).close()
        c = sqlite3.connect(str(p)); c.execute("CREATE TABLE intruder (x)"); c.commit(); c.close()
        with self.assertRaises(ForeignDatabase):
            Store(p)

    def test_new_and_empty_files_are_initialised_and_stamped(self):
        for p in (self.dir / "new.db", self.dir / "empty.db"):
            if p.name == "empty.db":
                p.write_bytes(b"")
            Store(p).close()
            header = p.read_bytes()[:100]
            self.assertEqual(header[:16], b"SQLite format 3\x00")
            self.assertEqual(int.from_bytes(header[68:72], "big"), store_mod.APPLICATION_ID)
            Store(p).close()                                   # and it is accepted again


class AuditAndInput(StoreBase):
    def test_denials_are_audited(self):
        with self.assertRaises(AccessDenied):
            self.s.search("stranger", "x")
        last = self.s.audit_tail(1)[0]
        self.assertEqual((last["actor"], last["action"], last["outcome"]), ("stranger", "search", "denied"))

    def test_rejects_bad_input(self):
        self.s.grant("human", "a", "home", write=True)
        for args in [("a", "Home", "s", "c"), ("a", "../etc", "s", "c"), ("a", "home", "", "c"),
                     ("a", "home", "s", "x" * 2001), ("a", "home", "s", "bell\x07"),
                     ("a", "home", "two\nlines", "c"), ("a", "home", "tab\there", "c"),
                     ("a", "home", "s", "rtl \u202e trick"), ("a", "home", "s", "ls\u2028sep")]:
            with self.assertRaises(InvalidInput, msg=repr(args)[:60]):
                self.s.propose(*args)
        with self.assertRaises(InvalidInput):
            self.s.propose("a", "home", "s", "c", source="multi\nline source")
        for bad in ("Bad Name", "work.bot", "Alice"):
            with self.assertRaises(InvalidInput):
                self.s.grant("human", bad, "home", write=True)

    def test_limit_must_be_an_integer(self):
        self.s.grant("human", "a", "home", write=False)
        with self.assertRaises(InvalidInput):
            self.s.search("a", "", limit="lots")
        with self.assertRaises(InvalidInput):
            self.s.search("a", "", limit=2.5)
        self.assertEqual(self.s.search("a", "", limit="3"), [])

    def test_one_line_rendering(self):
        self.assertEqual(store_mod.one_line("a\nb\r\nc\u2028d\te"), "a ⏎ b ⏎ c ⏎ d e")


# ----------------------------------------------------------------- plugin layer
class FakeCtx:
    def __init__(self, profile, settings):
        self.profile_name, self.settings = profile, settings
        self.tools, self.hooks, self.commands = {}, {}, {}

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def register_tool(self, name, toolset, schema, handler, **kw):
        self.tools[name] = handler

    def register_hook(self, name, cb):
        self.hooks[name] = cb

    def register_command(self, name, handler, **kw):
        self.commands[name] = handler


class FakeHermesConstants:
    """Stand-in for Hermes's public ``hermes_constants`` module (the plugin refuses without it).
    get_hermes_home() follows the profile of the ctx the test is currently driving."""

    def __init__(self, root: Path):
        import types
        self.root, self.current = root, "default"
        self.module = types.ModuleType("hermes_constants")
        self.module.get_default_hermes_root = lambda: self.root
        self.module.get_hermes_home = lambda: (self.root if self.current == "default"
                                               else self.root / "profiles" / str(self.current))


class PluginBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "team" / "shared.db"
        self.hc = FakeHermesConstants(Path(self.tmp.name) / "hermes-root")
        self._hc_patch = mock.patch.dict(sys.modules, {"hermes_constants": self.hc.module})
        self._hc_patch.start()
        self.loaded = []
        self.alice = self._load("alice", "smd_alice")
        self.bob = self._load("bob", "smd_bob")

    def tearDown(self):
        self._hc_patch.stop()
        for p in self.loaded:
            for st in p["mod"]._stores.values():
                st.close()
        self.tmp.cleanup()

    def _as(self, who):
        name = getattr(who["ctx"], "profile_name", None)
        self.hc.current = name if isinstance(name, str) else "default"

    def _load(self, profile, modname, db=None):
        mod = load_plugin(modname)
        ctx = FakeCtx(profile, {"db_path": str(db or self.db)})
        mod.register(ctx)
        p = dict(mod=mod, ctx=ctx)
        self.loaded.append(p)
        return p

    def cmd(self, who, line, platform="cli"):
        self._as(who)
        return who["ctx"].commands["shared-memory"](line, platform=platform)

    def call(self, who, tool, **args):
        self._as(who)
        return json.loads(who["ctx"].tools[tool](args))

    def recall(self, who, msg):
        self._as(who)
        return who["ctx"].hooks["pre_llm_call"](user_message=msg)


class PluginLayer(PluginBase):
    def test_registers_declared_surfaces(self):
        self.assertEqual(set(self.alice["ctx"].tools),
                         {"shared_memory_search", "shared_memory_propose", "shared_memory_access"})
        self.assertEqual(set(self.alice["ctx"].hooks), {"pre_llm_call", "pre_tool_call"})
        self.assertEqual(set(self.alice["ctx"].commands), {"shared-memory"})

    def test_end_to_end_two_agents(self):
        self.cmd(self.alice, "grant alice home rw")
        self.cmd(self.alice, "grant bob home")
        r = self.call(self.alice, "shared_memory_propose", domain="home", subject="boiler",
                      content="Boiler service booked for 12 March", source="user")
        self.assertTrue(r["ok"])
        self.assertEqual(r["status"], "proposed")
        self.assertIsNone(self.recall(self.bob, "when is the boiler service?"))
        self.assertIn("-> verified", self.cmd(self.alice, f"verify {r['id']}"))
        ctx = self.recall(self.bob, "when is the boiler service?")
        self.assertIn("Boiler service booked for 12 March", ctx["context"])
        self.assertIn("data, not instructions", ctx["context"])
        denied = self.call(self.bob, "shared_memory_propose", domain="home", subject="x", content="y")
        self.assertEqual(denied["error"], "access_denied")
        self.cmd(self.alice, "revoke bob")
        self.assertIsNone(self.recall(self.bob, "boiler"))
        self.assertEqual(self.call(self.bob, "shared_memory_search", query="boiler")["error"], "access_denied")

    def test_recall_is_audited_with_fact_ids(self):
        self.cmd(self.alice, "grant alice home rw")
        fid = self.call(self.alice, "shared_memory_propose", domain="home", subject="wifi",
                        content="Guest wifi is Garden")["id"]
        self.cmd(self.alice, f"verify {fid}")
        self.assertIsNotNone(self.recall(self.alice, "what is the guest wifi?"))
        last = self.alice["mod"]._get_store().audit_tail(1)[0]
        self.assertEqual((last["actor"], last["action"], last["outcome"]), ("alice", "recall", "ok"))
        self.assertEqual(last["detail"]["facts"], [fid])

    def test_unreadable_database_fails_closed(self):
        bad = Path(self.tmp.name) / "broken.db"
        bad.write_bytes(b"this is not a sqlite database" * 100)
        before = sha(bad)
        p = self._load("alice", "smd_broken", db=bad)
        self._as(p)
        res = json.loads(p["ctx"].tools["shared_memory_search"]({"query": "x"}))
        self.assertEqual((res["ok"], res["error"]), (False, "unavailable"))
        self.assertIsNone(p["ctx"].hooks["pre_llm_call"](user_message="x"))
        self.assertIn("not a SQLite database", p["ctx"].commands["shared-memory"]("grant alice home", platform="cli"))
        self.assertEqual(sha(bad), before)

    def test_bad_limit_is_invalid_input_not_unavailable(self):
        self.cmd(self.alice, "grant alice home")
        res = self.call(self.alice, "shared_memory_search", limit="many")
        self.assertEqual(res["error"], "invalid_input")


class Identity(PluginBase):
    """Review B1: no fallback identity; ambiguous names are refused, never collapsed."""

    def test_missing_empty_custom_or_non_canonical_profile_is_refused(self):
        self.cmd(self.alice, "grant default home rw")        # a 'default' agent exists with rights
        fid = self.call(self.alice, "shared_memory_access")  # sanity: alice works
        self.assertTrue(fid["ok"])
        for bad in (None, "", "custom", "Work Bot", "work.bot", "Alice", 42):
            ctx = self.alice["ctx"]
            ctx.profile_name = bad
            for tool in ("shared_memory_search", "shared_memory_propose", "shared_memory_access"):
                res = self.call(self.alice, tool, domain="home", subject="s", content="c")
                self.assertEqual(res.get("error"), "identity_unavailable", (bad, tool, res))
            self.assertIsNone(self.recall(self.alice, "anything at all"))
            self.assertIn("shared-memory:", self.cmd(self.alice, "grant x home"))
            self.assertNotIn("granted", self.cmd(self.alice, "grant x home"))
        del ctx.profile_name                                  # attribute absent altogether
        self.assertEqual(self.call(self.alice, "shared_memory_access")["error"], "identity_unavailable")

    def test_identity_is_read_on_every_call(self):
        self.cmd(self.alice, "grant alice home rw")
        self.alice["ctx"].profile_name = "bob"               # e.g. a multiplexed gateway turn
        self.assertEqual(self.call(self.alice, "shared_memory_access")["agent"], "bob")
        self.assertEqual(self.call(self.alice, "shared_memory_propose", domain="home", subject="s",
                                   content="c")["error"], "access_denied")

    def test_profile_name_must_match_hermes_home(self):
        """Hermes core falls back to 'default' when it cannot name the profile; the plugin
        cross-checks against HERMES_HOME so that fallback does not inherit 'default' rights."""
        import types
        root = self.hc.root                                   # same installation the db is bound to
        fake = types.ModuleType("hermes_constants")
        fake.get_default_hermes_root = lambda: root
        fake.get_hermes_home = lambda: root / "profiles" / "bob"
        self.cmd(self.alice, "grant default home rw")
        with mock.patch.dict(sys.modules, {"hermes_constants": fake}):
            self.alice["ctx"].profile_name = "default"        # claimed, but HERMES_HOME is bob's
            self.assertEqual(self.call(self.alice, "shared_memory_access")["error"], "identity_unavailable")
            self.alice["ctx"].profile_name = "bob"
            self.assertEqual(self.call(self.alice, "shared_memory_access")["agent"], "bob")
            fake.get_hermes_home = lambda: root                # the real root: 'default' is genuine
            self.alice["ctx"].profile_name = "default"
            self.assertEqual(self.call(self.alice, "shared_memory_access")["status"], "active")
            fake.get_hermes_home = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
            self.assertEqual(self.call(self.alice, "shared_memory_access")["error"], "identity_unavailable")

    def test_database_is_bound_to_one_hermes_installation(self):
        """Every Hermes root has its own 'default' profile: two installations sharing one file would
        merge identities. The first root to use the file owns it; another root is refused."""
        import types

        def fake_hc(root):
            m = types.ModuleType("hermes_constants")
            m.get_default_hermes_root = lambda: root
            m.get_hermes_home = lambda: root
            return m
        root_a, root_b = Path(self.tmp.name) / "install-a", Path(self.tmp.name) / "install-b"
        with mock.patch.dict(sys.modules, {"hermes_constants": fake_hc(root_a)}):
            self.alice["ctx"].profile_name = "default"
            self.assertTrue(self.call(self.alice, "shared_memory_access")["ok"])
        with mock.patch.dict(sys.modules, {"hermes_constants": fake_hc(root_b)}):
            self.bob["ctx"].profile_name = "default"
            res = self.call(self.bob, "shared_memory_access")
            self.assertEqual(res["error"], "unavailable")
            self.assertIn("another Hermes installation", res["message"])
            self.assertIsNone(self.recall(self.bob, "anything"))
            self.assertIn("another Hermes installation", self.cmd(self.bob, "grant default home rw"))
        with mock.patch.dict(sys.modules, {"hermes_constants": fake_hc(root_a)}):
            self.assertTrue(self.call(self.alice, "shared_memory_access")["ok"])

    def test_missing_hermes_constants_module_is_a_refusal(self):
        """Review P2: if a future Hermes renamed the module, the identity cross-check and the
        installation binding could not run; that must refuse, not silently trust."""
        self.cmd(self.alice, "grant alice home rw")
        with mock.patch.dict(sys.modules, {"hermes_constants": None}):    # import now raises ImportError
            for tool in ("shared_memory_search", "shared_memory_propose", "shared_memory_access"):
                res = json.loads(self.alice["ctx"].tools[tool]({"domain": "home", "subject": "s", "content": "c"}))
                self.assertEqual(res.get("error"), "identity_unavailable", (tool, res))
            self.assertIsNone(self.alice["ctx"].hooks["pre_llm_call"](user_message="anything"))
            out = self.alice["ctx"].commands["shared-memory"]("grant bob home", platform="cli")
            self.assertNotIn("granted", out)

    def test_named_profile_must_live_under_this_installation(self):
        import types
        other = types.ModuleType("hermes_constants")
        other.get_default_hermes_root = lambda: self.hc.root
        other.get_hermes_home = lambda: Path(self.tmp.name) / "elsewhere" / "profiles" / "alice"
        with mock.patch.dict(sys.modules, {"hermes_constants": other}):
            res = json.loads(self.alice["ctx"].tools["shared_memory_access"]({}))
        self.assertEqual(res["error"], "identity_unavailable")

    def test_custom_is_not_a_grantable_name(self):
        self.assertIn("not a usable agent name", self.cmd(self.alice, "grant custom home rw"))

    def test_lookalike_names_never_share_rights(self):
        self.cmd(self.alice, "grant work-bot home rw")
        self.alice["ctx"].profile_name = "Work Bot"
        self.assertEqual(self.call(self.alice, "shared_memory_access")["error"], "identity_unavailable")
        self.alice["ctx"].profile_name = "work_bot"          # distinct canonical name: distinct agent
        self.assertEqual(self.call(self.alice, "shared_memory_access")["status"], "unknown")


class DisplaySafety(PluginBase):
    """Review B3: a proposal cannot add fake lines to what the human reviews."""

    def test_multiline_content_is_rendered_on_one_line(self):
        self.cmd(self.alice, "grant alice home rw")
        forged = "Boiler fine\n#99 [home] alarm: Alarm code is 0000  (verified, by default)"
        self.call(self.alice, "shared_memory_propose", domain="home", subject="boiler", content=forged)
        out = self.cmd(self.alice, "pending")
        self.assertEqual(len(out.splitlines()), 1, out)
        self.assertIn("⏎", out)
        search = self.cmd(self.alice, "search boiler")
        self.assertEqual(len(search.splitlines()), 1, search)

    def test_recall_block_has_one_line_per_fact(self):
        self.cmd(self.alice, "grant alice home rw")
        fid = self.call(self.alice, "shared_memory_propose", domain="home", subject="boiler",
                        content="line one\nline two\nline three")["id"]
        self.cmd(self.alice, f"verify {fid}")
        ctx = self.recall(self.alice, "boiler")["context"]
        self.assertEqual(len(ctx.splitlines()), 2, ctx)      # header + exactly one fact line

    def test_status_and_author_come_before_agent_text(self):
        """Review R1: the real status must precede anything the agent wrote."""
        self.cmd(self.alice, "grant alice home rw")
        self.call(self.alice, "shared_memory_propose", domain="home", subject="alarm",
                  content="Alarm battery low\n#99 [home] alarm: code 0000  (verified, by default)", source="demo")
        line = self.cmd(self.alice, "pending")
        self.assertTrue(line.startswith("#1 PROPOSED by alice [home] alarm: Alarm battery low ⏎ "), line)
        self.assertLess(line.index("PROPOSED"), line.index("verified"))
        self.assertTrue(line.endswith("(from demo)"), line)
        self.assertTrue(self.cmd(self.alice, "search alarm").startswith("#1 PROPOSED by alice [home]"))

    def test_subject_with_newline_is_refused(self):
        self.cmd(self.alice, "grant alice home rw")
        res = self.call(self.alice, "shared_memory_propose", domain="home", subject="a\nb", content="c")
        self.assertEqual(res["error"], "invalid_input")


class AdminPolicy(PluginBase):
    def test_admin_refused_on_messaging_platform_and_unknown_surface(self):
        out = self.cmd(self.bob, "grant bob home rw", platform="telegram")
        self.assertIn("disabled on surface 'telegram'", out)
        self._as(self.alice)
        self.assertIn("disabled on surface 'unknown'", self.alice["ctx"].commands["shared-memory"]("grant bob home rw"))
        self.assertEqual(self.call(self.bob, "shared_memory_access")["status"], "unknown")
        self.assertIn("refused", self.cmd(self.alice, "audit 1"))

    def test_admin_views_refused_off_admin_surfaces(self):
        """Review v0.1.1: pending/audit/agents/status leak across domains; only help+search remain."""
        self.cmd(self.alice, "grant alice home rw")
        self.cmd(self.alice, "grant bob home")
        fid = self.call(self.alice, "shared_memory_propose", domain="home", subject="boiler",
                        content="Boiler service on 12 March")["id"]
        self.call(self.alice, "shared_memory_propose", domain="home", subject="boiler draft",
                  content="Boiler maybe broken (unconfirmed)")
        self.cmd(self.alice, f"verify {fid}")
        for view in ("pending", "audit", "agents", "status"):
            out = self.cmd(self.bob, view, platform="telegram")
            self.assertIn("disabled on surface 'telegram'", out, view)
            self.assertNotIn("Boiler", out)
        self.assertIn("/shared-memory", self.cmd(self.bob, "help", platform="telegram"))
        out = self.cmd(self.bob, "search boiler", platform="telegram")
        self.assertIn("Boiler service on 12 March", out)
        self.assertNotIn("unconfirmed", out)                      # proposals stay hidden off admin surfaces
        refused = [a for a in self.alice["mod"]._get_store().audit_tail(10)
                   if a["outcome"] == "refused" and a["actor"].endswith(":telegram")]
        self.assertEqual(sorted(a["action"] for a in refused), ["agents", "audit", "pending", "status"])

    def test_default_admin_surface_is_cli_only(self):
        """Review P1: on the TUI gateway the surface name is declared by the client (session.create
        'source'), and a remote desktop may arrive as 'tui' or 'desktop'. Default: 'cli' only."""
        self.assertEqual(self.alice["mod"].LOCAL_PLATFORMS, "cli")
        for surface in ("tui", "desktop", "telegram", "api_server", "local"):
            self.assertIn(f"disabled on surface '{surface}'",
                          self.cmd(self.alice, "grant bob home", platform=surface), surface)
        self.assertIn("granted", self.cmd(self.alice, "grant bob home", platform="cli"))
        self.alice["ctx"].settings["admin_platforms"] = "cli,desktop"      # explicit opt-in
        self.assertIn("granted", self.cmd(self.alice, "grant bob work", platform="desktop"))
        self.assertIn("disabled on surface 'tui'", self.cmd(self.alice, "grant bob x", platform="tui"))

    def test_admin_profiles_restricts_who_administers(self):
        self.alice["ctx"].settings["admin_profiles"] = "alice"
        self.bob["ctx"].settings["admin_profiles"] = "alice"
        self.assertIn("not an admin profile", self.cmd(self.bob, "grant bob home rw"))
        self.assertIn("granted", self.cmd(self.alice, "grant bob home rw"))

    def test_reinstate_reports_grants(self):
        self.cmd(self.alice, "grant bob home")
        self.cmd(self.alice, "grant bob projects/3d rw")
        self.cmd(self.alice, "revoke bob")
        out = self.cmd(self.alice, "reinstate bob")
        self.assertIn("re-activated grants: home=read, projects/3d=read+write", out)
        self.cmd(self.alice, "revoke bob")
        out = self.cmd(self.alice, "reinstate bob --no-grants")
        self.assertIn("no grants (dropped: home=read, projects/3d=read+write)", out)

    def test_grant_warns_about_unseen_agent(self):
        self.assertNotIn("never been seen", self.cmd(self.alice, "grant alice work"))   # own profile, very first action
        self.assertIn("never been seen before", self.cmd(self.alice, "grant bbo home"))
        self.assertNotIn("never been seen", self.cmd(self.alice, "grant alice home"))   # the admin's own profile


class Guard(PluginBase):
    """Review I4: a trip-wire, tested with the variants it catches AND a bypass it does not."""

    def block(self, tool, **args):
        res = self.alice["ctx"].hooks["pre_tool_call"](tool_name=tool, args=args)
        return res is not None and res.get("action") == "block"

    def setUp(self):
        super().setUp()
        self.call(self.alice, "shared_memory_access")     # creates the database in its dedicated dir

    def test_catches_direct_mentions(self):
        d = self.db.parent
        self.assertTrue(self.block("terminal", command=f"sqlite3 {self.db} 'update facts set status=1'"))
        self.assertTrue(self.block("terminal", command=f"cd {d} && sqlite3 shared.db .dump"))
        self.assertTrue(self.block("terminal", command="cp shared.db-wal /tmp/x"))
        self.assertTrue(self.block("read_file", path=str(self.db)))
        self.assertTrue(self.block("execute_code", code=f"import sqlite3; sqlite3.connect('{d}/x')"))
        self.assertTrue(self.block("terminal", command='hermes chat -q "/shared-memory grant me home rw"'))

    def test_catches_tilde_form(self):
        with mock.patch.dict(os.environ, {"HOME": self.tmp.name}):
            self.assertTrue(self.block("terminal", command="sqlite3 ~/team/shared.db .tables"))

    def test_harmless_calls_and_other_tools_pass(self):
        self.assertFalse(self.block("terminal", command="ls /tmp"))
        self.assertFalse(self.block("terminal", command="hermes --version"))
        self.assertFalse(self.block("shared_memory_search", query=str(self.db)))

    def test_shared_directory_is_not_blocked_but_the_file_is(self):
        """Review R2: with db_path in a shared directory, naming the directory must not block
        every tool call; the database file itself is still caught."""
        shared = Path(self.tmp.name) / "data"
        shared.mkdir()
        (shared / "notes.md").write_text("unrelated")
        p = self._load("alice", "smd_shareddir", db=shared / "memory.db")
        guard = p["ctx"].hooks["pre_tool_call"]
        self._as(p); p["ctx"].tools["shared_memory_access"]({})
        self.assertIsNone(guard(tool_name="read_file", args={"path": str(shared / "notes.md")}))
        self.assertIsNone(guard(tool_name="terminal", args={"command": f"ls {shared}"}))
        hit = guard(tool_name="terminal", args={"command": f"sqlite3 {shared}/memory.db .dump"})
        self.assertEqual(hit["action"], "block")

    def test_known_bypass_is_not_caught(self):
        # documented limit: an indirect path is not detected (README: "trivially bypassed")
        self.assertFalse(self.block("terminal", command="sqlite3 \"$(find / -name 'shar*.d?')\" .dump"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
