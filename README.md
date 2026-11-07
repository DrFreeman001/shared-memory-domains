# shared-memory-domains

**One memory, several Hermes agents, and a human who decides what becomes true.**

Not another memory: a control layer. Who can read what, and nothing circulates without human validation.

Each Hermes profile is an *agent*. Agents share one SQLite memory split into **domains**
(`home`, `projects/3d`, `work`…). You grant each agent read or read+write access per domain.
Agents can only **propose** facts; nothing is recalled until **you verify it**. Revoking an agent
stops its next read, and it stays revoked until you explicitly reinstate it.
Writes and human decisions are audited atomically; reads and recalls are audited best-effort.

> **Cooperative access control, not a sandbox.** Read [Guarantees and their limits](#guarantees-and-their-limits)
> before relying on it.

## Why

Most memory plugins give one agent one memory. Once you run several agents (a home assistant, a
coding agent, a work profile), you face questions a single memory cannot answer:

- *Should my coding agent see my home notes?* → per-domain grants.
- *An agent wrote something wrong and now it's "remembered".* → proposals stay unconfirmed until
  a human verifies them; agent text can never promote itself.
- *I stopped trusting one agent.* → sticky revocation, effective on its next read.
- *Who wrote what, and who allowed it?* → provenance kept separate from verification, plus an audit log.

## What it adds to Hermes

| Surface | What it does |
|---|---|
| `shared_memory_search` (tool) | Search the domains this agent may read. Verified facts only, unless `include_proposed`. |
| `shared_memory_propose` (tool) | Propose a fact to a domain the agent may write. Status: `proposed`. |
| `shared_memory_access` (tool) | Show this agent's grants and status. |
| `pre_llm_call` (hook) | Recalls up to `inject_limit` **verified** facts matching the user's message, one line per fact, framed as data, not instructions. |
| `pre_tool_call` (hook) | Trip-wire: blocks the agent's own `terminal`, `execute_code`, `read_file`, `write_file`, `patch` and `search_files` calls that **name** the database (see limits). |
| `/shared-memory` (slash command) | Human administration: `grant`, `ungrant`, `revoke`, `reinstate`, `pending`, `verify`, `reject`, `forget`, `search`, `audit`, `agents`, `status`. |

## Quick start

```bash
hermes plugins install shared-memory-domains     # once listed
```

In every profile that should share the memory, point the plugin at the same file
(Settings → Plugins, or the profile's `config.yaml`):

```yaml
plugins:
  entries:
    shared-memory-domains:
      settings:
        db_path: ~/hermes-shared/memory.db     # a NEW file, in a DEDICATED directory, on a local disk
```

Then, as the human, from `hermes` in a terminal on that machine (the only admin surface by default, see below):

```
/shared-memory grant default home rw       # your main agent reads and writes "home"
/shared-memory grant coder projects/3d rw  # the coding profile only sees "projects/3d"
/shared-memory grant coder home            # ...and may read "home"
/shared-memory pending                     # e.g. "#2 PROPOSED by coder [home] alarm: battery low ⏎ …  (from user)"
/shared-memory verify 12                   # make fact #12 recallable
/shared-memory revoke coder                # effective on coder's next read; a later grant will not re-open it
/shared-memory reinstate coder             # lists the grants that come back
/shared-memory reinstate coder --no-grants # ...or bring it back with no grant at all
/shared-memory audit 20
```

With no grant, an agent sees nothing: unknown agents are **denied by default**. A `grant` to a
name that has never been seen prints a warning: check it matches the Hermes profile name.

### Identity

The agent is the Hermes profile name (`ctx.profile_name`), read on every call. It is never
guessed: if it is missing, empty, `custom` (a `HERMES_HOME` outside the profiles directory), not in
canonical form (`a-z 0-9 _ -`), or does not match the active `HERMES_HOME`, every agent-side
operation is refused (`identity_unavailable`). The last check exists because Hermes itself reports
`default` when it cannot work the profile out; without it, an unidentified caller would get the
`default` agent's rights. It uses Hermes's public `hermes_constants` module; if that module cannot be
imported (for example after a rename in a future Hermes), every operation is refused rather than trusted.

Profile names are only unique **within one Hermes installation**: every installation has its own
`default` (Hermes also calls a `HERMES_HOME` outside any `profiles/` directory `default`). So the
first installation that uses a database file owns it, and another installation pointing at the same
file is refused (`unavailable: … bound to another Hermes installation`). Share a database between
profiles of one installation only. The binding is by path: two containers that mount the same Hermes
root at the same path look like one installation to the plugin.

### Who may administer

Changing grants, deciding on facts, and the cross-domain views (`pending`, `audit`, `agents`,
`status`) are allowed only from the surfaces in `admin_platforms`, **default `cli`**. Everywhere else
(Telegram, Discord, any messaging platform, the TUI, the desktop app, or a surface Hermes does not
name) they are **refused and audited**. There, only `help` and `search` remain, and `search` returns
only the verified facts that profile may read. Optionally restrict administration to some profiles
with `admin_profiles: default`.

Why not `tui` and `desktop` by default: Hermes passes the plugin a surface *name*, not proof of who is
typing. On the messaging gateway the name comes from the platform adapter (`telegram`, `discord`, …),
which chat users cannot choose. But on the TUI gateway, which serves the TUI and the desktop app,
**local or remote**, the name is the session `source` the client declares when it creates the session,
and the desktop app may also run against a backend on another machine (SSH or URL). So `tui` and
`desktop` do not mean "someone at this machine". Add them (`admin_platforms: cli,desktop`) only if
nobody else can reach your Hermes backend. Even `cli` is a declared name on that gateway: the rule
protects you from people who message your bot, not from people who can already sign in to your backend.

### Where to put the database

- On a **local disk of the host that runs Hermes**. SQLite WAL mode does not work on network
  shares (NFS, SMB) or across containers on different machines. On Unraid, prefer an `appdata`
  path on a disk or cache pool rather than `/mnt/user` (FUSE layer).
- In a **dedicated directory**. The guard treats the directory as part of the database only when it
  holds nothing else; in a shared directory it matches the file name alone (and logs a warning once).
- A **new** file, or one this plugin created. The file is stamped with `PRAGMA application_id`;
  any other file, including another application's SQLite database, is refused before anything is
  written to it (it is not switched to WAL, no table is created).

## Guarantees and their limits

What is enforced, inside Hermes:
- **Default deny**: unknown, revoked, unidentified or un-granted agents get no read and no write.
- **One snapshot per read**: the access check and the read happen in one SQLite read snapshot, so
  a concurrent revoke is either entirely before a read (nothing returned) or entirely after.
- **Bounded waits**: SQLite's own busy timeout is 0; every wait is an explicit, bounded retry.
  A read never waits for writers; its best-effort audit line waits at most ~0.2 s. A write or human
  decision gives up after 5 s; a revoke keeps trying for 10 s.
- **No self-promotion**: only a human decision changes a fact's status.
- **One line per fact** wherever a human or an agent reads facts: line breaks in content are shown
  as `⏎`; subjects and sources cannot contain line breaks, tabs or bidi control characters. In
  `pending` and `search` the real status and author come first (`#2 PROPOSED by coder [home] …`),
  before any text an agent wrote.
- **Deduplication** per domain on normalised (NFKC, case, whitespace) subject + content. A proposal
  identical to a **rejected** fact returns that rejected fact (`duplicate: true`) and cannot be
  re-proposed; only a `forget`-ed fact can be proposed again.
- **Fail closed** on a foreign, broken or newer-schema database: tools return `unavailable`,
  recall is skipped, admin commands change nothing.

What it is **not**:
- **Not an OS sandbox.** The plugin runs inside the Hermes process. Anything running as the same
  OS user can open the SQLite file directly.
- **An agent that has `terminal` or code-execution tools can do anything you can do on this
  machine, including administering this plugin** (for example by editing the database, or by starting
  another Hermes process on an admin surface). The admin-surface rule protects you from *people who
  message your bot*, not from *the agent itself*. If you need that, do not give the agent shell tools.
- **The `pre_tool_call` guard is a trip-wire.** It catches direct mentions of the database (absolute
  path, `~/` form, file name including `-wal`/`-shm`, its directory if dedicated, the plugin data directory)
  and shell commands that mention both `hermes` and `shared-memory`. It is **trivially bypassed** by
  indirect paths (`$(find …)`, variables, encodings).
- **Revoke and forget stop future recall; they cannot take back what was already shown.** A fact
  injected into a conversation stays in that conversation, in the session history, and in **any
  memory provider that records conversations** (Honcho, Mem0, …), outside this plugin's domains.
  For demos and sensitive domains, run the profiles without an external memory provider.
- **Reinstate brings back the grants** the agent had when revoked (it lists them), unless you use
  `--no-grants`.
- **Audit is not complete for reads.** Writes, decisions and admin refusals are audited in the same
  transaction as the change (if that audit line cannot be written, the change does not happen; a
  refused admin command stays refused even if its audit line fails). Reads, recalls and read denials
  are audited best-effort and are skipped when the database stays busy.
- **No anti-rollback**: restoring an old copy of the database restores old grants.
- **Summaries are not checked against their origin.** A summary proposed from a confined domain is
  not compared with the original text (no verbatim-copy refusal); the human sees its `source` in
  `/shared-memory pending` before verifying.
- **Agent identity = Hermes profile name.** Two processes running the same profile are the same agent.

## Roadmap

- Multi-host sync: not yet. Profiles share memory on one host only (local SQLite, WAL).

## Data and disclosure

- Reads and writes only the SQLite file you configure (default: `plugin-data/shared-memory-domains/shared.db`
  in the profile). With a shared `db_path` it reads and writes **outside** its own data directory, by design.
- Injects verified facts into the agent's context each turn (`inject_limit`, default 6; `0` disables).
- No network calls, no telemetry, no subprocesses, no credentials.
- Do not store secrets or health data in it; the tool descriptions tell the agent the same.

## Tests

```bash
python3 tests/test_shared_memory.py           # 56 tests, synthetic data only (a fake hermes_constants module is installed)
```

They cover default deny, identity refusal (missing, `custom`, non-canonical, HERMES_HOME mismatch,
another Hermes installation, missing `hermes_constants`), default admin surface,
domain isolation, verification, self-promotion attempts, one-line rendering, dedup and rejected
duplicates, sticky revocation across two connections, revoke under concurrent reads with explicit
time bounds, bounded waits under a held write lock, foreign databases left byte-identical, audit of
recalls and refusals, admin-surface policy (writes and cross-domain views), `reinstate` output, the
guard (including a bypass it does **not** catch) and fail-closed behaviour. The plugin was also
exercised end to end through Hermes's own plugin loader, tool registry, hook dispatch and
slash-command dispatch with two isolated profiles.

## License

MIT
