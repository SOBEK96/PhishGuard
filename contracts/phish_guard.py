# v0.3.0
# { "Depends": "py-genlayer:5jycge4q8k23462jtb0b9fyey1s9qz928sz2nbrd9mg4sxqg2qng" }

# PhishGuard -- Decentralized Web3 Anti-Phishing & Drainer Triage Oracle.
#
# Reporters stake a bond and submit a canonical `target_id` plus the SHA-256
# commitment to its indicator attributes. GenVM validators then read THREE
# governed threat-intelligence feeds hosted on three distinct hostnames AND three
# distinct operators, aggregate the answers with a fault-tolerant 2-of-3 rule,
# and settle the report into one discrete tier:
#
#   TIER_0_SAFE        0  clean / official domain       -> bond forfeited
#   TIER_1_SUSPICIOUS  1  anomaly, no drainer payload   -> 48h QUARANTINE_WATCH
#   TIER_2_DRAINER     2  confirmed wallet drainer      -> BLACKLISTED
#
# Design rules enforced by this file:
#  * NO Python float anywhere. Ratios are integer basis points (0..10000); money
#    is atto-scale (wei) integers; every view returns int / str / bool / list /
#    dict only, so `gen_call` can always ABI-encode the result.
#  * Reporters never supply a fetch URL. The URL is built from a governed feed
#    base and a validated slug, so there is no SSRF / arbitrary-fetch surface.
#  * An outage is never a slash. `_aggregate` returns QUORUM_FAILURE whenever an
#    unreachable source could still complete a 2-of-3 quorum.
#  * The governor can rotate feeds and register brands but has NO code path that
#    moves value: slashed bonds sit in `locked_slash_reserve`, bounties in
#    `reserved_bounty`, and every outflow is a pull-pattern `claim_payout`.
#  * No LLM is used: a security classification that gates wallet UX must be
#    reproducible byte-for-byte by every validator.

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

import genlayer as gl
from genlayer import Address, u256
from genlayer.storage import TreeMap

# genvm-lint matches the bare decorator name `allow_storage`; bind it to the
# runner's own storage decorator.
allow_storage = gl.storage.allow

# --- Deterministic business errors ------------------------------------------
ERR_UNAUTHORIZED = "ERR_UNAUTHORIZED"
ERR_STATE = "ERR_INVALID_STATE"
ERR_PARAMS = "ERR_INVALID_PARAMS"
ERR_BOND = "ERR_INSUFFICIENT_BOND"
ERR_FEED = "ERR_INVALID_FEED"
ERR_TIMELOCK = "ERR_TIMELOCK_ACTIVE"
ERR_NOTHING = "ERR_NOTHING_TO_CLAIM"
ERR_BLOCKED = "ERR_TARGET_BLOCKED"
ERR_TRANSFER = "ERR_TRANSFER_FAILED_RESTORED"
ERR_POOL = "ERR_POOL_LIQUIDITY"

# --- Threat tiers -----------------------------------------------------------
TIER_0_SAFE = 0
TIER_1_SUSPICIOUS = 1
TIER_2_DRAINER = 2
TIER_NAMES = {0: "TIER_0_SAFE", 1: "TIER_1_SUSPICIOUS", 2: "TIER_2_DRAINER"}

# --- Aggregate verdicts -----------------------------------------------------
VERDICT_SAFE_OR_UNFOUNDED = 0
VERDICT_VERIFIED_REPORT = 1
VERDICT_QUORUM_FAILURE = 2

# --- Source outcomes (per feed) ---------------------------------------------
SRC_OK = "OK"
SRC_NOT_FOUND = "NOT_FOUND"
SRC_OUTAGE = "OUTAGE"

# --- Feed record status / revision kinds ------------------------------------
REC_ACTIVE = "ACTIVE"
REC_FALSE_POSITIVE = "FALSE_POSITIVE_REVOKED"
REC_REMEDIATED = "REMEDIATED"
VALID_REC_STATUS = (REC_ACTIVE, REC_FALSE_POSITIVE, REC_REMEDIATED)
REV_NONE = 0
REV_FALSE_POSITIVE = 1
REV_REMEDIATED = 2

# --- Target lifecycle status ------------------------------------------------
ST_UNKNOWN = "UNKNOWN"
ST_DISMISSED = "DISMISSED"
ST_QUARANTINED = "QUARANTINED"
ST_BLACKLISTED = "BLACKLISTED"
ST_CLEARED = "CLEARED"
ST_REVOKED = "REVOKED_FALSE_POSITIVE"
ST_REMEDIATED = "REMEDIATED"

# --- Economics (atto-scale integers; 1 GEN == 10 ** 18) ----------------------
ATTO = 10**18
BPS_DENOM = 10000
MIN_REPORT_BOND = 10**16  # 0.01 GEN
MIN_APPEAL_BOND = 10**16  # 0.01 GEN
TIER2_BOUNTY = 2 * 10**16  # 0.02 GEN fixed tier bounty
MIN_POOL_DEPOSIT = 10**15  # 0.001 GEN
MAX_EPOCH_BOUNTY_BPS = 2000  # <= 20% of the bounty pool per epoch
MAX_BOUNTIES_PER_REPORTER_EPOCH = 3
MIN_LOCKED_SHARES = 1000  # dead shares: the pool can never be fully redeemed
SHARE_OFFSET = 1000  # virtual offset against share-price inflation
RESERVE_FLOOR = 10 * MIN_REPORT_BOND  # slash float kept for challenger rewards

# --- Time windows (seconds) -------------------------------------------------
COOLDOWN_WINDOW = 24 * 3600  # bounty / bond vesting cooldown
QUARANTINE_WATCH = 48 * 3600  # tier-1 watch window
FEED_TIMELOCK = 7 * 24 * 3600  # feed rotation timelock
EPOCH_SECONDS = 7 * 24 * 3600  # bounty cap epoch

NUM_SLOTS = 3
SLOT_NAMES = ("A", "B", "C")
COMMIT_PREFIX = "phishguard.v1"
MAX_BODY_BYTES = 8192
MAX_CLOCK_SKEW = 3600  # a feed record may not be dated further ahead than this
# Multi-part public suffixes / multi-tenant hosts: a listing of one of these
# must NEVER be inherited by the (unrelated) sites beneath it.
PUBLIC_SUFFIXES = (
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.kr", "co.in",
    "co.nz", "co.za", "com.br", "com.cn", "com.mx", "com.tr", "com.sg", "com.ar", "com.hk",
    "github.io", "gitlab.io", "vercel.app", "netlify.app", "pages.dev", "workers.dev", "web.app",
    "firebaseapp.com", "herokuapp.com", "blogspot.com", "azurewebsites.net", "appspot.com",
)
HEX_CHARS = "0123456789abcdef"
SLUG_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789.-"
LABEL_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789_-"
BANNED_HOST_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".corp")


# =============================================================================
# Pure helpers (no storage, no clock, no network) -- unit-testable directly.
# =============================================================================
def _hex(addr) -> str:
    """Canonical lowercase account key (every balance map uses this)."""
    return addr.as_hex.lower()


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _valid_target_id(s) -> bool:
    if not isinstance(s, str) or len(s) < 3 or len(s) > 128:
        return False
    for ch in s:
        if ch not in SLUG_CHARS:
            return False
    if s[0] in ".-" or s[-1] in ".-" or ".." in s:
        return False
    for label in s.split("."):
        if label == "" or label[0] == "-" or label[-1] == "-":
            return False
    return True


def _parent_chain(target_id: str) -> list:
    """Registrable-parent candidates of a hostname, nearest first. Always keeps
    at least two labels and stops at a public suffix / multi-tenant host."""
    labels = target_id.split(".")
    out = []
    for i in range(1, len(labels) - 1):
        parent = ".".join(labels[i:])
        if parent in PUBLIC_SUFFIXES:
            break
        out.append(parent)
    return out


def _tier_of_status(status: str) -> int:
    if status == ST_BLACKLISTED:
        return 2
    if status == ST_QUARANTINED:
        return 1
    return 0


def _valid_hash(s) -> bool:
    if not isinstance(s, str) or len(s) != 64:
        return False
    for ch in s:
        if ch not in HEX_CHARS:
            return False
    return True


def _valid_label(s, max_len: int = 64) -> bool:
    if not isinstance(s, str) or len(s) < 1 or len(s) > max_len:
        return False
    for ch in s:
        if ch not in LABEL_CHARS:
            return False
    return True


def _valid_operator(s) -> bool:
    if not isinstance(s, str) or len(s) < 3 or len(s) > 64:
        return False
    for ch in s:
        if ch not in SLUG_CHARS:
            return False
    return "." in s and s[0] not in ".-" and s[-1] not in ".-"


def _commitment(target_id: str, campaign_id: str, brand_id: str, first_seen_ts: int) -> str:
    """SHA-256 over the canonical indicator attributes."""
    raw = f"{COMMIT_PREFIX}|{target_id}|{campaign_id}|{brand_id}|{int(first_seen_ts)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _feed_host(base_url) -> str:
    """Return the lowercase hostname of a feed base URL, or "" if the URL is not
    an acceptable commit-pinned https feed root."""
    if not isinstance(base_url, str) or len(base_url) < 12 or len(base_url) > 300:
        return ""
    if not base_url.endswith("/"):
        return ""
    for ch in base_url:
        if ord(ch) < 33 or ord(ch) > 126:
            return ""
    try:
        parts = urlsplit(base_url)
        host = parts.hostname or ""
        port = parts.port
    except Exception:
        return ""
    if parts.scheme != "https" or host == "" or port is not None:
        return ""
    if parts.username is not None or parts.password is not None:
        return ""
    if parts.query != "" or parts.fragment != "" or "@" in parts.netloc:
        return ""
    if parts.netloc != parts.netloc.lower() or "." not in host:
        return ""
    for ch in host:
        if ch not in SLUG_CHARS:
            return ""
    # Reject IP literals (every label numeric) and private-suffix hostnames.
    labels = host.split(".")
    if all(lbl.isdigit() for lbl in labels):
        return ""
    for suffix in BANNED_HOST_SUFFIXES:
        if host.endswith(suffix):
            return ""
    if "" in labels:
        return ""
    return host


def _parse_record(data, target_id: str, max_ts: int):
    """Validate one feed record. Returns a normalized dict or None (schema
    error -> the source counts as an OUTAGE, never as a slash)."""
    if not isinstance(data, dict):
        return None
    if data.get("target_id") != target_id:
        return None
    tier: int = data["tier"] if "tier" in data else -1
    status = data.get("status")
    ev = data.get("evidence_hash")
    pub: int = data["published_ts"] if "published_ts" in data else -1
    first: int = data["first_seen_ts"] if "first_seen_ts" in data else -1
    camp = data.get("campaign_id")
    brand = data.get("brand_id")
    if not _is_int(tier) or tier < 0 or tier > 2:
        return None
    if status not in VALID_REC_STATUS:
        return None
    if not _valid_hash(ev):
        return None
    # A record dated in the future (beyond a small clock-skew allowance) is a
    # schema error: it would otherwise poison the target's override high-water
    # mark and silence every genuine later report.
    if not _is_int(pub) or pub <= 0 or pub > max_ts:
        return None
    if not _is_int(first) or first < 0 or first > max_ts:
        return None
    if not isinstance(camp, str) or len(camp) > 64:
        return None
    if not isinstance(brand, str) or len(brand) > 64:
        return None
    return {
        "tier": tier,
        "status": status,
        "hash": ev,
        "published_ts": pub,
        "first_seen_ts": first,
        "campaign_id": camp,
        "brand_id": brand,
    }


def _source_from_response(status, body, target_id: str, max_ts: int) -> dict:
    """Map one HTTP response onto SRC_OK / SRC_NOT_FOUND / SRC_OUTAGE."""
    if status == 404 or status == 410:
        return {"k": SRC_NOT_FOUND}
    if not _is_int(status) or status != 200:
        return {"k": SRC_OUTAGE}  # 3xx, 4xx(other), 429, 5xx, missing status
    try:
        if isinstance(body, (bytes, bytearray)):
            if len(body) > MAX_BODY_BYTES:
                return {"k": SRC_OUTAGE}
            text = bytes(body).decode("utf-8")
        elif isinstance(body, str):
            if len(body) > MAX_BODY_BYTES:
                return {"k": SRC_OUTAGE}
            text = body
        else:
            return {"k": SRC_OUTAGE}
        rec = _parse_record(json.loads(text), target_id, max_ts)
    except Exception:
        return {"k": SRC_OUTAGE}
    if rec is None:
        return {"k": SRC_OUTAGE}
    return {"k": SRC_OK, "rec": rec}


def _is_confirming(src: dict, expected_hash: str) -> bool:
    """A source CONFIRMS a threat only if it carries an ACTIVE tier >= 1 record
    whose evidence commitment equals the reporter's."""
    if src["k"] != SRC_OK:
        return False
    rec = src["rec"]
    return rec["status"] == REC_ACTIVE and rec["tier"] >= 1 and rec["hash"] == expected_hash


def _revision_of(sources: list) -> int:
    """Revision kind (FALSE_POSITIVE_REVOKED / REMEDIATED) backed by >= 2 sources."""
    fp = 0
    rem = 0
    for s in sources:
        if s["k"] == SRC_OK:
            if s["rec"]["status"] == REC_FALSE_POSITIVE:
                fp += 1
            elif s["rec"]["status"] == REC_REMEDIATED:
                rem += 1
    if fp >= 2:
        return REV_FALSE_POSITIVE
    if rem >= 2:
        return REV_REMEDIATED
    return REV_NONE


def _aggregate(sources: list, expected_hash: str) -> dict:
    """Fault-tolerant 2-of-3 aggregation into the exact 5-field payload
    {verdict, tier, source_count, evidence_hash, published_ts}.

    Each source is CONFIRMING (threat record matching the commitment),
    NON-CONFIRMING (any other valid record), NOT_FOUND (404), or OUTAGE
    (timeout / 5xx / schema error). The verdict is VERIFIED iff >= 2 sources
    confirm. If fewer than 2 confirm but the unreachable sources COULD complete
    a 2-of-3 quorum, the result is QUORUM_FAILURE (retryable, bond intact) --
    an outage can never be converted into a slash.
    """
    confirms = []
    clean = 0
    outage = 0
    for s in sources:
        if s["k"] == SRC_OUTAGE:
            outage += 1
            continue
        clean += 1
        if _is_confirming(s, expected_hash):
            confirms.append(s["rec"])

    n_conf = len(confirms)
    if n_conf >= 2:
        tiers = sorted([r["tier"] for r in confirms])
        # 2 sources -> conservative lower bound; 3 sources -> median.
        tier = tiers[0] if len(tiers) == 2 else tiers[1]
        pub = min(r["published_ts"] for r in confirms)
        return {
            "verdict": VERDICT_VERIFIED_REPORT,
            "tier": tier,
            "source_count": clean,
            "evidence_hash": expected_hash,
            "published_ts": pub,
        }

    if outage > 0 and n_conf + outage >= 2:
        return {
            "verdict": VERDICT_QUORUM_FAILURE,
            "tier": TIER_0_SAFE,
            "source_count": clean,
            "evidence_hash": expected_hash,
            "published_ts": 0,
        }

    # < 2 confirmations and no outage can change that: SAFE_OR_UNFOUNDED.
    rev = _revision_of(sources)
    pub = 0
    if rev != REV_NONE:
        want = REC_FALSE_POSITIVE if rev == REV_FALSE_POSITIVE else REC_REMEDIATED
        pub = min(s["rec"]["published_ts"] for s in sources if s["k"] == SRC_OK and s["rec"]["status"] == want)
    else:
        for s in sources:
            if s["k"] == SRC_OK and s["rec"]["published_ts"] > pub:
                pub = s["rec"]["published_ts"]
    return {
        "verdict": VERDICT_SAFE_OR_UNFOUNDED,
        "tier": TIER_0_SAFE,
        "source_count": clean,
        "evidence_hash": expected_hash,
        "published_ts": pub,
    }


def _aggregate_appeal(sources: list, expected_hash: str) -> dict:
    """`_aggregate` plus the `revision` kind, for appeals.

    An appeal succeeds on a >= 2-source REVISION quorum. So an unreachable
    source must be treated as a possible revision vote too: if the outage could
    complete a revision quorum, the answer is QUORUM_FAILURE (appeal bond
    refunded), never APPEAL_REJECTED (appeal bond slashed)."""
    payload = _aggregate(sources, expected_hash)
    revision = REV_NONE
    if payload["verdict"] == VERDICT_SAFE_OR_UNFOUNDED:
        revision = _revision_of(sources)
        if revision == REV_NONE:
            fp = 0
            rem = 0
            outage = 0
            for s in sources:
                if s["k"] == SRC_OUTAGE:
                    outage += 1
                elif s["k"] == SRC_OK:
                    if s["rec"]["status"] == REC_FALSE_POSITIVE:
                        fp += 1
                    elif s["rec"]["status"] == REC_REMEDIATED:
                        rem += 1
            if outage > 0 and max(fp, rem) + outage >= 2:
                payload = {
                    "verdict": VERDICT_QUORUM_FAILURE,
                    "tier": TIER_0_SAFE,
                    "source_count": payload["source_count"],
                    "evidence_hash": expected_hash,
                    "published_ts": 0,
                }
    payload["revision"] = revision
    return payload


PAYLOAD_KEYS = ("verdict", "tier", "source_count", "evidence_hash", "published_ts")


def _payload_shape_ok(p, with_revision: bool) -> bool:
    """Structural + semantic check of a (leader) payload. A forged payload that
    fails this is a validator DISAGREE."""
    if not isinstance(p, dict):
        return False
    want: set = set(PAYLOAD_KEYS)
    if with_revision:
        want.add("revision")
    if set(p.keys()) != want:
        return False
    for k in ("verdict", "tier", "source_count", "published_ts"):
        if not _is_int(p[k]):
            return False
    if not isinstance(p["evidence_hash"], str) or not _valid_hash(p["evidence_hash"]):
        return False
    if p["verdict"] not in (0, 1, 2) or p["tier"] < 0 or p["tier"] > 2:
        return False
    if p["source_count"] < 0 or p["source_count"] > NUM_SLOTS or p["published_ts"] < 0:
        return False
    if p["verdict"] == VERDICT_VERIFIED_REPORT:
        if p["tier"] < 1 or p["source_count"] < 2 or p["published_ts"] == 0:
            return False
    else:
        if p["tier"] != 0:
            return False
    if p["verdict"] == VERDICT_QUORUM_FAILURE and p["published_ts"] != 0:
        return False
    if with_revision:
        if not _is_int(p["revision"]) or p["revision"] < 0 or p["revision"] > 2:
            return False
        if p["verdict"] != VERDICT_SAFE_OR_UNFOUNDED and p["revision"] != REV_NONE:
            return False
    return True


def _payloads_agree(leader_p: dict, mine: dict, with_revision: bool) -> bool:
    keys = ["verdict", "tier", "source_count", "evidence_hash", "published_ts"]
    if with_revision:
        keys.append("revision")
    for k in keys:
        if leader_p[k] != mine[k]:
            return False
    return True


def _run_triage(urls: list, expected_hash: str, target_id: str, with_revision: bool, max_ts: int) -> dict:
    """Fetch the three governed feeds inside a leader/validator block and
    aggregate. The leader closure touches only plain locals + gl.nondet (no
    `self`); validators re-run it and compare the DECISION fields."""

    def leader():
        sources = []
        for url in urls:
            try:
                res = gl.nondet.web.get(url)
                status = getattr(res, "status", None)
                if status is None:
                    status = getattr(res, "status_code", None)
                sources.append(_source_from_response(status, res.body, target_id, max_ts))
            except Exception:
                sources.append({"k": SRC_OUTAGE})
        if with_revision:
            return _aggregate_appeal(sources, expected_hash)
        return _aggregate(sources, expected_hash)

    def validator(leaders_res) -> bool:
        if not isinstance(leaders_res, gl.vm.Return):
            return False
        lp = leaders_res.calldata
        if not _payload_shape_ok(lp, with_revision):
            return False
        if lp["evidence_hash"] != expected_hash:
            return False
        try:
            mine = leader()
        except Exception:
            return False
        return _payloads_agree(lp, mine, with_revision)

    return gl.vm.run_nondet(leader, validator)


# =============================================================================
# Storage
# =============================================================================
@allow_storage
@dataclass
class Target:
    status: str
    tier: u256
    reporter: Address
    bond_amount: u256  # bond originally posted
    bond_held: u256  # still escrowed (cooldown / pending claim)
    bounty_reserved: u256  # reserved from the pool, vests at vest_at
    bounty_epoch: u256
    vest_at: u256
    report_ts: u256
    published_ts: u256  # feed publication time the classification rests on
    quarantine_until: u256
    override_ts: u256  # a feed record must be NEWER than this to re-list
    evidence_hash: str
    campaign_id: str
    brand_id: str
    first_seen_ts: u256
    source_count: u256
    resolutions: u256


class PhishGuard(gl.contract.Contract):
    targets: TreeMap[str, Target]
    target_index: TreeMap[u256, str]
    target_count: u256
    brands: TreeMap[str, str]  # brand_id -> official domain
    official_domains: TreeMap[str, str]  # official domain -> brand_id
    # Governed feed slots (0=A, 1=B, 2=C) and their staged replacements.
    feed_url: TreeMap[u256, str]
    feed_host: TreeMap[u256, str]
    feed_operator: TreeMap[u256, str]
    staged_url: TreeMap[u256, str]
    staged_host: TreeMap[u256, str]
    staged_operator: TreeMap[u256, str]
    staged_ready_at: TreeMap[u256, u256]
    # Vault accounting. Every wei in `balance` belongs to exactly one bucket.
    bounty_pool: u256
    reserved_bounty: u256
    locked_slash_reserve: u256
    held_bonds: u256
    total_claimable: u256
    claimable: TreeMap[str, u256]
    # Share accounting for pool contributors (ERC-4626 style).
    total_shares: u256
    shares: TreeMap[str, u256]
    # Anti-farming bookkeeping.
    epoch_paid: TreeMap[u256, u256]
    epoch_cap: TreeMap[u256, u256]
    reporter_epoch_bounties: TreeMap[str, u256]
    campaign_paid: TreeMap[str, bool]
    governor: Address
    total_reports: u256

    def __init__(
        self,
        url_a: str,
        operator_a: str,
        url_b: str,
        operator_b: str,
        url_c: str,
        operator_c: str,
    ):
        urls = [url_a, url_b, url_c]
        ops = [operator_a, operator_b, operator_c]
        hosts = []
        for i in range(NUM_SLOTS):
            h = _feed_host(urls[i])
            if h == "":
                raise gl.vm.UserError(f"{ERR_FEED} slot {SLOT_NAMES[i]} url rejected")
            if not _valid_operator(ops[i]):
                raise gl.vm.UserError(f"{ERR_FEED} slot {SLOT_NAMES[i]} operator rejected")
            hosts.append(h)
        if len(set(hosts)) != NUM_SLOTS or len(set(ops)) != NUM_SLOTS:
            raise gl.vm.UserError(f"{ERR_FEED} feeds need 3 distinct hosts and 3 distinct operators")
        for i in range(NUM_SLOTS):
            self.feed_url[i] = urls[i]
            self.feed_host[i] = hosts[i]
            self.feed_operator[i] = ops[i]
            self.staged_url[i] = ""
            self.staged_host[i] = ""
            self.staged_operator[i] = ""
            self.staged_ready_at[i] = 0
        self.governor = gl.message.sender_address
        self.target_count = 0
        self.bounty_pool = 0
        self.reserved_bounty = 0
        self.locked_slash_reserve = 0
        self.held_bonds = 0
        self.total_claimable = 0
        self.total_shares = 0
        self.total_reports = 0

    # ------------------------------------------------------------------ views
    @gl.public.view
    def get_feed_sources(self) -> list:
        out = []
        for i in range(NUM_SLOTS):
            k = i
            out.append(
                {
                    "slot": SLOT_NAMES[i],
                    "base_url": self.feed_url[k],
                    "host": self.feed_host[k],
                    "operator": self.feed_operator[k],
                    "staged_url": self.staged_url[k],
                    "staged_host": self.staged_host[k],
                    "staged_operator": self.staged_operator[k],
                    "staged_ready_at": int(self.staged_ready_at[k]),
                }
            )
        return out

    @gl.public.view
    def get_pool_state(self) -> dict:
        epoch = self._epoch(self._now())
        e = epoch
        paid = int(self.epoch_paid[e]) if e in self.epoch_paid else 0
        cap = int(self.epoch_cap[e]) if e in self.epoch_cap else (int(self.bounty_pool) * MAX_EPOCH_BOUNTY_BPS // BPS_DENOM)
        return {
            "balance": str(self.balance),
            "bounty_pool": str(self.bounty_pool),
            "reserved_bounty": str(self.reserved_bounty),
            "locked_slash_reserve": str(self.locked_slash_reserve),
            "held_bonds": str(self.held_bonds),
            "total_claimable": str(self.total_claimable),
            "total_shares": str(self.total_shares),
            "epoch": epoch,
            "epoch_paid": str(paid),
            "epoch_cap": str(cap),
            "max_epoch_bounty_bps": MAX_EPOCH_BOUNTY_BPS,
            "tier2_bounty": str(TIER2_BOUNTY),
            "min_report_bond": str(MIN_REPORT_BOND),
            "min_appeal_bond": str(MIN_APPEAL_BOND),
            "cooldown_window": COOLDOWN_WINDOW,
            "quarantine_watch": QUARANTINE_WATCH,
            "feed_timelock": FEED_TIMELOCK,
            "target_count": int(self.target_count),
            "total_reports": int(self.total_reports),
            "solvent": self._solvent(),
        }

    @gl.public.view
    def get_target_status(self, target_id: str) -> dict:
        if not _valid_target_id(target_id):
            raise gl.vm.UserError(f"{ERR_PARAMS} bad target_id")
        eff_from, eff_status, eff_tier, _until = self._effective(target_id)
        if target_id not in self.targets:
            return {
                "target_id": target_id,
                "known": False,
                "status": ST_UNKNOWN,
                "tier": 0,
                "tier_name": TIER_NAMES[0],
                "reporter": "",
                "bond_amount": "0",
                "bond_held": "0",
                "bounty_reserved": "0",
                "vest_at": 0,
                "report_ts": 0,
                "published_ts": 0,
                "quarantine_until": 0,
                "override_ts": 0,
                "evidence_hash": "",
                "campaign_id": "",
                "brand_id": "",
                "first_seen_ts": 0,
                "source_count": 0,
                "resolutions": 0,
                "effective_status": eff_status,
                "effective_tier": eff_tier,
                "effective_from": eff_from,
                "inherited": eff_from != "" and eff_from != target_id,
            }
        t = self.targets[target_id]
        return {
            "target_id": target_id,
            "known": True,
            "status": t.status,
            "tier": int(t.tier),
            "tier_name": TIER_NAMES[int(t.tier)],
            "reporter": _hex(t.reporter),
            "bond_amount": str(t.bond_amount),
            "bond_held": str(t.bond_held),
            "bounty_reserved": str(t.bounty_reserved),
            "vest_at": int(t.vest_at),
            "report_ts": int(t.report_ts),
            "published_ts": int(t.published_ts),
            "quarantine_until": int(t.quarantine_until),
            "override_ts": int(t.override_ts),
            "evidence_hash": t.evidence_hash,
            "campaign_id": t.campaign_id,
            "brand_id": t.brand_id,
            "first_seen_ts": int(t.first_seen_ts),
            "source_count": int(t.source_count),
            "resolutions": int(t.resolutions),
            "effective_status": eff_status,
            "effective_tier": eff_tier,
            "effective_from": eff_from,
            "inherited": eff_from != "" and eff_from != target_id,
        }

    @gl.public.view
    def check_transaction_safety(self, target_id: str) -> dict:
        """Fast deterministic firewall read for wallets / routers.

        verdict: ALLOW (tier 0 / unknown), WARN (tier 1 quarantine),
        BLOCK (tier 2 blacklist). A listed registrable parent covers every
        subdomain beneath it: the STRICTEST tier on the exact host or any parent
        wins (a SAFE parent never makes a subdomain safe)."""
        if not _valid_target_id(target_id):
            raise gl.vm.UserError(f"{ERR_PARAMS} bad target_id")
        matched, status, tier, until = self._effective(target_id)
        verdict = "ALLOW"
        if tier == 2:
            verdict = "BLOCK"
        elif tier == 1:
            verdict = "WARN"
        return {
            "target_id": target_id,
            "known": target_id in self.targets or tier > 0,
            "status": status,
            "tier": tier,
            "tier_name": TIER_NAMES[tier],
            "verdict": verdict,
            "blocked": tier == 2,
            "warn": tier == 1,
            "quarantine_until": until,
            "matched_target": matched,
            "inherited": matched != "" and matched != target_id,
        }

    @gl.public.view
    def assert_target_safe(self, target_id: str) -> str:
        """Consumer guard: reverts on TIER_2_DRAINER, returns "WARN" for
        TIER_1_SUSPICIOUS and "SAFE" otherwise. Routers call this before
        forwarding user funds."""
        res = self.check_transaction_safety(target_id)
        if res["blocked"]:
            raise gl.vm.UserError(f"{ERR_BLOCKED} {target_id} is TIER_2_DRAINER")
        if res["warn"]:
            return "WARN"
        return "SAFE"

    @gl.public.view
    def get_brand(self, brand_id: str) -> str:
        return self.brands[brand_id] if brand_id in self.brands else ""

    @gl.public.view
    def get_target_count(self) -> int:
        return int(self.target_count)

    @gl.public.view
    def get_target_id_by_index(self, index: u256) -> str:
        if index not in self.target_index:
            raise gl.vm.UserError(f"{ERR_PARAMS} index out of range")
        return self.target_index[index]

    @gl.public.view
    def claimable_of(self, owner_hex: str) -> str:
        key = owner_hex.lower()
        return str(self.claimable[key]) if key in self.claimable else "0"

    @gl.public.view
    def shares_of(self, owner_hex: str) -> str:
        key = owner_hex.lower()
        return str(self.shares[key]) if key in self.shares else "0"

    @gl.public.view
    def get_governor(self) -> str:
        return _hex(self.governor)

    @gl.public.view
    def whoami(self) -> str:
        return _hex(gl.message.sender_address)

    @gl.public.view
    def compute_commitment(self, target_id: str, campaign_id: str, brand_id: str, first_seen_ts: u256) -> str:
        return _commitment(target_id, campaign_id, brand_id, int(first_seen_ts))

    # ------------------------------------------------------------- governance
    @gl.public.write
    def register_brand(self, brand_id: str, official_domain: str) -> None:
        self._only_governor()
        if not _valid_label(brand_id) or not _valid_target_id(official_domain):
            raise gl.vm.UserError(f"{ERR_PARAMS} bad brand")
        if brand_id in self.brands:
            raise gl.vm.UserError(f"{ERR_STATE} brand exists")
        if official_domain in self.official_domains:
            raise gl.vm.UserError(f"{ERR_STATE} domain already official")
        self.brands[brand_id] = official_domain
        self.official_domains[official_domain] = brand_id

    @gl.public.write
    def stage_feed(self, slot: u256, base_url: str, operator: str) -> int:
        """Stage a feed replacement. Takes effect only after FEED_TIMELOCK and
        must keep all hosts AND operators unique across active + staged slots."""
        self._only_governor()
        i = int(slot)
        if i < 0 or i >= NUM_SLOTS:
            raise gl.vm.UserError(f"{ERR_PARAMS} slot")
        host = _feed_host(base_url)
        if host == "" or not _valid_operator(operator):
            raise gl.vm.UserError(f"{ERR_FEED} url or operator rejected")
        for j in range(NUM_SLOTS):
            if j == i:
                continue
            k = j
            taken_h = [self.feed_host[k]]
            taken_o = [self.feed_operator[k]]
            if self.staged_host[k] != "":
                taken_h.append(self.staged_host[k])
                taken_o.append(self.staged_operator[k])
            if host in taken_h or operator in taken_o:
                raise gl.vm.UserError(f"{ERR_FEED} host/operator not unique")
        ready = self._now() + FEED_TIMELOCK
        k = i
        self.staged_url[k] = base_url
        self.staged_host[k] = host
        self.staged_operator[k] = operator
        self.staged_ready_at[k] = ready
        return ready

    @gl.public.write
    def activate_feed(self, slot: u256) -> None:
        """Anyone may activate a staged feed once the timelock elapsed; the
        uniqueness invariant is re-checked against the CURRENT other slots."""
        i = int(slot)
        if i < 0 or i >= NUM_SLOTS:
            raise gl.vm.UserError(f"{ERR_PARAMS} slot")
        k = i
        if self.staged_host[k] == "":
            raise gl.vm.UserError(f"{ERR_STATE} nothing staged")
        if self._now() < int(self.staged_ready_at[k]):
            raise gl.vm.UserError(f"{ERR_TIMELOCK} feed rotation timelock running")
        hosts = []
        ops = []
        for j in range(NUM_SLOTS):
            if j == i:
                hosts.append(self.staged_host[k])
                ops.append(self.staged_operator[k])
            else:
                hosts.append(self.feed_host[j])
                ops.append(self.feed_operator[j])
        if len(set(hosts)) != NUM_SLOTS or len(set(ops)) != NUM_SLOTS:
            raise gl.vm.UserError(f"{ERR_FEED} host/operator not unique")
        self.feed_url[k] = self.staged_url[k]
        self.feed_host[k] = self.staged_host[k]
        self.feed_operator[k] = self.staged_operator[k]
        self.staged_url[k] = ""
        self.staged_host[k] = ""
        self.staged_operator[k] = ""
        self.staged_ready_at[k] = 0

    @gl.public.write
    def cancel_staged_feed(self, slot: u256) -> None:
        self._only_governor()
        i = int(slot)
        if i < 0 or i >= NUM_SLOTS:
            raise gl.vm.UserError(f"{ERR_PARAMS} slot")
        k = i
        self.staged_url[k] = ""
        self.staged_host[k] = ""
        self.staged_operator[k] = ""
        self.staged_ready_at[k] = 0

    @gl.public.write
    def transfer_governor(self, new_governor_hex: str) -> None:
        self._only_governor()
        self.governor = Address(new_governor_hex)

    # ------------------------------------------------------------ bounty vault
    @gl.public.write.payable
    def fund_bounty_pool(self) -> str:
        """Contribute to the public-good bounty pool and receive shares."""
        amount = int(gl.message.value)
        if amount < MIN_POOL_DEPOSIT:
            raise gl.vm.UserError(f"{ERR_BOND} minimum pool deposit")
        key = _hex(gl.message.sender_address)
        assets = int(self.bounty_pool)
        total = int(self.total_shares)
        if total == 0:
            minted = amount - MIN_LOCKED_SHARES
            self.total_shares = amount  # includes MIN_LOCKED_SHARES dead shares
        else:
            minted = amount * (total + SHARE_OFFSET) // (assets + 1)
            self.total_shares = total + minted
        if minted <= 0:
            raise gl.vm.UserError(f"{ERR_BOND} deposit too small")
        self.shares[key] = (int(self.shares[key]) if key in self.shares else 0) + minted
        self.bounty_pool = assets + amount
        # Capital added mid-epoch raises that epoch's cap by the same 20 % share,
        # so a report made while the pool was empty cannot freeze the cap at 0.
        e = self._epoch(self._now())
        if e in self.epoch_cap:
            self.epoch_cap[e] = int(self.epoch_cap[e]) + amount * MAX_EPOCH_BOUNTY_BPS // BPS_DENOM
        return str(minted)

    @gl.public.write
    def withdraw_pool_shares(self, share_amount: u256) -> str:
        """Redeem shares against FREE pool liquidity only. Reserved bounties and
        the slash reserve are separate buckets and can never be redeemed, and
        the dead-share floor means the pool can never be fully emptied."""
        key = _hex(gl.message.sender_address)
        n = int(share_amount)
        have = int(self.shares[key]) if key in self.shares else 0
        if n <= 0 or n > have:
            raise gl.vm.UserError(f"{ERR_POOL} invalid share amount")
        total = int(self.total_shares)
        assets = int(self.bounty_pool)
        out = n * assets // total
        if out <= 0 or out > assets:
            raise gl.vm.UserError(f"{ERR_POOL} nothing redeemable")
        self.shares[key] = have - n
        self.total_shares = total - n
        self.bounty_pool = assets - out
        # Mirror image of funding: withdrawn liquidity leaves the cap too (never
        # below what was already paid), so deposit/withdraw cannot inflate it.
        e = self._epoch(self._now())
        if e in self.epoch_cap:
            paid = int(self.epoch_paid[e]) if e in self.epoch_paid else 0
            cut = out * MAX_EPOCH_BOUNTY_BPS // BPS_DENOM
            cap = int(self.epoch_cap[e])
            self.epoch_cap[e] = paid if cap - cut < paid else cap - cut
        self._credit(key, out)
        return str(out)

    @gl.public.write
    def recycle_slash_reserve(self) -> str:
        """Permissionless: slashed bonds above RESERVE_FLOOR flow back into the
        bounty pool (raising the share price). The governor is never a party."""
        reserve = int(self.locked_slash_reserve)
        if reserve <= RESERVE_FLOOR:
            raise gl.vm.UserError(f"{ERR_NOTHING} reserve at floor")
        moved = reserve - RESERVE_FLOOR
        self.locked_slash_reserve = RESERVE_FLOOR
        self.bounty_pool = int(self.bounty_pool) + moved
        return str(moved)

    # ------------------------------------------------------------ reporting
    @gl.public.write.payable
    def report_target(
        self,
        target_id: str,
        evidence_hash: str,
        campaign_id: str,
        brand_id: str,
        first_seen_ts: u256,
    ) -> str:
        """Stake a bond and request multi-source triage of `target_id`.

        `evidence_hash` must equal SHA-256 of the canonical attributes
        (target_id, campaign_id, brand_id, first_seen_ts) -- recomputed here, so
        the attributes that gate the bounty are bound to what the feeds
        corroborate. Returns the resolved status string."""
        bond = int(gl.message.value)
        if not _valid_target_id(target_id):
            raise gl.vm.UserError(f"{ERR_PARAMS} bad target_id")
        if not _valid_hash(evidence_hash):
            raise gl.vm.UserError(f"{ERR_PARAMS} bad evidence_hash")
        if not _valid_label(campaign_id) or not _valid_label(brand_id):
            raise gl.vm.UserError(f"{ERR_PARAMS} bad campaign/brand label")
        first_seen = int(first_seen_ts)
        now = self._now()
        # first_seen_ts > report time is NOT a revert (fee simulation runs on a
        # simulation clock that is not the block clock); it is a bounty gate in
        # `_reserve_bounty`, which pays nothing for a first-seen in the future.
        if _commitment(target_id, campaign_id, brand_id, first_seen) != evidence_hash:
            raise gl.vm.UserError(f"{ERR_PARAMS} evidence_hash does not commit to the attributes")
        if bond < MIN_REPORT_BOND:
            raise gl.vm.UserError(f"{ERR_BOND} minimum report bond")

        existing = target_id in self.targets
        if existing:
            cur = self.targets[target_id]
            if cur.status == ST_BLACKLISTED:
                raise gl.vm.UserError(f"{ERR_STATE} already blacklisted")
            if cur.status == ST_QUARANTINED:
                if now < int(cur.quarantine_until):
                    raise gl.vm.UserError(f"{ERR_STATE} under quarantine watch")
                raise gl.vm.UserError(f"{ERR_STATE} quarantine elapsed: call reevaluate_target")

        sender = gl.message.sender_address
        sender_hex = _hex(sender)
        self.total_reports = int(self.total_reports) + 1

        # A verified official brand domain can never be blacklisted.
        if target_id in self.official_domains:
            self.locked_slash_reserve = int(self.locked_slash_reserve) + bond
            return "TIER_0_SAFE_OFFICIAL_DOMAIN"

        payload = _run_triage(self._feed_urls(target_id), evidence_hash, target_id, False, now + MAX_CLOCK_SKEW)
        verdict = int(payload["verdict"])

        if verdict == VERDICT_QUORUM_FAILURE:
            # Outage / lag: nobody is slashed, the bond is simply returned.
            self._credit(sender_hex, bond)
            return "QUORUM_FAILURE"

        override_ts = 0
        if existing:
            override_ts = int(self.targets[target_id].override_ts)
            # Anything the previous record still escrows (an unvested bounty left
            # by a REMEDIATED appeal, a held bond) is settled to its reporter's
            # pull ledger BEFORE the record is replaced, so nothing is orphaned.
            self._settle_prior(target_id)
        t = self._fresh_target(
            target_id, existing, sender, bond, now, evidence_hash, campaign_id, brand_id, first_seen
        )
        t.override_ts = override_ts
        t.source_count = int(payload["source_count"])

        if verdict == VERDICT_SAFE_OR_UNFOUNDED:
            # Fabricated / benign report: forfeited to the slash reserve.
            self.locked_slash_reserve = int(self.locked_slash_reserve) + bond
            t.status = ST_DISMISSED
            t.tier = TIER_0_SAFE
            t.bond_held = 0
            t.published_ts = int(payload["published_ts"])
            t.resolutions = int(t.resolutions) + 1
            self._store_target(target_id, existing, t)
            return ST_DISMISSED

        # VERIFIED_REPORT -- but a feed record older than a standing
        # FALSE_POSITIVE / REMEDIATED override cannot re-list the target.
        pub = int(payload["published_ts"])
        if pub <= override_ts:
            self._credit(sender_hex, bond)
            return "FALSE_POSITIVE_OVERRIDE_ACTIVE"

        t.published_ts = pub
        tier = int(payload["tier"])
        t.tier = tier
        t.resolutions = int(t.resolutions) + 1
        if tier == TIER_1_SUSPICIOUS:
            # Anomaly without a confirmed drainer: watch window, bond refunded.
            t.status = ST_QUARANTINED
            t.quarantine_until = now + QUARANTINE_WATCH
            t.bond_held = 0
            self._credit(sender_hex, bond)
            self._store_target(target_id, existing, t)
            return ST_QUARANTINED

        t.status = ST_BLACKLISTED
        t.bond_held = bond
        self.held_bonds = int(self.held_bonds) + bond
        t.vest_at = now + COOLDOWN_WINDOW
        self._reserve_bounty(t, sender_hex, now)
        self._store_target(target_id, existing, t)
        return ST_BLACKLISTED

    @gl.public.write
    def reevaluate_target(self, target_id: str) -> str:
        """Re-run triage on a quarantined target once its 48h watch elapsed."""
        if not _valid_target_id(target_id):
            raise gl.vm.UserError(f"{ERR_PARAMS} bad target_id")
        if target_id not in self.targets:
            raise gl.vm.UserError(f"{ERR_STATE} unknown target")
        t = self.targets[target_id]
        if t.status != ST_QUARANTINED:
            raise gl.vm.UserError(f"{ERR_STATE} target is not quarantined")
        now = self._now()
        if now < int(t.quarantine_until):
            raise gl.vm.UserError(f"{ERR_TIMELOCK} quarantine watch still running")
        payload = _run_triage(self._feed_urls(target_id), t.evidence_hash, target_id, False, now + MAX_CLOCK_SKEW)
        verdict = int(payload["verdict"])
        if verdict == VERDICT_QUORUM_FAILURE:
            return "QUORUM_FAILURE"
        t.resolutions = int(t.resolutions) + 1
        if verdict == VERDICT_SAFE_OR_UNFOUNDED:
            t.status = ST_CLEARED
            t.tier = TIER_0_SAFE
            t.quarantine_until = 0
            self.targets[target_id] = t
            return ST_CLEARED
        pub = int(payload["published_ts"])
        if pub <= int(t.override_ts):
            return "FALSE_POSITIVE_OVERRIDE_ACTIVE"
        t.published_ts = pub
        t.source_count = int(payload["source_count"])
        if int(payload["tier"]) == TIER_2_DRAINER:
            t.status = ST_BLACKLISTED
            t.tier = TIER_2_DRAINER
            t.quarantine_until = 0
            t.vest_at = now + COOLDOWN_WINDOW
            self._reserve_bounty(t, _hex(t.reporter), now)
            self.targets[target_id] = t
            return ST_BLACKLISTED
        t.quarantine_until = now + QUARANTINE_WATCH
        self.targets[target_id] = t
        return ST_QUARANTINED

    @gl.public.write
    def claim_settlement(self, target_id: str) -> str:
        """Reporter pulls the staged bond refund + bounty after the cooldown."""
        if target_id not in self.targets:
            raise gl.vm.UserError(f"{ERR_STATE} unknown target")
        t = self.targets[target_id]
        if gl.message.sender_address != t.reporter:
            raise gl.vm.UserError(f"{ERR_UNAUTHORIZED} only the reporter may claim")
        if self._now() < int(t.vest_at):
            raise gl.vm.UserError(f"{ERR_TIMELOCK} cooldown window still running")
        bond = int(t.bond_held)
        bounty = int(t.bounty_reserved)
        if bond == 0 and bounty == 0:
            raise gl.vm.UserError(f"{ERR_NOTHING}")
        t.bond_held = 0
        t.bounty_reserved = 0
        self.targets[target_id] = t
        self.held_bonds = int(self.held_bonds) - bond
        self.reserved_bounty = int(self.reserved_bounty) - bounty
        self._credit(_hex(t.reporter), bond + bounty)
        return str(bond + bounty)

    # ---------------------------------------------------------------- appeals
    @gl.public.write.payable
    def appeal_classification(self, target_id: str) -> str:
        """Challenge a BLACKLISTED / QUARANTINED classification by posting an
        appeal bond. Succeeds only if >= 2 feeds now publish a NEWER record that
        revokes (false positive) or remediates the target."""
        bond = int(gl.message.value)
        if not _valid_target_id(target_id):
            raise gl.vm.UserError(f"{ERR_PARAMS} bad target_id")
        if bond < MIN_APPEAL_BOND:
            raise gl.vm.UserError(f"{ERR_BOND} minimum appeal bond")
        if target_id not in self.targets:
            raise gl.vm.UserError(f"{ERR_STATE} unknown target")
        t = self.targets[target_id]
        if t.status != ST_BLACKLISTED and t.status != ST_QUARANTINED:
            raise gl.vm.UserError(f"{ERR_STATE} nothing to appeal")
        sender = gl.message.sender_address
        if sender == t.reporter:
            raise gl.vm.UserError(f"{ERR_UNAUTHORIZED} reporter cannot appeal own report")
        sender_hex = _hex(sender)

        payload = _run_triage(
            self._feed_urls(target_id), t.evidence_hash, target_id, True, self._now() + MAX_CLOCK_SKEW
        )
        verdict = int(payload["verdict"])
        if verdict == VERDICT_QUORUM_FAILURE:
            self._credit(sender_hex, bond)
            return "QUORUM_FAILURE"

        rev = int(payload["revision"])
        pub = int(payload["published_ts"])
        upheld = verdict == VERDICT_SAFE_OR_UNFOUNDED and rev != REV_NONE and pub > int(t.published_ts)
        if not upheld:
            # Frivolous appeal: the bond goes to the slash reserve, not a governor.
            self.locked_slash_reserve = int(self.locked_slash_reserve) + bond
            return "APPEAL_REJECTED"

        reporter_hex = _hex(t.reporter)
        held = int(t.bond_held)
        t.override_ts = pub
        t.tier = TIER_0_SAFE
        t.quarantine_until = 0
        t.published_ts = pub
        t.resolutions = int(t.resolutions) + 1
        if rev == REV_FALSE_POSITIVE:
            # Explicit error in the original report: the reporter's escrowed
            # bond is slashed to the challenger, the reserved bounty returns
            # to the pool, and the campaign may be bountied again.
            t.status = ST_REVOKED
            reward = held
            self.held_bonds = int(self.held_bonds) - held
            t.bond_held = 0
            if held == 0:
                # Bond already vested / refunded: pay from the slash float.
                reward = min(int(t.bond_amount), int(self.locked_slash_reserve))
                self.locked_slash_reserve = int(self.locked_slash_reserve) - reward
            self._release_bounty(t)
            self._credit(sender_hex, bond + reward)
            self.targets[target_id] = t
            return ST_REVOKED
        # Post-remediation cleanup: nobody is unfairly slashed.
        t.status = ST_REMEDIATED
        self.held_bonds = int(self.held_bonds) - held
        t.bond_held = 0
        self._credit(reporter_hex, held)
        self._credit(sender_hex, bond)
        self.targets[target_id] = t
        return ST_REMEDIATED

    # ------------------------------------------------------------ settlement
    @gl.public.write
    def claim_payout(self) -> str:
        """Pull-pattern withdrawal (checks-effects-interactions)."""
        key = _hex(gl.message.sender_address)
        if key not in self.claimable or int(self.claimable[key]) == 0:
            raise gl.vm.UserError(f"{ERR_NOTHING}")
        amount = int(self.claimable[key])
        self.claimable[key] = 0
        self.total_claimable = int(self.total_claimable) - amount
        try:
            gl.chain.Account(gl.message.sender_address).emit_transfer(amount, on="finalized")
        except Exception:
            self.claimable[key] = amount
            self.total_claimable = int(self.total_claimable) + amount
            raise gl.vm.UserError(f"{ERR_TRANSFER}")
        return str(amount)

    # --------------------------------------------------------------- internals
    def _effective(self, target_id: str):
        """(matched_target, status, tier, quarantine_until) after parent walk."""
        matched = ""
        status = ST_UNKNOWN
        tier = 0
        until = 0
        if target_id in self.targets:
            t = self.targets[target_id]
            matched = target_id
            status = t.status
            tier = _tier_of_status(t.status)
            until = int(t.quarantine_until)
        for parent in _parent_chain(target_id):
            if parent not in self.targets:
                continue
            pt = self.targets[parent]
            ptier = _tier_of_status(pt.status)
            if ptier > tier:  # strictly stricter: nearest parent wins ties
                matched = parent
                status = pt.status
                tier = ptier
                until = int(pt.quarantine_until)
        return matched, status, tier, until

    def _only_governor(self) -> None:
        if gl.message.sender_address != self.governor:
            raise gl.vm.UserError(f"{ERR_UNAUTHORIZED} governor only")

    def _now(self) -> int:
        return int(datetime.now(timezone.utc).timestamp())

    def _epoch(self, ts: int) -> int:
        return ts // EPOCH_SECONDS

    def _solvent(self) -> bool:
        tracked = (
            int(self.bounty_pool)
            + int(self.reserved_bounty)
            + int(self.locked_slash_reserve)
            + int(self.held_bonds)
            + int(self.total_claimable)
        )
        return int(self.balance) >= tracked

    def _credit(self, owner_hex: str, amount: int) -> None:
        if amount <= 0:
            return
        cur = int(self.claimable[owner_hex]) if owner_hex in self.claimable else 0
        self.claimable[owner_hex] = cur + amount
        self.total_claimable = int(self.total_claimable) + amount

    def _feed_urls(self, target_id: str) -> list:
        urls = []
        for i in range(NUM_SLOTS):
            urls.append(self.feed_url[i] + target_id + ".json")
        return urls

    def _fresh_target(
        self, target_id, existing, reporter, bond, now, evidence_hash, campaign_id, brand_id, first_seen
    ) -> Target:
        prev = int(self.targets[target_id].resolutions) if existing else 0
        return Target(
            status=ST_UNKNOWN,
            tier=0,
            reporter=reporter,
            bond_amount=bond,
            bond_held=0,
            bounty_reserved=0,
            bounty_epoch=0,
            vest_at=0,
            report_ts=now,
            published_ts=0,
            quarantine_until=0,
            override_ts=0,
            evidence_hash=evidence_hash,
            campaign_id=campaign_id,
            brand_id=brand_id,
            first_seen_ts=first_seen,
            source_count=0,
            resolutions=prev,
        )

    def _settle_prior(self, target_id: str) -> None:
        prior = self.targets[target_id]
        bond = int(prior.bond_held)
        bounty = int(prior.bounty_reserved)
        if bond == 0 and bounty == 0:
            return
        self.held_bonds = int(self.held_bonds) - bond
        self.reserved_bounty = int(self.reserved_bounty) - bounty
        prior.bond_held = 0
        prior.bounty_reserved = 0
        self.targets[target_id] = prior
        self._credit(_hex(prior.reporter), bond + bounty)

    def _store_target(self, target_id: str, existing: bool, t: Target) -> None:
        if not existing:
            self.target_index[self.target_count] = target_id
            self.target_count = int(self.target_count) + 1
        self.targets[target_id] = t

    def _reserve_bounty(self, t: Target, reporter_hex: str, now: int) -> None:
        """Reserve the fixed tier-2 bounty iff EVERY provenance gate passes:
        corroborated by >= 2 independent feeds, a campaign_id, first_seen_ts
        no later than the report AND the feed publication, a registered brand,
        a campaign not yet bountied, per-reporter and per-epoch caps."""
        t.bounty_reserved = 0
        if int(t.source_count) < 2 or t.campaign_id == "" or t.brand_id == "":
            return
        if int(t.first_seen_ts) > now or int(t.first_seen_ts) > int(t.published_ts):
            return
        if t.brand_id not in self.brands:
            return
        if t.campaign_id in self.campaign_paid and self.campaign_paid[t.campaign_id]:
            return
        epoch = self._epoch(now)
        e = epoch
        rk = f"{epoch}|{reporter_hex}"
        count = int(self.reporter_epoch_bounties[rk]) if rk in self.reporter_epoch_bounties else 0
        if count >= MAX_BOUNTIES_PER_REPORTER_EPOCH:
            return
        pool = int(self.bounty_pool)
        if e not in self.epoch_cap:
            self.epoch_cap[e] = pool * MAX_EPOCH_BOUNTY_BPS // BPS_DENOM
            self.epoch_paid[e] = 0
        paid = int(self.epoch_paid[e])
        if paid + TIER2_BOUNTY > int(self.epoch_cap[e]) or TIER2_BOUNTY > pool:
            return
        self.epoch_paid[e] = paid + TIER2_BOUNTY
        self.reporter_epoch_bounties[rk] = count + 1
        self.campaign_paid[t.campaign_id] = True
        self.bounty_pool = pool - TIER2_BOUNTY
        self.reserved_bounty = int(self.reserved_bounty) + TIER2_BOUNTY
        t.bounty_reserved = TIER2_BOUNTY
        t.bounty_epoch = epoch

    def _release_bounty(self, t: Target) -> None:
        """Return an unvested bounty to the pool and re-open its campaign."""
        amount = int(t.bounty_reserved)
        if amount == 0:
            return
        self.reserved_bounty = int(self.reserved_bounty) - amount
        self.bounty_pool = int(self.bounty_pool) + amount
        e = int(t.bounty_epoch)
        if e in self.epoch_paid and int(self.epoch_paid[e]) >= amount:
            self.epoch_paid[e] = int(self.epoch_paid[e]) - amount
        if t.campaign_id in self.campaign_paid:
            self.campaign_paid[t.campaign_id] = False
        t.bounty_reserved = 0
