"""Data-driven threat-intelligence detection (Phase 1 B5).

Where ``risk_rules.py`` classifies an extension by its *permissions* (a
heuristic), this module matches an extension against *known-bad indicators* — a
versioned, operator-curated feed of malicious publishers, banned extension IDs,
and typosquat targets. It is the threat-intel half of detection: deterministic
"we have seen this is bad" signals rather than "this looks risky."

The feed lives in ``rules/threat_intel.json`` (same load strategy as
``risk_rules.py``: env override, repo path, portal-local copy, then embedded
defaults). Evaluation runs server-side during scan-report ingestion; pushing
the signed feed down to daemons over the Phase 1 B1 command channel is a
documented follow-up.

Every match is one ``ThreatMatch`` dict: ``{indicator_type, indicator, detail,
severity}``. The function is pure, so it is trivially testable and is also
consumed by composite risk scoring (B8, ``risk_score.py``).
"""
import json
import os

# Embedded fallback so the container image still works if the JSON is absent.
_DEFAULT_FEED = {
    "version": "embedded",
    "malicious_publishers": [],
    "banned_extension_ids": [],
    "typosquat_targets": [],
    "malicious_file_hashes": [],
}

# A typosquat is an extension id within this edit distance of a known target
# but NOT equal to it. 1–2 char swaps/insertions are the realistic attack.
TYPOSQUAT_MAX_DISTANCE = 2


def _candidate_paths():
    env = os.environ.get("THREAT_INTEL_RULES")
    if env:
        yield env
    here = os.path.dirname(os.path.abspath(__file__))
    yield os.path.join(here, "..", "..", "rules", "threat_intel.json")
    yield os.path.join(here, "threat_intel.json")


def _load_feed() -> dict:
    for path in _candidate_paths():
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict) and "version" in data:
                return data
        except (OSError, ValueError):
            continue
    return dict(_DEFAULT_FEED)


# Loaded once at import; restart to pick up a new feed (matches risk_rules.py).
_FEED = _load_feed()
_MALICIOUS_PUBLISHERS = {p.lower() for p in _FEED.get("malicious_publishers", [])}
_BANNED_IDS = {e.lower() for e in _FEED.get("banned_extension_ids", [])}
_TYPOSQUAT_TARGETS = [t.lower() for t in _FEED.get("typosquat_targets", [])]


def feed_version() -> str:
    return _FEED.get("version", "unknown")


def _levenshtein(a: str, b: str) -> int:
    """Classic edit distance (small strings, so the simple DP is fine)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(
                prev[j] + 1,        # deletion
                cur[j - 1] + 1,     # insertion
                prev[j - 1] + (ca != cb),  # substitution
            ))
        prev = cur
    return prev[-1]


def evaluate_extension(extension_id: str, publisher: str = "", name: str = "") -> list:
    """Return the list of threat matches for one extension (possibly empty).

    Indicators, highest-confidence first:
      * banned_extension     — exact id is on the banned list (critical)
      * malicious_publisher  — the publisher is known-bad (critical)
      * typosquat            — id is a near-miss of a popular extension (high)
    """
    matches = []
    ext_id = (extension_id or "").lower().strip()
    pub = (publisher or "").lower().strip()
    # VS Code ids are "publisher.name"; derive the publisher if not given.
    if not pub and "." in ext_id:
        pub = ext_id.split(".", 1)[0]

    if ext_id and ext_id in _BANNED_IDS:
        matches.append({
            "indicator_type": "banned_extension",
            "indicator": extension_id,
            "detail": "Extension id is on the banned-extension threat list.",
            "severity": "critical",
        })

    if pub and pub in _MALICIOUS_PUBLISHERS:
        matches.append({
            "indicator_type": "malicious_publisher",
            "indicator": publisher or pub,
            "detail": f"Publisher '{pub}' is flagged as malicious.",
            "severity": "critical",
        })

    # Typosquat: only meaningful if it isn't a legitimate target itself.
    if ext_id and ext_id not in _TYPOSQUAT_TARGETS and ext_id not in _BANNED_IDS:
        for target in _TYPOSQUAT_TARGETS:
            dist = _levenshtein(ext_id, target)
            if 0 < dist <= TYPOSQUAT_MAX_DISTANCE:
                matches.append({
                    "indicator_type": "typosquat",
                    "indicator": extension_id,
                    "detail": f"Closely resembles popular extension '{target}' "
                              f"(edit distance {dist}) — possible typosquat.",
                    "severity": "high",
                })
                break

    return matches
