#!/usr/bin/env python3
"""Parse MagicRoot P0 safe-mode A/B run logs.

Offline only: this tool never touches a device.  It accepts one or more
``run.log`` files (or directories that contain them) and extracts the fields
needed to compare a P0 arm against a baseline arm:

* phase groups: v36 ``permissive`` / ``fsuid`` and cred ``phase1`` / ``phase2``
  (inferred from the ``== N. ... ==`` section headers emitted by ``run.sh``,
  from cred ``== phaseN start`` markers, and from the ``p1``/``p2`` prefixes);
* attempt counts, ``SAFE_ABORT`` counts, early-abort counts and abort reasons;
* per-attempt drain durations (mean / median / p90 / min / max);
* ``leaked`` first/last/max values;
* ``STEP_OK`` / ``LEAK`` landing attempts per phase;
* total run time when the log carries timestamps (or when a ``*.meta.json``
  sidecar records it);
* optional A/B acceptance comparison (safe-baseline vs p0-early).

Supported input line shapes (tolerated, all optional):

* plain shell output captured by ``tee -a run.log`` (no timestamps);
* logcat-style prefixes (``MM-DD HH:MM:SS.mmm  123  456 I/... :``,
  ``[YYYY-MM-DD HH:MM:SS]``, ISO-8601 timestamps);
* v36 attempt lines, e.g.::

    attempt=12 victims=32 timers=12800 drained=0(6091ms) slab=3947/13568 frag=0 landed=0
    attempt=12 victims=32 ... base=900/1024 leaked=32 landed=0

* cred attempt lines, e.g.::

    p1 attempt=5 timers=6400 drained=0(6021ms) slab=3842/6976 frag=0 leak=0 leaked=0

* safe abort lines::

    attempt=12 SAFE_ABORT drained=0(6000ms) slab=... base=... leaked=32
    attempt=12 SAFE_ABORT short_spray got=100/12000 leaked=64
    attempt=12 SAFE_ABORT slab_regrown slab=... base=... leaked=96
    attempt=12 SAFE_ABORT early elapsed=4501ms slab=... base=... best=... stall=...
    SAFE_LEAK_LIMIT leaked=128
    SAFE_BUDGET_EXCEEDED elapsed=1350000ms

* success markers::

    LANDED attempt=34 off=0xa78 val=...
    STEP_OK pc=0 target=... attempt=34 page=...
    LEAK p2 attempt=9 off=... val=...
    phase1 start / phase2 start
    DONE
    FAIL=cred_phase rc=6

Outputs: JSON (machine readable), Markdown (short tables for the report) and
optional CSV (one row per run x phase).  ``--json`` / ``--markdown`` select a
single format; with neither flag both are printed with clear separators.

Usage examples::

    python release/tools/parse_safe_ab.py release/publish/experiments/p0-ab/sessions
    python release/tools/parse_safe_ab.py run.log --format json
    python release/tools/parse_safe_ab.py sessions/ --format markdown --out-markdown p0-ab.md
    python release/tools/parse_safe_ab.py sessions/ --out-json p0-ab.json --out-csv p0-ab.csv
Exit codes: 0 = at least one run parsed, 2 = no parseable input.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from statistics import median

TOOL_VERSION = "1.0.0"
SCHEMA = "magicroot-safe-ab-parse/v1"

# Phases that a run is expected to contain.  Missing phases are still emitted
# with ``present: false`` so two runs can be compared column by column.
EXPECTED_PHASES = ("permissive", "fsuid", "cred_phase1", "cred_phase2")
PHASE_LABELS = {
    "permissive": "v36 permissive",
    "fsuid": "v36 fsuid",
    "cred_phase1": "cred phase1",
    "cred_phase2": "cred phase2",
}
MODE_LABELS = {
    "safe-baseline": "safe baseline (safe-mode, early-abort=0)",
    "p0-early": "P0 early-abort",
    "production": "production (safe-mode off)",
    "unknown": "unknown / not annotated",
}

LOG_SUFFIXES = {".log", ".txt", ".out"}
META_SUFFIXES = (".meta.json", ".meta.txt", ".meta")

RE_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
RE_BAD_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
RE_ISO_TS = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
RE_LOGCAT_TS = re.compile(
    r"^(?P<mon>\d{2})-(?P<day>\d{2})\s+(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\.(?P<ms>\d{3})\b"
)
RE_LOGCAT_THREADTIME = re.compile(
    r"^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\d+\s+\d+\s+[VDIWEF]\s+[^:]*:\s?"
)
RE_BRACKET_TS = re.compile(
    r"^\[\s*(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
    r"(?:[+-]\d{2}:?\d{2})?\s*\]\s?"
)
RE_SECTION = re.compile(r"^\s*==+\s*(?P<title>.+?)\s*==+\s*$")
RE_SECTION_ALT = re.compile(r"^\s*\[SECTION\]\s*(?P<title>.+?)\s*$")
RE_RUN_MARKER = re.compile(r"^\s*(?:===+\s*)?(?:AB_)?RUN(?:[=:\s]|\s*#)(?P<rest>.*?)\s*(?:===+)?\s*$")
RE_RUN_BOUNDARY = re.compile(r"^\s*---+\s*(?:RUN|AB RUN)\b(?P<rest>.*?)\s*---+\s*$")
RE_VICTIMS_PERMISSIVE = re.compile(r"^\s*VICTIMS_PERMISSIVE\s*=\s*\d+")
RE_CRED_START = re.compile(r"^\s*(?:==+\s*)?phase(?P<p>[12])\s+start\b", re.IGNORECASE)
RE_ATTEMPT = re.compile(r"\battempt=(?P<n>\d+)\b")
RE_CRED_ATTEMPT = re.compile(r"\bp(?P<p>[12])\s+attempt=(?P<n>\d+)\b")
RE_LANDED = re.compile(r"^\s*LANDED\s+(?:p(?P<p>[12])\s+)?attempt=(?P<n>\d+)\b")
RE_LEAK = re.compile(r"^\s*(?:LEAK\b)(?:\s+p(?P<p>[12]))?\s+attempt=(?P<n>\d+)\b")
RE_STEP_OK = re.compile(r"^\s*STEP_OK\b")
RE_STEP_FAIL = re.compile(r"^\s*STEP_FAIL\b")
RE_DRAINED = re.compile(r"\bdrained=(?P<flag>\d+)\((?P<ms>\d+)\s*ms\)")
RE_ELAPSED_MS = re.compile(r"\belapsed=(?P<ms>\d+)\s*ms\b")
RE_BEST = re.compile(r"\bbest=(?P<a>-?\d+)(?:/(?P<t>-?\d+))?")
RE_STALL = re.compile(r"\bstall=(?P<ms>\d+)\s*ms\b")
RE_PHASE_NUM = re.compile(r"\bphase=(?P<p>[12])\b")
RE_SAFE_BUILD = re.compile(
    r"SAFE_BUILD\s+name=(?P<name>\S+)\s+maxvictim=(?P<maxvictim>\d+).*?"
    r"early=(?P<early>\d+)\s*ms"
)
RE_SLAB = re.compile(r"\bslab=(?P<a>-?\d+)/(?P<t>-?\d+)")
RE_BASE = re.compile(r"\bbase=(?P<a>-?\d+)/(?P<t>-?\d+)")
RE_DRAIN_CAP = re.compile(r"\bdrain_max=(?P<v>\d+)\s*ms")
RE_SAFE_MODE = re.compile(r"\bSAFE_MODE=(?P<v>[01])\b")
RE_EARLY_MS = re.compile(r"\bEARLY_ABORT_MS=(?P<v>\d+)\b")
RE_AB_EXPORT = re.compile(r"\bAB_EXPORT=(?P<v>[01])\b")
RE_FAIL = re.compile(r"^\s*FAIL=(?P<code>\S+)(?P<rest>.*)$")
RE_LEAK_LIMIT = re.compile(r"\bSAFE_LEAK_LIMIT\b.*?leaked=(?P<v>\d+)")
RE_BUDGET = re.compile(r"\bSAFE_BUDGET_EXCEEDED\b.*?elapsed=(?P<v>\d+)\s*ms")
RE_BOOT_ID = re.compile(r"\b(?:AB_)?BOOT_ID=(?P<v>[0-9A-Za-z-]+)")
RE_PHASE_LANDED = re.compile(r"^\s*phase(?P<p>[12])\s+landed\b", re.IGNORECASE)
RE_PHASE_VERIFY = re.compile(r"\bPHASE(?P<p>[12])_VERIFY\s+(?P<res>ok|FAIL)\b")
RE_KV_PAIR = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<val>\S+)")


# ---------------------------------------------------------------------------
# small text helpers
# ---------------------------------------------------------------------------


def _safe_int(text: str | None) -> int | None:
    if text is None:
        return None
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def _kv(text: str) -> dict[str, str]:
    """Collect ``key=value`` tokens; later duplicates win."""
    out: dict[str, str] = {}
    for m in RE_KV_PAIR.finditer(text):
        out[m.group("key")] = m.group("val")
    return out


def _percentile_nearest_rank(values: list[float], pct: float) -> float | None:
    """p90 style percentile using the nearest-rank method (no interpolation)."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, int(round((pct / 100.0) * len(ordered) + 0.499999)))
    rank = min(rank, len(ordered))
    return ordered[rank - 1]


def _drain_stats(samples: list[int]) -> dict:
    vals = [float(v) for v in samples if v is not None]
    if not vals:
        return {
            "samples": 0,
            "mean_ms": None,
            "median_ms": None,
            "p90_ms": None,
            "min_ms": None,
            "max_ms": None,
        }
    return {
        "samples": len(vals),
        "mean_ms": round(sum(vals) / len(vals), 1),
        "median_ms": round(float(median(vals)), 1),
        "p90_ms": round(float(_percentile_nearest_rank(vals, 90)), 1),
        "min_ms": int(min(vals)),
        "max_ms": int(max(vals)),
    }


def _read_text(path: Path) -> str:
    data = path.read_bytes()
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    for enc in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _normalize_line(raw: str) -> str:
    line = RE_BAD_CTRL.sub("", raw)
    line = RE_ANSI.sub("", line)
    line = line.rstrip("\r\n")
    # Strip the most common logcat / timestamp wrappers so the payload regexes
    # see the actual program output.
    line = RE_LOGCAT_THREADTIME.sub("", line)
    line = RE_BRACKET_TS.sub("", line)
    return line


@dataclass
class TimestampHit:
    kind: str  # "iso" | "logcat"
    text: str
    iso: datetime | None = None
    year: int | None = None
    month: int | None = None
    day: int | None = None
    hour: int | None = None
    minute: int | None = None
    second: int | None = None
    milli: int = 0


def _parse_iso_ts(text: str) -> datetime | None:
    candidate = text.strip().replace(" ", "T", 1)
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def _timestamp_hit(raw: str, default_year: int) -> TimestampHit | None:
    m = RE_LOGCAT_TS.match(raw)
    if m:
        return TimestampHit(
            kind="logcat",
            text=m.group(0),
            year=default_year,
            month=int(m.group("mon")),
            day=int(m.group("day")),
            hour=int(m.group("h")),
            minute=int(m.group("m")),
            second=int(m.group("s")),
            milli=int(m.group("ms")),
        )
    m = RE_ISO_TS.search(raw)
    if m:
        iso = _parse_iso_ts(m.group("ts"))
        if iso is not None:
            return TimestampHit(kind="iso", text=m.group("ts"), iso=iso)
    return None


def _ts_to_seconds(hit: TimestampHit) -> float | None:
    if hit.kind == "iso" and hit.iso is not None:
        try:
            return hit.iso.timestamp()
        except (OverflowError, OSError, ValueError):
            return hit.iso.replace(tzinfo=None).timestamp()
    if hit.kind == "logcat":
        try:
            dt = datetime(
                hit.year or 1970,
                hit.month or 1,
                hit.day or 1,
                hit.hour or 0,
                hit.minute or 0,
                hit.second or 0,
                hit.milli * 1000,
            )
        except ValueError:
            return None
        return dt.timestamp()
    return None


def _duration_seconds(hits: list[TimestampHit]) -> tuple[float | None, str]:
    """Return (duration, source) from an ordered timestamp list.

    Logcat timestamps carry no year and can cross midnight, so wrap-around is
    corrected by adding whole days when the clock moves backwards.
    """
    numeric: list[tuple[float, TimestampHit]] = []
    for hit in hits:
        secs = _ts_to_seconds(hit)
        if secs is not None:
            numeric.append((secs, hit))
    if len(numeric) < 2:
        return None, "none"
    source = "log-iso" if numeric[0][1].kind == "iso" else "log-logcat"
    offset = 0.0
    first = numeric[0][0] + offset
    prev = first
    last = first
    for secs, hit in numeric[1:]:
        cur = secs + offset
        if hit.kind == "logcat" and cur < prev - 12 * 3600:
            offset += 86400.0
            cur += 86400.0
        prev = cur
        last = cur
    if last < first:
        return None, "none"
    return round(last - first, 3), source


# ---------------------------------------------------------------------------
# sidecar metadata
# ---------------------------------------------------------------------------


def _coerce_meta_value(value: object) -> object:
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "yes", "1"):
            return True
        if low in ("false", "no", "0"):
            return False
        try:
            return int(value)
        except ValueError:
            try:
                return float(value)
            except ValueError:
                return value.strip()
    return value


def _find_meta_path(log_path: Path) -> Path | None:
    candidates: list[Path] = []
    for suffix in META_SUFFIXES:
        candidates.append(log_path.with_suffix(log_path.suffix + suffix))
        candidates.append(log_path.with_name(log_path.stem + suffix))
    candidates.append(log_path.with_suffix(".meta.json"))
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def _load_meta(log_path: Path) -> tuple[dict, Path | None]:
    meta_path = _find_meta_path(log_path)
    if meta_path is None:
        return {}, None
    text = _read_text(meta_path)
    meta: dict = {}
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            loaded = json.loads(text)
            if isinstance(loaded, dict):
                meta = dict(loaded)
        except json.JSONDecodeError:
            meta = {}
    if not meta:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            meta[key.strip()] = _coerce_meta_value(value.strip().strip('"'))
    return meta, meta_path


# ---------------------------------------------------------------------------
# data model
# ---------------------------------------------------------------------------


@dataclass
class LandEvent:
    kind: str  # landed | leak | step_ok | step_fail | phase_landed | phase_verify
    phase: str
    attempt: int | None
    detail: str
    line_no: int = 0


@dataclass
class RunData:
    label: str
    file: str
    line_start: int
    line_end: int
    meta: dict = field(default_factory=dict)
    meta_path: str | None = None
    config: dict = field(default_factory=dict)
    explicit_arm: str | None = None
    lines: list[tuple[int, str, str, TimestampHit | None]] = field(default_factory=list)
    # phase -> list of attempt/abort records
    attempts: dict[str, list[dict]] = field(default_factory=dict)
    aborts: dict[str, list[dict]] = field(default_factory=dict)
    abort_drains: list[int] = field(default_factory=list)
    leaked_values: list[int] = field(default_factory=list)
    leak_limit_values: list[int] = field(default_factory=list)
    budget_elapsed_ms: list[int] = field(default_factory=list)
    landings: list[LandEvent] = field(default_factory=list)
    done: bool = False
    fail_codes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    boot_ids: list[str] = field(default_factory=list)
    timestamps: list[TimestampHit] = field(default_factory=list)
    reuse_fast_path: bool = False
    kpl: dict = field(default_factory=dict)  # misc key=value passthrough
    raw_attempt_lines: int = 0

    # filled by postprocess
    arm: str = "unknown"
    phase_stats: dict[str, dict] = field(default_factory=dict)
    boot_id_before: str | None = None
    boot_id_after: str | None = None
    reboot_detected: bool = False
    wall_time_seconds: float | None = None
    time_source: str = "none"
    phase_order: list[str] = field(default_factory=lambda: list(EXPECTED_PHASES))


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

SECTION_KIND_MAP: list[tuple[str, str]] = [
    ("reuse existing kernelsu", "reuse0"),
    ("kaslr", "kaslr"),
    ("patch kernelsu", "ko_patch"),
    ("selinux permissive", "permissive"),
    ("reuse live module", "reuse3b"),
    ("cred target", "cred_target"),
    ("fsuid", "fsuid"),
    ("phase1+phase2", "cred"),
    ("kernelsu userspace", "userspace"),
]


def _section_kind(title: str) -> str:
    low = title.lower()
    for needle, kind in SECTION_KIND_MAP:
        if needle in low:
            return kind
    return "section"


class LogParser:
    def __init__(self, paths: list[Path], label: str | None = None) -> None:
        self.paths = paths
        self.label = label
        self.inputs: list[str] = []
        self.runs: list[RunData] = []
        self.global_warnings: list[str] = []

    # -- input discovery ---------------------------------------------------

    def discover(self) -> list[Path]:
        found: list[Path] = []
        seen: set[Path] = set()
        for path in self.paths:
            if path.is_dir():
                candidates = sorted(
                    p
                    for p in path.rglob("*")
                    if p.is_file() and p.suffix.lower() in LOG_SUFFIXES
                )
                if not candidates:
                    self.global_warnings.append(f"directory has no .log/.txt files: {path}")
                for cand in candidates:
                    resolved = cand.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        found.append(cand)
            elif path.is_file():
                resolved = path.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    found.append(path)
            else:
                self.global_warnings.append(f"input not found (skipped): {path}")
        return found

    # -- public ------------------------------------------------------------

    def parse(self) -> list[RunData]:
        files = self.discover()
        for path in files:
            self.inputs.append(str(path))
            try:
                text = _read_text(path)
            except OSError as exc:
                self.global_warnings.append(f"cannot read {path}: {exc}")
                continue
            meta, meta_path = _load_meta(path)
            default_year = 1970
            try:
                default_year = datetime.fromtimestamp(path.stat().st_mtime).year
            except OSError:
                pass
            payload = self._split_runs(path, text, meta, meta_path, default_year)
            if not payload:
                self.global_warnings.append(f"no run markers/attempts found in {path}")
                continue
            self.runs.extend(payload)
        if self.label:
            if len(self.runs) == 1:
                self.runs[0].label = self.label
            else:
                self.global_warnings.append(
                    "--label ignored: it only applies when exactly one run is parsed"
                )
        for run in self.runs:
            self._postprocess(run)
        return self.runs

    # -- run splitting -----------------------------------------------------

    def _split_runs(
        self,
        path: Path,
        text: str,
        meta: dict,
        meta_path: Path | None,
        default_year: int,
    ) -> list[RunData]:
        records = text.splitlines()
        runs: list[RunData] = []
        current_lines: list[tuple[int, str, str, TimestampHit | None]] = []
        current_marker: dict[str, str] | None = None
        current_start = 1

        def payload_seen() -> bool:
            for _no, _raw, clean, _ts in current_lines:
                if (
                    RE_ATTEMPT.search(clean)
                    or RE_SAFE_MODE.search(clean)
                    or RE_SECTION.match(clean)
                    or clean.strip() in ("DONE",)
                    or RE_FAIL.match(clean)
                ):
                    return True
            return False

        def flush(end_line: int) -> None:
            nonlocal current_lines, current_start, current_marker
            if not current_lines:
                return
            label = ""
            explicit_arm = None
            if current_marker:
                pairs = _kv(current_marker.get("rest", ""))
                label = (
                    pairs.get("label")
                    or pairs.get("name")
                    or pairs.get("id")
                    or current_marker.get("rest", "").strip()
                )
                explicit_arm = pairs.get("arm") or pairs.get("mode")
            run = RunData(
                label=label,
                file=str(path),
                line_start=current_start,
                line_end=end_line,
                meta=dict(meta),
                meta_path=str(meta_path) if meta_path else None,
                explicit_arm=explicit_arm,
                lines=current_lines,
            )
            run.config["_file_default_year"] = default_year
            runs.append(run)
            current_lines = []
            current_marker = None

        for idx, raw in enumerate(records, start=1):
            clean = _normalize_line(raw)
            ts = _timestamp_hit(raw, default_year)
            marker: dict[str, str] | None = None
            stripped = clean.strip()
            m_marker = RE_RUN_MARKER.match(stripped)
            m_boundary = RE_RUN_BOUNDARY.match(stripped)
            if m_boundary:
                marker = {"rest": m_boundary.group("rest")}
            elif m_marker and not RE_VICTIMS_PERMISSIVE.match(clean):
                rest = (m_marker.group("rest") or "").strip()
                # avoid matching a random "RUN ..." prose line
                if "=" in rest or rest.upper().startswith(("AB", "BASELINE", "P0", "SAFE", "PRODUCTION")):
                    marker = {"rest": rest}
            new_run = False
            if marker is not None:
                new_run = True
            elif RE_VICTIMS_PERMISSIVE.match(clean) and payload_seen():
                new_run = True
            if new_run:
                flush(idx - 1)
                current_start = idx
                current_marker = marker
                if marker is None:
                    current_marker = None
            current_lines.append((idx, raw, clean, ts))

        flush(len(records))
        # Keep only chunks that actually contain exploit output.  A run made of
        # only early-abort marker lines (no attempt=) is still a valid sample.
        def looks_like_run(run: RunData) -> bool:
            for _no, _raw, clean, _ts in run.lines:
                stripped = clean.strip()
                if (
                    RE_ATTEMPT.search(clean)
                    or "SAFE_ABORT" in clean
                    or RE_STEP_OK.match(stripped)
                    or "SAFE_MODE=" in clean
                    or stripped == "DONE"
                    or RE_FAIL.match(stripped)
                ):
                    return True
            return False

        runs = [r for r in runs if r.lines and looks_like_run(r)]
        if not runs:
            return []
        used_labels: set[str] = set()
        for number, run in enumerate(runs, start=1):
            if not run.label:
                parent = path.parent.name
                if path.stem.lower() in ("run", "run.log", "device-run") and parent not in ("", ".", ".."):
                    base = f"{parent}/{path.stem}"
                else:
                    base = path.stem
                run.label = base if len(runs) == 1 else f"{base}#{number}"
            label = run.label
            suffix = 2
            while label in used_labels:
                label = f"{run.label}~{suffix}"
                suffix += 1
            run.label = label
            used_labels.add(label)
        return runs

    # -- per run parsing ---------------------------------------------------

    def _split_payload(self, run: RunData) -> tuple[dict, str]:
        """Parse all lines of a run in one pass.

        Returns (config, context_kind).  Records are appended to run fields.
        """
        cfg: dict = run.config
        context = "pre"
        cred_sub: int | None = None
        phase_attempts: dict[str, list[dict]] = {p: [] for p in EXPECTED_PHASES}
        phase_aborts: dict[str, list[dict]] = {p: [] for p in EXPECTED_PHASES}

        def phase_for_context() -> str:
            if context in ("permissive", "fsuid", "cred_phase1", "cred_phase2"):
                return context
            if context == "cred":
                return f"cred_phase{cred_sub or 1}"
            return "unknown"

        for line_no, raw, clean, ts in run.lines:
            if ts is not None:
                run.timestamps.append(ts)
            stripped = clean.strip()
            if not stripped:
                continue

            # config echoes (also works for lines that are not inside sections)
            for key in (
                "VICTIMS_PERMISSIVE",
                "VICTIMS_FSUID",
                "VICTIMS_CRED",
                "GRAB_LOOPS",
                "KERNEL_ACTUAL",
                "KERNEL_PROFILE",
                "PROFILE_READY",
                "SKIP_FSUID",
                "DRAIN_PERMISSIVE",
                "MIN_PERMISSIVE",
                "FRAG_PERMISSIVE",
                "V36_BIN",
                "CRED_BIN",
            ):
                m = re.search(rf"\b{key}=(?P<v>\S+)", stripped)
                if m:
                    cfg[key.lower()] = m.group("v")
            m = re.search(r"\bSAFE_MODE=(?P<v>[01])\b", stripped)
            if m:
                cfg["safe_mode"] = int(m.group("v"))
            m = re.search(r"\bEARLY_ABORT_MS=(?P<v>\d+)\b", stripped)
            if m:
                cfg["early_abort_ms"] = int(m.group("v"))
            m = re.search(r"\bAB_EXPORT=(?P<v>[01])\b", stripped)
            if m:
                cfg["ab_export"] = int(m.group("v"))
            m = RE_SAFE_BUILD.search(stripped)
            if m:
                cfg["safe_build"] = {
                    "name": m.group("name"),
                    "maxvictim": int(m.group("maxvictim")),
                    "early_ms": int(m.group("early")),
                }
            if "SAFE_ARGV" in stripped:
                argv = {
                    key: int(value)
                    for key, value in _kv(stripped).items()
                    if key in ("base_drain", "base_min", "drain1", "min1", "drain2", "min2")
                    and value.lstrip("-").isdigit()
                }
                if argv:
                    cfg["safe_argv"] = argv
            m = re.search(
                r"\bCRED\s+nfrag=(?P<nfrag>\d+)\s+drain1=(?P<d1>\d+)\s+min1=(?P<m1>\d+)"
                r"\s+drain2=(?P<d2>\d+)\s+min2=(?P<m2>\d+)",
                stripped,
            )
            if m:
                cfg["cred_params"] = {k: int(v) for k, v in m.groupdict().items()}
            m = re.search(r"\bATTEMPTS_PERMISSIVE=(?P<v>\d+)\s+ATTEMPTS_CRED=(?P<c1>\d+)/(?P<c2>\d+)", stripped)
            if m:
                cfg["attempts_permissive"] = int(m.group("v"))
                cfg["attempts_cred"] = [int(m.group("c1")), int(m.group("c2"))]
            m = RE_DRAIN_CAP.search(stripped)
            if m:
                cfg["drain_max_ms"] = int(m.group("v"))

            # section headers
            sec = RE_SECTION.match(stripped) or RE_SECTION_ALT.match(stripped)
            if sec:
                title = sec.group("title").strip()
                kind = _section_kind(title)
                if kind in ("permissive", "fsuid"):
                    context = kind
                    cred_sub = None
                elif kind == "cred":
                    context = "cred"
                    cred_sub = None
                else:
                    context = kind
                    cred_sub = None
                continue
            m = RE_CRED_START.match(stripped)
            if m:
                context = "cred"
                cred_sub = int(m.group("p"))
                continue

            # boot ids / reuse fast path
            for m in RE_BOOT_ID.finditer(stripped):
                run.boot_ids.append(m.group("v"))
            if stripped.startswith("MODULE_ALREADY_LIVE"):
                run.reuse_fast_path = True
            if stripped.startswith("MODULE_LIVE_FAST_REPAIR_OK"):
                run.reuse_fast_path = True

            # DONE / FAIL
            if stripped == "DONE":
                run.done = True
                continue
            m = RE_FAIL.match(stripped)
            if m:
                run.fail_codes.append(m.group("code"))
                continue

            # SAFE_ABORT family
            if "SAFE_ABORT" in stripped:
                self._record_abort(run, phase_attempts, phase_aborts, stripped, line_no, context, cred_sub)
                continue

            # normal attempt lines
            m_cred = RE_CRED_ATTEMPT.search(stripped)
            if m_cred and "drained=" in stripped:
                p = int(m_cred.group("p"))
                phase = f"cred_phase{p}"
                self._record_attempt(run, phase_attempts, stripped, line_no, phase)
                continue
            if RE_ATTEMPT.search(stripped) and (
                "victims=" in stripped
                or "timers=" in stripped
                or "landed=" in stripped
                or "drained=" in stripped
            ):
                phase = phase_for_context()
                self._record_attempt(run, phase_attempts, stripped, line_no, phase)
                continue

            # landing / success markers
            m = RE_LANDED.match(stripped)
            if m:
                p = m.group("p")
                phase = f"cred_phase{p}" if p else phase_for_context()
                run.landings.append(
                    LandEvent("landed", phase, int(m.group("n")), stripped, line_no)
                )
                continue
            m = RE_LEAK.match(stripped)
            if m:
                p = m.group("p")
                phase = f"cred_phase{p}" if p else phase_for_context()
                run.landings.append(
                    LandEvent("leak", phase, int(m.group("n")), stripped, line_no)
                )
                continue
            m = RE_STEP_OK.match(stripped)
            if m:
                n = RE_ATTEMPT.search(stripped)
                run.landings.append(
                    LandEvent(
                        "step_ok",
                        phase_for_context(),
                        int(n.group("n")) if n else None,
                        stripped,
                        line_no,
                    )
                )
                continue
            m = RE_STEP_FAIL.match(stripped)
            if m:
                n = RE_ATTEMPT.search(stripped)
                run.landings.append(
                    LandEvent(
                        "step_fail",
                        phase_for_context(),
                        int(n.group("n")) if n else None,
                        stripped,
                        line_no,
                    )
                )
                continue

            # leak / budget / phase markers
            m = RE_LEAK_LIMIT.search(stripped)
            if m:
                run.leak_limit_values.append(int(m.group("v")))
                continue
            m = RE_BUDGET.search(stripped)
            if m:
                run.budget_elapsed_ms.append(int(m.group("v")))
                continue
            m = RE_PHASE_LANDED.match(stripped)
            if m:
                phase = f"cred_phase{int(m.group('p'))}"
                run.landings.append(LandEvent("phase_landed", phase, None, stripped, line_no))
                continue
            m = RE_PHASE_VERIFY.search(stripped)
            if m:
                phase = f"cred_phase{int(m.group('p'))}"
                run.landings.append(
                    LandEvent(
                        "phase_verify",
                        phase,
                        None,
                        stripped + " " + m.group("res"),
                        line_no,
                    )
                )
                continue

            # generic useful key=value (kept for debugging / reporting)
            kv = _kv(stripped)
            for key in (
                "KASLR_SLIDE",
                "KASLR_CACHE_HIT",
                "KO_CACHE_HIT",
                "KO_CACHE_RESTORED",
                "MODULE_LOADED",
                "MODULE_REUSED_AFTER_PERMISSIVE",
            ):
                if key in kv:
                    run.kpl[key] = kv[key]
            if stripped.startswith("KASLR_CACHE_HIT"):
                run.kpl["KASLR_CACHE_HIT"] = "1"
            if stripped.startswith("KO_CACHE_HIT"):
                run.kpl["KO_CACHE_HIT"] = "1"

        run.attempts = phase_attempts
        run.aborts = phase_aborts
        return cfg, context

    def _record_attempt(
        self,
        run: RunData,
        phase_attempts: dict[str, list[dict]],
        text: str,
        line_no: int,
        phase_hint: str,
    ) -> None:
        m_phase = RE_CRED_ATTEMPT.search(text)
        if m_phase:
            phase = f"cred_phase{int(m_phase.group('p'))}"
        else:
            phase = phase_hint or "unknown"
        m_attempt = RE_ATTEMPT.search(text)
        drained = RE_DRAINED.search(text)
        slab = RE_SLAB.search(text)
        base = RE_BASE.search(text)
        kv = _kv(text)
        record = {
            "line": line_no,
            "phase": phase,
            "attempt": int(m_attempt.group("n")) if m_attempt else None,
            "drained": int(drained.group("flag")) if drained else None,
            "drain_ms": int(drained.group("ms")) if drained else None,
            "slab_active": int(slab.group("a")) if slab else None,
            "slab_total": int(slab.group("t")) if slab else None,
            "base_active": int(base.group("a")) if base else None,
            "base_total": int(base.group("t")) if base else None,
            "frag": _safe_int(kv.get("frag")),
            "timers": _safe_int(kv.get("timers")),
            "victims": _safe_int(kv.get("victims")),
            "landed": _safe_int(kv.get("landed")),
            "leaked": _safe_int(kv.get("leaked")),
            "leak": _safe_int(kv.get("leak")),
            "kind": "attempt",
            "raw": text,
        }
        phase_attempts.setdefault(phase, []).append(record)
        if record["leaked"] is not None:
            run.leaked_values.append(record["leaked"])
        elif record["leak"] is not None:
            run.leaked_values.append(record["leak"])
        run.raw_attempt_lines += 1

    def _record_abort(
        self,
        run: RunData,
        phase_attempts: dict[str, list[dict]],
        phase_aborts: dict[str, list[dict]],
        text: str,
        line_no: int,
        context: str,
        cred_sub: int | None,
    ) -> None:
        m_early = re.search(r"\bSAFE_ABORT\s+early\b", text)
        if not m_early:
            m_early = re.search(r"\bearly\b", text)
        early = m_early is not None
        drained = RE_DRAINED.search(text)
        slab = RE_SLAB.search(text)
        base = RE_BASE.search(text)
        elapsed = RE_ELAPSED_MS.search(text)
        best = RE_BEST.search(text)
        stall = RE_STALL.search(text)
        m_phase_num = RE_PHASE_NUM.search(text)
        kv = _kv(text)
        m_attempt = RE_ATTEMPT.search(text)
        m_p = re.search(r"\bp(?P<p>[12])\s+attempt=", text)
        if m_p:
            phase = f"cred_phase{int(m_p.group('p'))}"
        elif m_phase_num:
            phase = f"cred_phase{int(m_phase_num.group('p'))}"
        elif context in ("permissive", "fsuid"):
            phase = context
        elif context == "cred":
            phase = f"cred_phase{cred_sub or 1}"
        else:
            phase = "unknown"
        reason = "other"
        if "short_spray" in text:
            reason = "short_spray"
        elif "slab_regrown" in text:
            reason = "slab_regrown"
        elif "drained=" in text:
            reason = "drain_timeout"
        elif early:
            reason = "early_marker"
        summer = bool(("short_spray" in text) or ("slab_regrown" in text) or ("drained=" in text))
        record = {
            "line": line_no,
            "phase": phase,
            "attempt": int(m_attempt.group("n")) if m_attempt else None,
            "drained": int(drained.group("flag")) if drained else None,
            "drain_ms": int(drained.group("ms")) if drained else None,
            "slab_active": int(slab.group("a")) if slab else None,
            "slab_total": int(slab.group("t")) if slab else None,
            "base_active": int(base.group("a")) if base else None,
            "base_total": int(base.group("t")) if base else None,
            "frag": _safe_int(kv.get("frag")),
            "leaked": _safe_int(kv.get("leaked")),
            "kind": "abort",
            "reason": reason,
            "early": early,
            "summer": summer,
            "elapsed_ms": int(elapsed.group("ms")) if elapsed else _safe_int(kv.get("elapsed")),
            "best_active": int(best.group("a")) if best else _safe_int(kv.get("best")),
            "stall_ms": int(stall.group("ms")) if stall else None,
            "raw": text,
        }
        phase_aborts.setdefault(phase, []).append(record)
        if record["drained"] is not None:
            phase_attempts.setdefault(phase, []).append(record)
        if record["drain_ms"] is not None:
            run.abort_drains.append(record["drain_ms"])
        if record["leaked"] is not None:
            run.leaked_values.append(record["leaked"])

    # -- postprocess -------------------------------------------------------

    def _postprocess(self, run: RunData) -> None:
        cfg = run.config
        self._split_payload(run)

        # metadata overrides / annotations
        meta = run.meta or {}
        if meta.get("label"):
            run.label = str(meta["label"])
        run.boot_id_before = str(meta.get("boot_id_before") or "").strip() or None
        run.boot_id_after = str(meta.get("boot_id_after") or "").strip() or None
        if not run.boot_id_before or not run.boot_id_after:
            before = meta.get("boot_before") or meta.get("bootid_before")
            after = meta.get("boot_after") or meta.get("bootid_after")
            if before and not run.boot_id_before:
                run.boot_id_before = str(before).strip()
            if after and not run.boot_id_after:
                run.boot_id_after = str(after).strip()
        if run.boot_ids:
            if not run.boot_id_before:
                run.boot_id_before = run.boot_ids[0]
            if not run.boot_id_after:
                run.boot_id_after = run.boot_ids[-1]
        reboot_meta = meta.get("reboot_detected", meta.get("reboot"))
        if isinstance(reboot_meta, str):
            reboot_meta = reboot_meta.strip().lower() in ("1", "true", "yes")
        run.reboot_detected = bool(reboot_meta)
        if (
            not run.reboot_detected
            and run.boot_id_before
            and run.boot_id_after
            and run.boot_id_before != run.boot_id_after
        ):
            run.reboot_detected = True
        if len({b for b in run.boot_ids}) > 1:
            run.reboot_detected = True

        # wall time: log timestamps first, then sidecar
        run.wall_time_seconds, run.time_source = _duration_seconds(run.timestamps)
        if run.wall_time_seconds is None:
            for key in ("wall_time_seconds", "duration_seconds", "elapsed_seconds"):
                value = meta.get(key)
                if isinstance(value, (int, float)):
                    run.wall_time_seconds = round(float(value), 3)
                    run.time_source = "meta"
                    break
        if run.wall_time_seconds is None:
            started = meta.get("started_at")
            finished = meta.get("finished_at")
            if isinstance(started, str) and isinstance(finished, str):
                start_dt = _parse_iso_ts(started)
                end_dt = _parse_iso_ts(finished)
                if start_dt and end_dt:
                    run.wall_time_seconds = round((end_dt - start_dt).total_seconds(), 3)
                    run.time_source = "meta"

        # arm inference
        arm = self._infer_arm(run, cfg, meta)
        run.arm = arm

        # phase stats
        stats: dict[str, dict] = {}
        for phase in EXPECTED_PHASES:
            stats[phase] = self._phase_stats(
                phase, run.attempts.get(phase, []), run.aborts.get(phase, []), run.landings
            )
        for phase in sorted(set(run.attempts) | set(run.aborts)):
            if phase not in stats:
                stats[phase] = self._phase_stats(
                    phase, run.attempts.get(phase, []), run.aborts.get(phase, []), run.landings
                )
        run.phase_stats = stats
        present = [p for p in stats if stats[p]["present"]]
        # Keep expected phases first, then any extra (e.g. unknown) at the end.
        ordered = [p for p in EXPECTED_PHASES if p in stats]
        ordered += sorted(p for p in stats if p not in EXPECTED_PHASES)
        run.phase_order = ordered
        if not present:
            run.warnings.append("no attempt/abort lines parsed")
        if run.reuse_fast_path:
            run.warnings.append("run took the MODULE_ALREADY_LIVE fast-repair path; not a valid exploit A/B sample")
        if run.reboot_detected:
            run.warnings.append("reboot detected before/after this run; exclude from metrics")
        if not run.done and not run.fail_codes and not run.reboot_detected:
            run.warnings.append("log has neither DONE nor FAIL= (truncated or still running)")
        for phase in present:
            if stats[phase]["attempts"] == 0:
                run.warnings.append(f"phase {phase} has abort records but no attempt records")
        unknown = stats.get("unknown")
        if unknown and unknown["present"]:
            run.warnings.append("some attempts could not be mapped to a phase")

    def _infer_arm(self, run: RunData, cfg: dict, meta: dict) -> str:
        override = meta.get("arm") or run.explicit_arm
        if override:
            key = str(override).strip().lower()
            aliases = {
                "baseline": "safe-baseline",
                "safe-baseline": "safe-baseline",
                "safe_baseline": "safe-baseline",
                "safe": "safe-baseline",
                "p0": "p0-early",
                "p0-early": "p0-early",
                "p0_early": "p0-early",
                "early": "p0-early",
                "early-abort": "p0-early",
                "production": "production",
                "prod": "production",
            }
            if key in aliases:
                return aliases[key]
            return key
        safe = cfg.get("safe_mode")
        early = cfg.get("early_abort_ms")
        v36_bin = str(cfg.get("v36_bin") or "")
        cred_bin = str(cfg.get("cred_bin") or "")
        safe_bin = "_safe" in v36_bin or "_safe" in cred_bin
        any_early = any(rec.get("early") for recs in run.aborts.values() for rec in recs)
        any_abort = any(recs for recs in run.aborts.values())
        if safe == 1:
            if isinstance(early, int) and early > 0:
                return "p0-early"
            return "safe-baseline"
        if safe == 0:
            return "production"
        if any_early:
            return "p0-early"
        if any_abort:
            return "safe-baseline"
        if safe_bin:
            return "safe-baseline"
        if any(cfg.get(k) for k in ("victims_permissive", "kernel_actual")):
            return "production"
        return "unknown"

    def _phase_stats(
        self,
        phase: str,
        attempts: list[dict],
        aborts: list[dict],
        landings: list[LandEvent],
    ) -> dict:
        attempt_numbers = {
            rec["attempt"]
            for rec in attempts + aborts
            if rec.get("attempt") is not None
        }
        normal = [rec for rec in attempts if rec.get("kind") == "attempt"]
        abort_events = [rec for rec in aborts if rec.get("summer")]
        early_aborts = [rec for rec in aborts if rec.get("early")]
        reasons: dict[str, int] = {}
        for rec in abort_events:
            reasons[rec.get("reason", "other")] = reasons.get(rec.get("reason", "other"), 0) + 1
        drain_samples = [
            rec["drain_ms"]
            for rec in (normal + abort_events)
            if rec.get("drain_ms") is not None
        ]
        abort_drain_samples = [
            rec["drain_ms"] for rec in abort_events if rec.get("drain_ms") is not None
        ]
        leaked = [
            rec["leaked"]
            for rec in (normal + aborts)
            if rec.get("leaked") is not None and rec.get("kind") in ("attempt", "abort")
        ]
        landed_numbers = sorted(
            {
                rec.get("attempt")
                for rec in normal
                if rec.get("landed") == 1 and rec.get("attempt") is not None
            }
        )
        phase_landings = [le for le in landings if le.phase == phase]
        for le in phase_landings:
            if le.attempt is not None and le.kind in ("landed", "leak", "step_ok"):
                landed_numbers.append(le.attempt)
        landed_numbers = sorted(set(landed_numbers))
        step_ok = [le.attempt for le in phase_landings if le.kind == "step_ok" and le.attempt is not None]
        leak_attempts = [le.attempt for le in phase_landings if le.kind == "leak" and le.attempt is not None]
        attempt_count = (
            max(attempt_numbers)
            if attempt_numbers
            else len(normal) + len(abort_events)
        )
        return {
            "present": bool(attempts or aborts or phase_landings),
            "attempts": attempt_count,
            "attempt_lines": len(normal),
            "attempt_numbers_seen": len(attempt_numbers),
            "abort_lines": len(aborts),
            "abort_events": len(abort_events),
            "early_aborts": len(early_aborts),
            "abort_reasons": reasons,
            "abort_drain": _drain_stats(abort_drain_samples),
            "drain": _drain_stats(drain_samples),
            "leaked_start": leaked[0] if leaked else None,
            "leaked_end": leaked[-1] if leaked else None,
            "leaked_max": max(leaked) if leaked else None,
            "landing_attempts": landed_numbers,
            "first_landing_attempt": landed_numbers[0] if landed_numbers else None,
            "step_ok_attempts": sorted(set(step_ok)),
            "leak_attempts": sorted(set(leak_attempts)),
            "phase_landed_flag": any(le.kind == "phase_landed" for le in phase_landings),
            "phase_verify": [
                le.detail for le in phase_landings if le.kind == "phase_verify"
            ],
            "step_fail": sum(1 for le in phase_landings if le.kind == "step_fail"),
        }

    # -- run level summary -------------------------------------------------

    @staticmethod
    def run_summary(run: RunData) -> dict:
        stats = run.phase_stats
        drain_all: list[int] = []
        abort_events = 0
        early_aborts = 0
        abort_lines = 0
        attempts_total = 0
        leaked: list[int] = list(run.leaked_values)
        for phase, st in stats.items():
            attempts_total += st["attempts"]
            abort_events += st["abort_events"]
            early_aborts += st["early_aborts"]
            abort_lines += st["abort_lines"]
            for rec in run.attempts.get(phase, []):
                if rec.get("kind") == "attempt" and rec.get("drain_ms") is not None:
                    drain_all.append(rec["drain_ms"])
            for rec in run.aborts.get(phase, []):
                if rec.get("summer") and rec.get("drain_ms") is not None:
                    drain_all.append(rec["drain_ms"])
        leaked_max = max(leaked) if leaked else None
        if run.leak_limit_values:
            leaked_max = max(leaked_max or 0, max(run.leak_limit_values))
        return {
            "label": run.label,
            "file": run.file,
            "meta_file": run.meta_path,
            "arm": run.arm,
            "status": "done" if run.done else (f"fail:{run.fail_codes[0]}" if run.fail_codes else ("reboot" if run.reboot_detected else "incomplete")),
            "done": run.done,
            "fail_codes": run.fail_codes,
            "reboot_detected": run.reboot_detected,
            "reuse_fast_path": run.reuse_fast_path,
            "boot_id_before": run.boot_id_before,
            "boot_id_after": run.boot_id_after,
            "line_range": [run.line_start, run.line_end],
            "config": {
                key: value
                for key, value in run.config.items()
                if not key.startswith("_")
            },
            "attempts_total": attempts_total,
            "attempt_lines_total": run.raw_attempt_lines,
            "abort_lines_total": abort_lines,
            "abort_events_total": abort_events,
            "early_aborts_total": early_aborts,
            "drain": _drain_stats(drain_all),
            "drain_samples_ms": drain_all,
            "abort_drain": _drain_stats(run.abort_drains),
            "leaked_start": leaked[0] if leaked else None,
            "leaked_end": leaked[-1] if leaked else None,
            "leaked_max": leaked_max,
            "leak_limit_count": len(run.leak_limit_values),
            "leak_limit_values": list(run.leak_limit_values),
            "budget_exceeded_count": len(run.budget_elapsed_ms),
            "budget_elapsed_ms": list(run.budget_elapsed_ms),
            "phase_landings": {
                phase: stats[phase]["first_landing_attempt"]
                for phase in run.phase_order
                if stats[phase]["present"]
            },
            "step_ok_attempts": {
                phase: stats[phase]["step_ok_attempts"]
                for phase in run.phase_order
                if stats[phase]["present"]
            },
            "wall_time_seconds": run.wall_time_seconds,
            "time_source": run.time_source,
            "sum_attempt_drain_ms": sum(drain_all),
            "kpl": dict(run.kpl),
            "warnings": list(run.warnings),
            "phases": {phase: stats[phase] for phase in run.phase_order},
        }


# ---------------------------------------------------------------------------
# aggregation / acceptance comparison
# ---------------------------------------------------------------------------


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 3) if values else None


def mode_summary(runs: list[dict]) -> dict:
    summary: dict[str, dict] = {}
    for run in runs:
        arm = run["arm"]
        bucket = summary.setdefault(
            arm,
            {
                "runs": 0,
                "done": 0,
                "fail": 0,
                "reboot": 0,
                "incomplete": 0,
                "reuse_fast_path": 0,
                "drain_samples": [],
                "run_medians": [],
                "abort_events_total": 0,
                "early_aborts_total": 0,
                "leak_limit_total": 0,
                "budget_exceeded_total": 0,
                "leaked_max": None,
                "phase_landings": {p: [] for p in EXPECTED_PHASES},
                "wall_time_seconds": [],
                "runs_detail": [],
            },
        )
        bucket["runs"] += 1
        status = run["status"]
        if run["done"]:
            bucket["done"] += 1
        elif status.startswith("fail:"):
            bucket["fail"] += 1
        elif run["reboot_detected"]:
            bucket["reboot"] += 1
        else:
            bucket["incomplete"] += 1
        if run["reuse_fast_path"]:
            bucket["reuse_fast_path"] += 1
        if run["drain"]["samples"]:
            bucket["drain_samples"].extend(run.get("drain_samples_ms") or [])
            bucket["run_medians"].append(run["drain"]["median_ms"])
        bucket["abort_events_total"] += run["abort_events_total"]
        bucket["early_aborts_total"] += run["early_aborts_total"]
        bucket["leak_limit_total"] += run["leak_limit_count"]
        bucket["budget_exceeded_total"] += run["budget_exceeded_count"]
        if run["leaked_max"] is not None:
            bucket["leaked_max"] = max(bucket["leaked_max"] or 0, run["leaked_max"])
        if run["wall_time_seconds"] is not None:
            bucket["wall_time_seconds"].append(run["wall_time_seconds"])
        for phase, value in (run.get("phase_landings") or {}).items():
            if isinstance(value, int):
                bucket["phase_landings"].setdefault(phase, []).append(value)
        bucket["runs_detail"].append(
            {
                "label": run["label"],
                "status": run["status"],
                "done": run["done"],
                "reboot_detected": run["reboot_detected"],
                "attempts_total": run["attempts_total"],
                "abort_events_total": run["abort_events_total"],
                "early_aborts_total": run["early_aborts_total"],
                "drain_median_ms": run["drain"]["median_ms"],
                "drain_p90_ms": run["drain"]["p90_ms"],
                "leaked_max": run["leaked_max"],
                "phase_landings": run.get("phase_landings") or {},
                "wall_time_seconds": run["wall_time_seconds"],
            }
        )
    for arm, bucket in summary.items():
        n = bucket["runs"]
        bucket["label"] = MODE_LABELS.get(arm, arm)
        bucket["success_rate"] = round(bucket["done"] / n, 3) if n else None
        bucket["abort_events_per_run"] = round(bucket["abort_events_total"] / n, 2) if n else None
        bucket["early_aborts_per_run"] = round(bucket["early_aborts_total"] / n, 2) if n else None
        bucket["drain_median_mean_ms"] = _mean([v for v in bucket["run_medians"] if v is not None])
        if bucket["drain_samples"]:
            samples = bucket["drain_samples"]
            bucket["pooled_drain_median_ms"] = round(float(median(samples)), 1)
            bucket["pooled_drain_p90_ms"] = round(float(_percentile_nearest_rank(samples, 90)), 1)
            bucket["pooled_drain_samples"] = len(samples)
        else:
            bucket["pooled_drain_median_ms"] = None
            bucket["pooled_drain_p90_ms"] = None
            bucket["pooled_drain_samples"] = 0
        bucket["mean_first_landing_attempt"] = {
            phase: _mean([float(v) for v in values])
            for phase, values in bucket["phase_landings"].items()
            if values
        }
        bucket["mean_wall_time_seconds"] = _mean(bucket["wall_time_seconds"])
        bucket.pop("drain_samples", None)
    return summary


def build_comparison(
    runs: list[dict],
    abort_tolerance: float = 1.0,
    landing_tolerance: float = 1.0,
    median_limit_ms: float = 5500.0,
) -> dict | None:
    baseline = [r for r in runs if r["arm"] == "safe-baseline"]
    p0 = [r for r in runs if r["arm"] == "p0-early"]
    if not baseline or not p0:
        return None
    summary = mode_summary(runs)
    b = summary["safe-baseline"]
    p = summary["p0-early"]
    metrics: dict[str, dict] = {}

    b_median = b["pooled_drain_median_ms"]
    p_median = p["pooled_drain_median_ms"]
    metrics["median_drain_ms"] = {
        "baseline": b_median,
        "p0": p_median,
        "delta": round(p_median - b_median, 1) if (b_median is not None and p_median is not None) else None,
        "rule": f"p0 pooled drain median <= {median_limit_ms:.0f} ms",
        "pass": (p_median is not None and p_median <= median_limit_ms),
    }

    b_abort = b["abort_events_per_run"]
    p_abort = p["abort_events_per_run"]
    metrics["abort_events_per_run"] = {
        "baseline": b_abort,
        "p0": p_abort,
        "delta": round(p_abort - b_abort, 2) if (b_abort is not None and p_abort is not None) else None,
        "tolerance": abort_tolerance,
        "rule": f"p0 mean SAFE_ABORT events/run <= baseline + {abort_tolerance:g}",
        "pass": (p_abort is not None and b_abort is not None and p_abort <= b_abort + abort_tolerance),
    }

    landing_rows: dict[str, dict] = {}
    landing_pass_flags: list[bool] = []
    for phase in EXPECTED_PHASES:
        b_vals = b["phase_landings"].get(phase) or []
        p_vals = p["phase_landings"].get(phase) or []
        b_mean = _mean([float(v) for v in b_vals])
        p_mean = _mean([float(v) for v in p_vals])
        if b_mean is None or p_mean is None:
            landing_rows[phase] = {
                "baseline": b_mean,
                "p0": p_mean,
                "delta": None,
                "rule": "n/a (one arm has no landing in this phase)",
                "pass": None,
            }
            continue
        passed = p_mean <= b_mean + landing_tolerance
        landing_pass_flags.append(passed)
        landing_rows[phase] = {
            "baseline": b_mean,
            "p0": p_mean,
            "delta": round(p_mean - b_mean, 2),
            "tolerance": landing_tolerance,
            "rule": f"p0 mean first landing attempt <= baseline + {landing_tolerance:g}",
            "pass": passed,
        }
    metrics["landing_attempts"] = landing_rows

    p0_reboots = sum(1 for r in p0 if r["reboot_detected"])
    metrics["reboots"] = {
        "p0_reboot_runs": p0_reboots,
        "baseline_reboot_runs": sum(1 for r in baseline if r["reboot_detected"]),
        "rule": "p0 reboot runs == 0",
        "pass": p0_reboots == 0,
    }

    p0_reuse = sum(1 for r in p0 if r["reuse_fast_path"])
    baseline_reuse = sum(1 for r in baseline if r["reuse_fast_path"])
    metrics["valid_sample"] = {
        "p0_reuse_fast_path_runs": p0_reuse,
        "baseline_reuse_fast_path_runs": baseline_reuse,
        "rule": "no run may take the MODULE_ALREADY_LIVE fast path",
        "pass": (p0_reuse + baseline_reuse) == 0,
    }

    metrics["success_rate"] = {
        "baseline": b["success_rate"],
        "p0": p["success_rate"],
        "delta": None,
        "rule": "informational: p0 DONE rate >= baseline DONE rate",
        "pass": None,
    }
    if b["success_rate"] is not None and p["success_rate"] is not None:
        metrics["success_rate"]["delta"] = round(p["success_rate"] - b["success_rate"], 3)
        metrics["success_rate"]["pass"] = p["success_rate"] >= b["success_rate"]

    overall_parts = [
        metrics["median_drain_ms"]["pass"],
        metrics["abort_events_per_run"]["pass"],
        metrics["reboots"]["pass"],
        metrics["valid_sample"]["pass"],
    ]
    if landing_pass_flags:
        overall_parts.append(all(landing_pass_flags))
    overall = all(flag is True for flag in overall_parts) if overall_parts else None
    return {
        "baseline_runs": len(baseline),
        "p0_runs": len(p0),
        "metrics": metrics,
        "overall_pass": overall,
        "thresholds": {
            "median_drain_ms": median_limit_ms,
            "abort_tolerance": abort_tolerance,
            "landing_tolerance": landing_tolerance,
        },
    }


# ---------------------------------------------------------------------------
# output builders
# ---------------------------------------------------------------------------


def _fmt(value: object, digits: int = 1) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        text = f"{value:.{digits}f}"
        return text.rstrip("0").rstrip(".") if "." in text else text
    return str(value)


def _md_escape(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def build_markdown(runs: list[dict], summary: dict, comparison: dict | None, inputs: list[str], warnings: list[str]) -> str:
    out: list[str] = []
    out.append("# P0 A/B 安全模式日志解析报告")
    out.append("")
    out.append(f"- 工具: `parse_safe_ab.py` v{TOOL_VERSION} (离线解析，不接触设备)")
    out.append(f"- 输入: {len(inputs)} 个文件")
    for item in inputs:
        out.append(f"  - `{item}`")
    out.append(f"- 解析运行数: {len(runs)}")
    mode_counts: dict[str, int] = {}
    for run in runs:
        mode_counts[run["arm"]] = mode_counts.get(run["arm"], 0) + 1
    out.append(
        "- 模式分布: " + ", ".join(f"{k}={v}" for k, v in sorted(mode_counts.items()))
    )
    out.append("")

    out.append("## 按模式汇总")
    out.append("")
    out.append(
        "| 模式 | runs | DONE | FAIL | reboot | 无效样本(reuse) | 全局 drain 中位 ms | 全局 p90 ms | "
        "SAFE_ABORT 次数 | early abort 次数 | leaked max | 成功率 |"
    )
    out.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for arm in sorted(summary):
        b = summary[arm]
        out.append(
            "| {arm} | {runs} | {done} | {fail} | {reboot} | {reuse} | {med} | {p90} | {abort} | {early} | {leak} | {rate} |".format(
                arm=MODEL_ARM_LABEL.get(arm, arm),
                runs=b["runs"],
                done=b["done"],
                fail=b["fail"],
                reboot=b["reboot"],
                reuse=b["reuse_fast_path"],
                med=_fmt(b["pooled_drain_median_ms"]),
                p90=_fmt(b["pooled_drain_p90_ms"]),
                abort=b["abort_events_total"],
                early=b["early_aborts_total"],
                leak=_fmt(b["leaked_max"]),
                rate=_fmt(b["success_rate"], 2),
            )
        )
    out.append("")

    out.append("## 每次运行")
    out.append("")
    out.append(
        "| run | 模式 | 结果 | attempts | abort(early) | drain 中位 ms | p90 ms | "
        "leaked 起/止/max | landing permissive/fsuid | landing cred p1/p2 | 时长 s |"
    )
    out.append("|---|---|---|---:|---:|---:|---:|---|---|---|---:|")
    for run in runs:
        landings = run.get("phase_landings") or {}
        out.append(
            "| {label} | {arm} | {status} | {attempts} | {abort}({early}) | {med} | {p90} | "
            "{ls}/{le}/{lm} | {perm}/{fsuid} | {p1}/{p2} | {wall} |".format(
                label=_md_escape(run["label"]),
                arm=MODEL_ARM_LABEL.get(run["arm"], run["arm"]),
                status=_md_escape(run["status"]),
                attempts=run["attempts_total"],
                abort=run["abort_events_total"],
                early=run["early_aborts_total"],
                med=_fmt(run["drain"]["median_ms"]),
                p90=_fmt(run["drain"]["p90_ms"]),
                ls=_fmt(run["leaked_start"]),
                le=_fmt(run["leaked_end"]),
                lm=_fmt(run["leaked_max"]),
                perm=_fmt(landings.get("permissive")),
                fsuid=_fmt(landings.get("fsuid")),
                p1=_fmt(landings.get("cred_phase1")),
                p2=_fmt(landings.get("cred_phase2")),
                wall=_fmt(run["wall_time_seconds"]),
            )
        )
    out.append("")

    if comparison:
        out.append("## A/B 验收（safe-baseline vs p0-early）")
        out.append("")
        out.append(
            f"- 样本: baseline {comparison['baseline_runs']} runs, P0 {comparison['p0_runs']} runs"
        )
        out.append(f"- **总体判定: {'PASS' if comparison['overall_pass'] else 'FAIL / 待确认'}**")
        out.append("")
        metrics = comparison["metrics"]
        out.append("| 指标 | baseline | P0 | delta | 规则 | 判定 |")
        out.append("|---|---:|---:|---:|---|---|")
        med = metrics["median_drain_ms"]
        out.append(
            f"| drain 中位 (ms) | {_fmt(med['baseline'])} | {_fmt(med['p0'])} | {_fmt(med['delta'])} | "
            f"{_md_escape(med['rule'])} | {'PASS' if med['pass'] else 'FAIL'} |"
        )
        ab = metrics["abort_events_per_run"]
        out.append(
            f"| SAFE_ABORT 次数/run | {_fmt(ab['baseline'], 2)} | {_fmt(ab['p0'], 2)} | {_fmt(ab['delta'], 2)} | "
            f"{_md_escape(ab['rule'])} | {'PASS' if ab['pass'] else 'FAIL'} |"
        )
        for phase in EXPECTED_PHASES:
            row = metrics["landing_attempts"].get(phase)
            if not row:
                continue
            verdict = "n/a" if row["pass"] is None else ("PASS" if row["pass"] else "FAIL")
            out.append(
                f"| first landing {PHASE_LABELS.get(phase, phase)} | {_fmt(row['baseline'], 2)} | "
                f"{_fmt(row['p0'], 2)} | {_fmt(row['delta'], 2)} | {_md_escape(row['rule'])} | {verdict} |"
            )
        rb = metrics["reboots"]
        out.append(
            f"| 重启 run 数 | {rb['baseline_reboot_runs']} | {rb['p0_reboot_runs']} | - | "
            f"{_md_escape(rb['rule'])} | {'PASS' if rb['pass'] else 'FAIL'} |"
        )
        vs = metrics["valid_sample"]
        out.append(
            f"| 有效样本 (无 reuse 快路径) | {vs['baseline_reuse_fast_path_runs']} 次 reuse | "
            f"{vs['p0_reuse_fast_path_runs']} 次 reuse | - | {_md_escape(vs['rule'])} | "
            f"{'PASS' if vs['pass'] else 'FAIL'} |"
        )
        sr = metrics["success_rate"]
        out.append(
            f"| DONE 成功率 | {_fmt(sr['baseline'], 2)} | {_fmt(sr['p0'], 2)} | {_fmt(sr['delta'], 2)} | "
            f"{_md_escape(sr['rule'])} | {('PASS' if sr['pass'] else 'FAIL') if sr['pass'] is not None else 'info'} |"
        )
        out.append("")
        out.append(
            "> 判定规则可在命令行动态调整：`--median-limit-ms`、`--abort-tolerance`、`--landing-tolerance`。"
        )
        out.append("")

    if warnings:
        out.append("## 警告")
        out.append("")
        for warning in warnings:
            out.append(f"- {warning}")
        out.append("")

    out.append("## 字段说明 / 假设")
    out.append("")
    out.append("- `attempts`: 每个 phase 内执行到的最大 attempt 序号（缺失行为 0 时退化为 attempt 行数）。")
    out.append(
        "- `abort_events`: 含 `drained=0(...)` / `short_spray` / `slab_regrown` 的 SAFE_ABORT 事件；"
        "若 early 早停单独打印一行 `SAFE_ABORT early ...`，该行计入 `early_aborts` 而不重复计为一次 abort 事件。"
    )
    out.append("- `early_aborts`: 行内包含 `SAFE_ABORT` 与 `early` 的行数。")
    out.append("- `drain median/p90`: 仅统计 attempt/abort 摘要行里 `drained=N(ms)` 的 drain 循环时长；p90 用 nearest-rank。")
    out.append("- `leaked 起/止/max`: 按日志顺序取 `leaked=`（cred 旧格式回退到 `leak=`）；`SAFE_LEAK_LIMIT leaked=` 也参与 max。")
    out.append("- `landing`: v36 取 `STEP_OK`/`LANDED`/`landed=1`，cred 取 `LEAK pN attempt=`；first = 最小 attempt。")
    out.append("- `时长 s`: 仅当日志含时间戳或 sidecar 记录 wall time 时给出，否则为 `-`；`time_source` 在 JSON 中。")
    out.append("- phase 推断: `== 3. SELinux permissive ==` → permissive；`== 5. fsuid/fsgid ==` → fsuid；")
    out.append("  `== 6. phase1+phase2 ==` 内的 `p1/p2` 前缀或 `== phaseN start` → cred phase1/phase2。")
    out.append("- 模式推断: `SAFE_MODE=1` 且 `EARLY_ABORT_MS>0` → `p0-early`；`SAFE_MODE=1` 且 0/缺省 → `safe-baseline`；")
    out.append("  `SAFE_MODE=0` → `production`；无法判断时为 `unknown`（可用 sidecar `arm=` 覆盖）。")
    out.append("")
    return "\n".join(out)


MODEL_ARM_LABEL = {
    "safe-baseline": "safe-baseline",
    "p0-early": "p0-early",
    "production": "production",
    "unknown": "unknown",
}


# ---------------------------------------------------------------------------
# JSON / CSV
# ---------------------------------------------------------------------------


def build_json(runs: list[dict], summary: dict, comparison: dict | None, inputs: list[str], warnings: list[str]) -> dict:
    totals = {
        "runs": len(runs),
        "done": sum(1 for r in runs if r["done"]),
        "fail": sum(1 for r in runs if r["status"].startswith("fail:")),
        "incomplete": sum(
            1
            for r in runs
            if not r["done"] and not r["status"].startswith("fail:") and not r["reboot_detected"]
        ),
        "reboot": sum(1 for r in runs if r["reboot_detected"]),
        "attempts_total": sum(r["attempts_total"] for r in runs),
        "abort_events_total": sum(r["abort_events_total"] for r in runs),
        "early_aborts_total": sum(r["early_aborts_total"] for r in runs),
    }
    return {
        "schema": SCHEMA,
        "tool": {"name": "parse_safe_ab.py", "version": TOOL_VERSION},
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "inputs": inputs,
        "runs": runs,
        "mode_summary": summary,
        "comparison": comparison,
        "totals": totals,
        "warnings": warnings,
        "field_notes": {
            "attempts": "max attempt number seen in the phase (falls back to attempt-line count)",
            "abort_events": "SAFE_ABORT summary lines containing drained=/short_spray/slab_regrown",
            "early_aborts": "SAFE_ABORT lines containing the word early",
            "drain": "drained=N(ms) durations from attempt/abort summary lines; p90 nearest-rank",
            "leaked": "values of leaked= (cred legacy leak= fallback); SAFE_LEAK_LIMIT leaked= also contributes to max",
            "landing": "STEP_OK/LANDED/landed=1 for v36, LEAK pN attempt= for cred; first = minimum attempt",
            "phase_inference": "run.sh == N. section == headers + cred p1/p2 prefixes / == phaseN start",
            "mode_inference": "SAFE_MODE/EARLY_ABORT_MS config echo; sidecar arm= overrides",
            "wall_time": "log timestamps, then sidecar wall_time_seconds/started_at+finished_at; else null",
        },
    }


CSV_COLUMNS = [
    "run",
    "file",
    "arm",
    "status",
    "phase",
    "present",
    "attempts",
    "attempt_lines",
    "abort_events",
    "early_aborts",
    "median_drain_ms",
    "p90_drain_ms",
    "drain_samples",
    "leaked_start",
    "leaked_end",
    "leaked_max",
    "first_landing_attempt",
    "step_ok_attempts",
    "phase_landed_flag",
    "wall_time_seconds",
]


def build_csv_rows(runs: list[dict]) -> list[list[object]]:
    rows: list[list[object]] = []
    for run in runs:
        for phase, st in run["phases"].items():
            rows.append(
                [
                    run["label"],
                    run["file"],
                    run["arm"],
                    run["status"],
                    phase,
                    st["present"],
                    st["attempts"],
                    st["attempt_lines"],
                    st["abort_events"],
                    st["early_aborts"],
                    st["drain"]["median_ms"],
                    st["drain"]["p90_ms"],
                    st["drain"]["samples"],
                    st["leaked_start"],
                    st["leaked_end"],
                    st["leaked_max"],
                    st["first_landing_attempt"],
                    ";".join(str(v) for v in st["step_ok_attempts"]),
                    st["phase_landed_flag"],
                    run["wall_time_seconds"],
                ]
            )
    return rows


def write_csv(path: Path, rows: list[list[object]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_COLUMNS)
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Parse MagicRoot safe-mode A/B run logs offline. "
            "Inputs may be run.log files or directories containing them."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python release/tools/parse_safe_ab.py release/publish/experiments/p0-ab/sessions\n"
            "  python release/tools/parse_safe_ab.py run.log --format json\n"
            "  python release/tools/parse_safe_ab.py sessions/ --out-json p0-ab.json --out-markdown p0-ab.md\n"
        ),
    )
    parser.add_argument("paths", nargs="+", help="run.log files and/or directories")
    parser.add_argument(
        "--format",
        choices=("both", "json", "markdown", "csv"),
        default=None,
        help="stdout format (default: both = JSON then Markdown; --json/--markdown shorthands exist)",
    )
    parser.add_argument("--json", action="store_true", help="print JSON only (overrides --format both)")
    parser.add_argument("--markdown", action="store_true", help="print Markdown only")
    parser.add_argument("--csv", action="store_true", help="print CSV to stdout")
    parser.add_argument("--label", default=None, help="override label when exactly one run is parsed")
    parser.add_argument("--out-json", type=Path, default=None, help="write the JSON document to this path")
    parser.add_argument("--out-markdown", type=Path, default=None, help="write the Markdown report to this path")
    parser.add_argument("--out-csv", type=Path, default=None, help="write the run x phase CSV to this path")
    parser.add_argument(
        "--median-limit-ms",
        type=float,
        default=5500.0,
        help="P0 acceptance limit for pooled drain median (default: 5500)",
    )
    parser.add_argument(
        "--abort-tolerance",
        type=float,
        default=1.0,
        help="allowed SAFE_ABORT events/run increase vs baseline (default: 1.0)",
    )
    parser.add_argument(
        "--landing-tolerance",
        type=float,
        default=1.0,
        help="allowed first-landing attempt increase vs baseline (default: 1.0)",
    )
    parser.add_argument("--quiet", action="store_true", help="only print requested stdout output; do not print warnings separately")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    # Emit UTF-8 even on Windows consoles/pipes; report files are UTF-8 as well.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass
    args = parse_args(argv)
    parser = LogParser([Path(p) for p in args.paths], label=args.label)
    runs_data = parser.parse()
    if not runs_data:
        print("error: no parseable run logs found", file=sys.stderr)
        for warning in parser.global_warnings:
            print(f"  warning: {warning}", file=sys.stderr)
        return 2

    runs = [LogParser.run_summary(run) for run in runs_data]
    summary = mode_summary(runs)
    comparison = build_comparison(
        runs,
        abort_tolerance=args.abort_tolerance,
        landing_tolerance=args.landing_tolerance,
        median_limit_ms=args.median_limit_ms,
    )

    warnings: list[str] = list(parser.global_warnings)
    for run in runs:
        for warning in run["warnings"]:
            warnings.append(f"{run['label']}: {warning}")

    json_doc = build_json(runs, summary, comparison, parser.inputs, warnings)
    markdown = build_markdown(runs, summary, comparison, parser.inputs, warnings)
    csv_rows = build_csv_rows(runs)

    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(
            json.dumps(json_doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    if args.out_markdown:
        args.out_markdown.parent.mkdir(parents=True, exist_ok=True)
        args.out_markdown.write_text(markdown + "\n", encoding="utf-8")
    if args.out_csv:
        args.out_csv.parent.mkdir(parents=True, exist_ok=True)
        write_csv(args.out_csv, csv_rows)

    fmt = args.format
    if args.json and args.markdown:
        fmt = "both"
    elif args.json:
        fmt = "json"
    elif args.markdown:
        fmt = "markdown"
    elif args.csv:
        fmt = "csv"
    elif fmt is None:
        fmt = "both"

    if fmt in ("json", "both"):
        print(json.dumps(json_doc, ensure_ascii=False, indent=2))
    if fmt == "both":
        print("\n# ---- MARKDOWN ----\n")
    if fmt in ("markdown", "both"):
        print(markdown)
    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(CSV_COLUMNS)
        writer.writerows(csv_rows)
        print(buffer.getvalue().rstrip("\r\n"))

    if fmt == "both" and warnings and not args.quiet:
        print("\n# warnings:", file=sys.stderr)
        for warning in warnings:
            print(f"#   - {warning}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
