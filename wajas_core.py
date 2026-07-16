"""
wajas_core.py — منظومة وَجَسْ (Wajas) On-Device Risk Engine
================================================================
This is the functional core of the Wajas SDK: the part that would ship
inside a banking app as a lightweight, on-device library. Everything in
this module runs locally and returns only a numeric risk score plus a
coarse breakdown — never raw signal data — to whatever host app embeds it.

WHAT IS REAL VS. SIMULATED IN THIS PROTOTYPE
------------------------------------------------------------------
- Remote-desktop detection  -> REAL. Uses `psutil` to enumerate actual
  running OS processes and match them against a signature list of known
  remote-access tools (AnyDesk, TeamViewer, VNC variants, etc.).
- Active-call detection     -> SIMULATED (documented). A desktop Python
  process has no access to a phone's cellular/VoIP call state — that
  requires a native OS hook (CallKit on iOS, TelephonyManager on
  Android). CallDetector exposes a manual/injectable signal here and the
  class docstring specifies exactly which native API a production build
  would call instead.
- Keystroke-dynamics stress -> REAL ANALYZER over SIMULATED input. The
  scoring algorithm (KeystrokeAnalyzer.analyze) is genuine statistics —
  mean inter-key latency, jitter, long-pause count — run against a real
  Python list of floats. In this desktop prototype those timestamps are
  synthesized (KeystrokeAnalyzer.simulate_events) because capturing true
  per-keystroke timing needs a native text-field hook (UITextField /
  EditText), not something a browser-rendered Streamlit widget can give
  us. Swap simulate_events() for a native capture bridge in production
  and the analyzer itself does not change.

SECURITY / PRIVACY DESIGN NOTES
------------------------------------------------------------------
- Data minimization: WajasSDK.assess_transaction() returns an
  AssessmentResult containing a score, a decision, and a *coarse* signal
  breakdown (booleans + one float) — never a call recording, a screen
  capture, or the full process list. That is what should ever be
  transmitted off-device, consistent with SAMA's Cyber Security
  Framework and PDPL data-minimization principles.
- Detection is inherently best-effort: matching on process *name* is
  fast and works for the mainstream remote-access tools used in scams,
  but a determined attacker can rename a binary to evade it. Production
  hardening would add code-signature / publisher verification, loaded
  driver inspection, and window-class heuristics — noted inline below.
- No persistence: this module keeps its audit trail in memory only
  (WajasSDK._log) for the lifetime of the process, mirroring an SDK that
  should not silently write user telemetry to disk.

Run standalone as a smoke test:  python wajas_core.py
"""

from __future__ import annotations

import platform
import random
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional

import psutil

# ---------------------------------------------------------------------------
# SIGNATURE DATABASE — known remote-access / screen-sharing tools.
# In production this list would be a versioned, remotely-updatable feed
# (new scam tooling appears constantly) rather than a hardcoded constant.
# Matching is done on the lower-cased process name with the platform
# executable suffix stripped, so one list covers Windows/macOS/Linux.
# ---------------------------------------------------------------------------
REMOTE_ACCESS_SIGNATURES: List[str] = [
    "anydesk",
    "teamviewer",
    "teamviewer_service",
    "tv_w32", "tv_x64",
    "vncserver", "vncviewer", "winvnc", "tvnserver", "realvnc",
    "chrome_remote_desktop", "remoting_host",
    "ammyy",
    "supremo",
    "logmein", "logmeinrescue",
    "gotomypc", "gotoassist",
    "splashtop", "srserver", "srfeature",
    "remotepc",
    "screenconnect", "connectwisecontrol",
    "dwservice", "dwrcs",
    "ultraviewer",
    "aeroadmin",
    "radmin", "rserver3",
    "showmypc",
    "zohoassist",
    "ninjaremote", "ninjarmm",
]


class Decision(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    HOLD = "HOLD"
    FREEZE = "FREEZE"


class RiskTier(str, Enum):
    SAFE = "SAFE"
    LEVEL_1 = "LEVEL_1"
    LEVEL_2 = "LEVEL_2"
    LEVEL_3 = "LEVEL_3"


@dataclass
class ScanResult:
    """Output of a single real process-table scan."""
    active: bool
    matched_processes: List[str]
    processes_scanned: int
    duration_ms: float


@dataclass
class AssessmentResult:
    """The ONLY object that should ever leave the device in production —
    deliberately free of raw PII, call audio, or a full process dump."""
    timestamp: str
    score: float
    tier: RiskTier
    decision: Decision
    breakdown: dict
    call_active: bool
    remote_desktop_active: bool
    matched_processes: List[str]
    keystroke_stress: float
    scan_duration_ms: float
    amount: float = 0.0


# ---------------------------------------------------------------------------
# SIGNAL 1 — Remote-Access Detector (REAL)
# ---------------------------------------------------------------------------
class RemoteDesktopDetector:
    """Scans the live OS process table for known remote-access tools.

    This is genuine, functional detection: on a machine that actually has
    AnyDesk or TeamViewer running, `scan()` will find it. Nothing here is
    faked or hardcoded to a particular answer.
    """

    def __init__(self, signatures: Optional[List[str]] = None):
        self.signatures = signatures or REMOTE_ACCESS_SIGNATURES

    @staticmethod
    def _normalize(name: str) -> str:
        name = name.lower().strip()
        for suffix in (".exe", ".app"):
            if name.endswith(suffix):
                name = name[: -len(suffix)]
        return name

    def scan(self) -> ScanResult:
        start = time.perf_counter()
        matched: List[str] = []
        scanned = 0

        # psutil.process_iter streams live OS process objects; we only
        # request the 'name' field to keep the scan cheap (no per-process
        # memory/CPU stat collection), which matters for an SDK that must
        # be lightweight and battery-friendly if ported to mobile.
        for proc in psutil.process_iter(["name"]):
            scanned += 1
            try:
                raw_name = proc.info.get("name") or ""
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Processes can exit mid-iteration, or be owned by another
                # user/OS account — both are expected and non-fatal.
                continue

            normalized = self._normalize(raw_name)
            if not normalized:
                continue

            for sig in self.signatures:
                if sig in normalized:
                    matched.append(raw_name)
                    break

        duration_ms = (time.perf_counter() - start) * 1000
        return ScanResult(
            active=len(matched) > 0,
            matched_processes=sorted(set(matched)),
            processes_scanned=scanned,
            duration_ms=round(duration_ms, 2),
        )

        # PRODUCTION HARDENING NOTE: name-matching is trivially evaded by
        # renaming the executable. A hardened version would additionally
        # check the Authenticode/codesign publisher certificate, inspect
        # loaded remote-input drivers (e.g. mirror display drivers used by
        # VNC/AnyDesk), and correlate with outbound connections to known
        # remote-access relay infrastructure.


# ---------------------------------------------------------------------------
# SIGNAL 2 — Active-Call Detector (SIMULATED — see module docstring)
# ---------------------------------------------------------------------------
class CallDetector:
    """Placeholder for native call-state detection.

    Real implementation path per platform:
      - iOS:     CXCallObserver (CallKit) — observe `CXCall.hasConnected`
                 / `.hasEnded` via a Swift/Obj-C bridge exposed to the
                 SDK's cross-platform layer.
      - Android: TelephonyManager.listen(PhoneStateListener,
                 LISTEN_CALL_STATE) — react to CALL_STATE_OFFHOOK.

    Neither API is reachable from a desktop Python process, so this class
    simply stores a manually-injected boolean for the prototype/dashboard
    to drive. The public method signature (`get_state`) is what the rest
    of the engine depends on, so swapping in a real native bridge later
    requires no changes to WajasSDK.
    """

    def __init__(self, initial_state: bool = False):
        self._state = initial_state

    def set_state(self, active: bool) -> None:
        self._state = bool(active)

    def get_state(self) -> bool:
        return self._state


# ---------------------------------------------------------------------------
# SIGNAL 3 — Keystroke Dynamics Analyzer (REAL algorithm, simulated feed)
# ---------------------------------------------------------------------------
class KeystrokeAnalyzer:
    """Turns a list of inter-keystroke intervals (milliseconds) into a
    0-100 behavioral-stress score.

    The scoring logic itself is real and deterministic — three genuine
    statistical features, each clamped and weighted:
      1. mean latency vs. a natural-typing baseline (dictation-reading
         victims type slower than someone typing from memory)
      2. jitter / stdev (irregular pacing — hesitation, distraction)
      3. count of "long pauses" > 800ms (classic sign of listening to a
         scammer dictate digits before typing each one)
    """

    BASELINE_MS = 140.0        # average relaxed human inter-key interval
    LONG_PAUSE_MS = 800.0

    @classmethod
    def analyze(cls, intervals_ms: List[float]) -> tuple[float, dict]:
        if not intervals_ms or len(intervals_ms) < 2:
            return 0.0, {}

        mean_latency = statistics.mean(intervals_ms)
        jitter = statistics.pstdev(intervals_ms)
        long_pauses = sum(1 for iv in intervals_ms if iv > cls.LONG_PAUSE_MS)

        latency_component = max(0.0, min(50.0, (mean_latency - cls.BASELINE_MS) / 10))
        jitter_component = max(0.0, min(30.0, jitter / 15))
        pause_component = min(20.0, long_pauses * 7)

        score = round(max(0.0, min(100.0, latency_component + jitter_component + pause_component)), 1)
        breakdown = {
            "mean_latency_ms": round(mean_latency, 1),
            "jitter_ms": round(jitter, 1),
            "long_pauses": long_pauses,
        }
        return score, breakdown

    @staticmethod
    def simulate_events(stress_level: int, num_keys: int = 14) -> List[float]:
        """TEST-DATA GENERATOR ONLY. Produces a synthetic inter-key
        interval list whose statistical profile matches a requested
        0-100 stress level, so the real `analyze()` above has something
        to chew on in this desktop demo. A production build replaces
        this with genuine keyDown/keyUp deltas captured by the host
        app's native text field."""
        stress_level = max(0, min(100, stress_level))
        base = 90 + stress_level * 2.2          # calmer typists -> ~90ms, stressed -> ~310ms
        spread = 10 + stress_level * 1.8         # more jitter under stress
        pause_chance = stress_level / 400.0      # occasional long "reading the number" pause

        events = []
        for _ in range(num_keys):
            if random.random() < pause_chance:
                events.append(random.uniform(900, 2200))
            else:
                events.append(max(30.0, random.gauss(base, spread)))
        return events


# ---------------------------------------------------------------------------
# THE ENGINE — combines all three signals into one risk decision.
# ---------------------------------------------------------------------------
class WajasSDK:
    """Public entry point. This is the class a host banking app would
    instantiate once at startup and call on every sensitive transaction."""

    # Rule-based weights. Illustrative fraud-analytics assumptions, not a
    # calibrated model — a production engine would fit these (or replace
    # the whole rule-set with a small on-device classifier) against
    # labelled incident data.
    W_CALL = 35.0
    W_REMOTE = 40.0
    W_KEYSTROKE = 0.20          # multiplies the 0-100 keystroke score
    W_COMBO = 15.0              # call + remote simultaneously
    W_HIGH_VALUE = 5.0
    HIGH_VALUE_THRESHOLD = 20_000.0

    def __init__(self):
        self.remote_detector = RemoteDesktopDetector()
        self.call_detector = CallDetector()
        self._log: List[str] = []
        self._append_log(f"Wajas engine initialized on {platform.system()} {platform.release()}.")

    # -- internal audit trail (kept in memory only — see module docstring)
    def _append_log(self, message: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._log.append(f"[{ts}] {message}")
        self._log = self._log[-60:]

    def get_log(self, limit: int = 20) -> List[str]:
        return self._log[-limit:]

    def _tier_for(self, score: float):
        if score < 40.0:
            return RiskTier.SAFE, Decision.ALLOW
        if score <= 70.0:
            return RiskTier.LEVEL_1, Decision.WARN
        if score <= 85.0:
            return RiskTier.LEVEL_2, Decision.HOLD
        return RiskTier.LEVEL_3, Decision.FREEZE

    def assess_transaction(
        self,
        call_active: bool = False,
        remote_desktop: Optional[bool] = None,
        keystroke_events: Optional[List[float]] = None,
        amount: float = 0.0,
    ) -> AssessmentResult:
        """Run one full risk assessment. `remote_desktop=None` triggers a
        REAL live process scan; pass True/False explicitly only to force
        a value (e.g. for unit tests)."""
        breakdown: dict = {}

        if remote_desktop is None:
            scan = self.remote_detector.scan()
            self._append_log(
                f"Process scan complete: {scan.processes_scanned} processes checked in "
                f"{scan.duration_ms}ms — {len(scan.matched_processes)} match(es)."
            )
            if scan.matched_processes:
                self._append_log(f"MATCHED remote-access signature(s): {', '.join(scan.matched_processes)}")
            remote_active = scan.active
            matched_processes = scan.matched_processes
            scan_duration_ms = scan.duration_ms
        else:
            remote_active = remote_desktop
            matched_processes = []
            scan_duration_ms = 0.0

        if call_active:
            breakdown["Active call during transaction"] = self.W_CALL
        if remote_active:
            breakdown["Remote-access software detected"] = self.W_REMOTE

        keystroke_score = 0.0
        if keystroke_events:
            keystroke_score, ks_breakdown = KeystrokeAnalyzer.analyze(keystroke_events)
            weighted = round(keystroke_score * self.W_KEYSTROKE, 1)
            if weighted > 0:
                breakdown["Keystroke-dynamics anomaly"] = weighted
            self._append_log(f"Keystroke analyzer: stress={keystroke_score}/100 ({ks_breakdown})")

        if call_active and remote_active:
            breakdown["Combined social-engineering signature (call + remote access)"] = self.W_COMBO

        if amount >= self.HIGH_VALUE_THRESHOLD:
            breakdown["High-value transaction amplifier"] = self.W_HIGH_VALUE

        score = round(min(100.0, sum(breakdown.values())), 1)
        tier, decision = self._tier_for(score)

        self._append_log(f"Risk score {score}/100 -> tier {tier.value} -> decision {decision.value}.")

        return AssessmentResult(
            timestamp=datetime.now().isoformat(timespec="seconds"),
            score=score,
            tier=tier,
            decision=decision,
            breakdown=breakdown,
            call_active=call_active,
            remote_desktop_active=remote_active,
            matched_processes=matched_processes,
            keystroke_stress=keystroke_score,
            scan_duration_ms=scan_duration_ms,
            amount=amount,
        )


# ---------------------------------------------------------------------------
# ONE-LINE INTEGRATION API
# A host app does not need to know about classes/signals at all:
#
#     from wajas_core import assess
#     result = assess(call_active=True, amount=15000)
#     if result.decision == "FREEZE":
#         block_transaction()
#
# ---------------------------------------------------------------------------
_default_sdk = WajasSDK()


def assess(**kwargs) -> AssessmentResult:
    """Module-level convenience wrapper around a shared WajasSDK singleton."""
    return _default_sdk.assess_transaction(**kwargs)


def get_engine() -> WajasSDK:
    """Access the shared singleton directly (e.g. to read its audit log)."""
    return _default_sdk


# ---------------------------------------------------------------------------
# STANDALONE SMOKE TEST — `python wajas_core.py`
# Proves the module works with zero UI: runs a real remote-desktop scan
# on whatever machine executes it.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("Wajas Core — standalone self-test\n" + "-" * 40)

    sdk = WajasSDK()

    print("\n[1] Safe baseline (no signals):")
    r = sdk.assess_transaction(amount=2000)
    print(f"    score={r.score} tier={r.tier.value} decision={r.decision.value}")

    print("\n[2] Real remote-desktop scan + simulated stressed typing + active call:")
    fake_events = KeystrokeAnalyzer.simulate_events(stress_level=85)
    r = sdk.assess_transaction(call_active=True, keystroke_events=fake_events, amount=25000)
    print(f"    score={r.score} tier={r.tier.value} decision={r.decision.value}")
    print(f"    remote_desktop_active={r.remote_desktop_active} matched={r.matched_processes}")
    print(f"    breakdown={r.breakdown}")

    print("\n[3] Engine audit log (last 10 lines):")
    for line in sdk.get_log(10):
        print("    " + line)
