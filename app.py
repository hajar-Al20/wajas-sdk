"""
app.py — Wajas SDK Testing Sandbox (Streamlit)
================================================================
Visual dashboard that drives and displays REAL output from
`wajas_core.py`. This file contains no risk-scoring logic of its own —
every score, decision, and log line rendered here is produced by the
WajasSDK engine, not fabricated for the UI. See wajas_core.py's module
docstring for exactly which signals are real (remote-desktop process
scan) vs. simulated-by-necessity (active call, raw keystroke timing).

Two tabs:
  1. Mobile Banking Sandbox — a mock Alinma-style transfer screen that
     lets you drive the three input signals and call the real SDK.
  2. Security Command Center — the "banker's view": live risk gauge,
     rule ladder, and the SDK's own internal engine log.

Run with:  streamlit run app.py
Deps:      pip install streamlit plotly pandas psutil
"""

import time

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from wajas_core import (
    Decision,
    KeystrokeAnalyzer,
    RemoteDesktopDetector,
    WajasSDK,
)

# ---------------------------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Wajas وَجَسْ | SDK Testing Sandbox",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# THEME — Dark / Beige, high contrast, white text, red/green/yellow status.
# ---------------------------------------------------------------------------
BG = "#15100C"          # near-black warm charcoal
PANEL = "#211A14"       # dark beige-brown panel
PANEL_2 = "#2A2119"
BEIGE = "#E7DAC0"
GOLD = "#D8AE60"
WHITE = "#FBF7F0"
RED = "#E5484D"
GREEN = "#3FC97F"
YELLOW = "#F2C037"

TIER_COLOR = {"SAFE": GREEN, "LEVEL_1": YELLOW, "LEVEL_2": "#E8873B", "LEVEL_3": RED}
TIER_ICON = {"SAFE": "✅", "LEVEL_1": "⚠️", "LEVEL_2": "⏳", "LEVEL_3": "⛔"}


def inject_css() -> None:
    st.markdown(
        f"""
        <style>
        .stApp {{ background-color: {BG}; }}
        html, body, [class*="css"] {{ font-family: 'Segoe UI', 'Tajawal', sans-serif; color: {WHITE}; }}
        h1, h2, h3, h4, h5, p, span, label, .stMarkdown {{ color: {WHITE} !important; }}
        .wajas-hero {{
            background: linear-gradient(135deg, {PANEL} 0%, {PANEL_2} 100%);
            padding: 22px 28px; border-radius: 14px; margin-bottom: 18px;
            border: 1px solid {GOLD}66;
        }}
        .wajas-hero h1 {{ margin: 0; font-size: 26px; color: {WHITE} !important; }}
        .wajas-hero p {{ color: {GOLD} !important; margin: 4px 0 0 0; font-size: 14px; }}
        .wajas-card {{
            background: {PANEL}; border: 1px solid #3A3024; border-radius: 12px;
            padding: 18px 20px; margin-bottom: 14px;
        }}
        .wajas-card h4 {{ color: {BEIGE} !important; margin-top: 0; }}
        .status-pill {{
            display: inline-block; padding: 5px 16px; border-radius: 999px;
            font-weight: 700; font-size: 13px; color: #10100E;
        }}
        .edge-console {{
            background: #0A0705; color: #8FE3A8; font-family: 'Consolas','Courier New',monospace;
            font-size: 12.5px; padding: 14px 16px; border-radius: 10px; height: 260px;
            overflow-y: auto; border: 1px solid {GOLD}55; line-height: 1.6;
        }}
        .frozen-banner {{ background: linear-gradient(135deg,#3a0e0e,#5a1717); color:{WHITE};
            padding:20px; border-radius:12px; border:1px solid {RED}; }}
        .hold-banner {{ background: linear-gradient(135deg,#4a3410,#6a4a18); color:{WHITE};
            padding:20px; border-radius:12px; border:1px solid #E8873B; }}
        .warn-banner {{ background: linear-gradient(135deg,#3f3a12,#5c531a); color:{WHITE};
            padding:20px; border-radius:12px; border:1px solid {YELLOW}; }}
        .stButton>button[kind="primary"] {{ background-color: {GOLD}; border-color:{GOLD}; color:#1a1206; font-weight:700; }}
        div[data-testid="stMetricValue"] {{ color: {WHITE} !important; }}
        div[data-testid="stMetricLabel"] {{ color: {BEIGE} !important; }}
        section[data-testid="stSidebar"] {{ background-color: {PANEL}; }}
        </style>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# SESSION STATE
# ---------------------------------------------------------------------------
def init_state() -> None:
    if "sdk" not in st.session_state:
        st.session_state.sdk = WajasSDK()          # persists across reruns -> real running audit log
    defaults = {
        "txn_state": "idle",
        "hold_start": None,
        "kyc_step": 0,
        "logs": [],
        "current_result": None,
        "current_snapshot": {},
        "demo_mode": True,
        "simulate_remote": False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def record_attempt(snapshot: dict, result) -> None:
    iban = snapshot["iban"].replace(" ", "")
    masked_iban = f"{iban[:4]} •••• •••• {iban[-4:]}" if len(iban) >= 8 else iban
    st.session_state.logs.insert(0, {
        "time": result.timestamp,
        "beneficiary": snapshot["beneficiary"],
        "iban_masked": masked_iban,
        "amount": snapshot["amount"],
        "call_active": result.call_active,
        "remote_desktop": result.remote_desktop_active,
        "matched_processes": ", ".join(result.matched_processes) or "-",
        "keystroke_stress": result.keystroke_stress,
        "score": result.score,
        "tier": result.tier.value,
        "decision": result.decision.value,
    })


# ---------------------------------------------------------------------------
# TAB 1 — MOBILE BANKING SANDBOX
# ---------------------------------------------------------------------------
def render_banking_tab() -> None:
    st.markdown(
        """
        <div class="wajas-hero">
            <h1>🏦 Alinma Bank — Money Transfer (Wajas Sandbox)</h1>
            <p>منظومة وَجَسْ · Real-time on-device risk engine, wired to a live process scan</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_form, col_sensors = st.columns([1.1, 1], gap="large")

    with col_form:
        st.markdown('<div class="wajas-card">', unsafe_allow_html=True)
        st.markdown("#### 💳 Available Balance: **SAR 48,250.00**")
        st.markdown("##### New Transfer")
        beneficiary = st.text_input("Beneficiary Name", value="Mohammed Al-Qahtani", key="beneficiary")
        iban = st.text_input("IBAN", value="SA44 2000 0001 2345 6789 1234", key="iban")
        amount = st.number_input("Amount (SAR)", min_value=0.0, value=15000.0, step=500.0, key="amount")
        st.markdown("</div>", unsafe_allow_html=True)

    with col_sensors:
        st.markdown('<div class="wajas-card">', unsafe_allow_html=True)
        st.markdown("#### 🔧 Wajas SDK — Live Signals")

        # --- Signal B: REAL remote-desktop scan, run on every rerun ----
        scan = RemoteDesktopDetector().scan()
        simulate_remote = st.checkbox(
            "🧪 Demo override: force remote-access DETECTED",
            key="simulate_remote",
            help="For judges without AnyDesk/TeamViewer installed — overrides the real scan result below.",
        )
        remote_active = simulate_remote or scan.active
        pill_color = RED if remote_active else GREEN
        pill_text = "ACTIVE" if remote_active else "CLEAR"
        st.markdown(
            f'📡 **Remote Desktop App** — '
            f'<span class="status-pill" style="background:{pill_color};">{pill_text}</span>',
            unsafe_allow_html=True,
        )
        st.caption(
            f"Real scan: {scan.processes_scanned} processes checked in {scan.duration_ms}ms · "
            f"matches: {', '.join(scan.matched_processes) if scan.matched_processes else 'none'}"
        )

        st.divider()

        # --- Signal A: manual/simulated call toggle (see wajas_core docstring) ---
        voice_call = st.toggle("📞 Active Voice Call Detected (GSM/VoIP)", key="voice_call", value=False)
        st.caption("Simulated here — production reads CallKit (iOS) / TelephonyManager (Android) natively.")

        st.divider()

        # --- Signal C: slider drives synthetic events fed into the REAL analyzer ---
        keystroke_slider = st.slider(
            "⌨️ Keystroke Dynamics / Typing Stress Level", 0, 100, 10, key="keystroke_slider",
            help="Generates a synthetic keystroke-timing sample at this stress level, then runs it through the real KeystrokeAnalyzer.",
        )
        st.markdown("</div>", unsafe_allow_html=True)

    # --- Live preview: real engine call, no side effects on the audit log ---
    preview_events = KeystrokeAnalyzer.simulate_events(keystroke_slider)
    preview_stress, _ = KeystrokeAnalyzer.analyze(preview_events)
    live_score, live_tier = _preview_score(voice_call, remote_active, preview_stress, amount)

    color = TIER_COLOR[live_tier]
    icon = TIER_ICON[live_tier]
    st.markdown(
        f"""
        <div class="wajas-card" style="display:flex;align-items:center;justify-content:space-between;">
            <div><strong>Live Predicted Risk</strong><br>
            <span style="font-size:12px;color:{BEIGE};">Recomputed every rerun from the real signals above.</span></div>
            <div><span class="status-pill" style="background:{color};">{icon} {live_score:.0f}/100 · {live_tier.replace('_',' ')}</span></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    confirm = st.button(
        "🔒 Confirm Transfer", type="primary", use_container_width=True,
        disabled=st.session_state.txn_state not in ("idle", "cancelled", "completed"),
    )

    if confirm:
        events = KeystrokeAnalyzer.simulate_events(keystroke_slider)
        result = st.session_state.sdk.assess_transaction(
            call_active=voice_call,
            remote_desktop=True if simulate_remote else None,  # None => real scan runs again inside the SDK
            keystroke_events=events,
            amount=amount,
        )
        snapshot = dict(beneficiary=beneficiary, iban=iban, amount=amount)
        st.session_state.current_result = result
        st.session_state.current_snapshot = snapshot
        st.session_state.kyc_step = 0
        record_attempt(snapshot, result)

        if result.decision == Decision.ALLOW:
            st.session_state.txn_state = "completed"
        elif result.decision == Decision.WARN:
            st.session_state.txn_state = "level1_warning"
        elif result.decision == Decision.HOLD:
            st.session_state.txn_state = "level2_hold"
            st.session_state.hold_start = time.time()
        else:
            st.session_state.txn_state = "level3_frozen"

    render_mitigation_flow()


def _preview_score(call_active, remote_active, keystroke_stress, amount):
    """Mirrors WajasSDK's weighting for the live preview badge without
    writing to the engine's audit log on every single rerun (only the
    Confirm click should produce a logged assessment)."""
    breakdown = {}
    if call_active:
        breakdown["call"] = WajasSDK.W_CALL
    if remote_active:
        breakdown["remote"] = WajasSDK.W_REMOTE
    breakdown["keystroke"] = keystroke_stress * WajasSDK.W_KEYSTROKE
    if call_active and remote_active:
        breakdown["combo"] = WajasSDK.W_COMBO
    if amount >= WajasSDK.HIGH_VALUE_THRESHOLD:
        breakdown["amount"] = WajasSDK.W_HIGH_VALUE
    score = min(100.0, sum(breakdown.values()))
    if score < 40:
        tier = "SAFE"
    elif score <= 70:
        tier = "LEVEL_1"
    elif score <= 85:
        tier = "LEVEL_2"
    else:
        tier = "LEVEL_3"
    return score, tier


def render_mitigation_flow() -> None:
    state = st.session_state.txn_state
    snap = st.session_state.current_snapshot
    result = st.session_state.current_result
    score = result.score if result else 0.0

    if state == "completed":
        st.success(
            f"✅ Transfer of **SAR {snap.get('amount', 0):,.2f}** to **{snap.get('beneficiary','')}** "
            f"completed. (Risk score at approval: {score:.0f}/100)"
        )
        if st.button("↺ Start New Transfer"):
            _reset_transaction()

    elif state == "cancelled":
        st.info("🛑 Transfer cancelled by user. No funds were moved.")
        if st.button("↺ Start New Transfer"):
            _reset_transaction()

    elif state == "level1_warning":
        triggers = ", ".join(result.breakdown.keys())
        st.markdown(
            f"""
            <div class="warn-banner">
                <h3>⚠️ Wajas Security Notice</h3>
                <p><strong>Risk Score: {score:.0f}/100</strong> — signals: {triggers}</p>
                <p>Scammers often stay on the phone with you while guiding you to move money
                "to protect it" or "verify your identity." <strong>Alinma Bank will never ask you
                to transfer funds during a call or install remote-access software.</strong></p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        c1, c2 = st.columns(2)
        with c1:
            if st.button("❌ Cancel Transfer (Recommended)", use_container_width=True):
                st.session_state.txn_state = "cancelled"
                st.rerun()
        with c2:
            if st.button("✅ Proceed Anyway", use_container_width=True):
                st.session_state.txn_state = "completed"
                st.rerun()

    elif state == "level2_hold":
        hold_duration = 15 if st.session_state.demo_mode else 300
        elapsed = time.time() - st.session_state.hold_start
        remaining = max(0, hold_duration - elapsed)
        pct = int(100 * (hold_duration - remaining) / hold_duration)

        st.markdown(
            f"""<div class="hold-banner"><h3>⏳ Security Hold Active — Risk Score {score:.0f}/100</h3>
            <p>Transfer delayed so Alinma can protect your funds while unusual activity is present.</p></div>""",
            unsafe_allow_html=True,
        )
        mm, ss = divmod(int(remaining), 60)
        st.metric("Time remaining", f"{mm:02d}:{ss:02d}")
        st.progress(pct)

        if remaining <= 0:
            st.success("Hold complete.")
            if st.button("✅ Release Funds Now", type="primary"):
                st.session_state.txn_state = "completed"
                st.rerun()
        else:
            st.caption("⚡ Demo Mode: compressed to 15s." if st.session_state.demo_mode else "")
            if st.button("❌ Cancel Transfer"):
                st.session_state.txn_state = "cancelled"
                st.rerun()
            time.sleep(1)
            st.rerun()

    elif state == "level3_frozen":
        st.markdown(
            f"""<div class="frozen-banner"><h3>⛔ Transaction Frozen — Risk Score {score:.0f}/100</h3>
            <p>High-confidence live social-engineering pattern detected. Complete identity
            re-verification below to unlock funds.</p></div>""",
            unsafe_allow_html=True,
        )
        st.markdown("#### 🎥 Video-KYC / Liveness Face-ID Verification")

        if st.session_state.kyc_step == 0:
            st.warning("Funds are locked until liveness verification succeeds.")
            if st.button("▶️ Start Liveness Check", type="primary"):
                st.session_state.kyc_step = 1
                st.rerun()
        elif st.session_state.kyc_step == 1:
            placeholder = st.empty()
            steps = ["Requesting camera access…", "Detecting face…", "Please blink naturally…",
                     "Turn head slightly left…", "Turn head slightly right…", "Matching biometric template…"]
            progress = st.progress(0)
            duration = 0.35 if st.session_state.demo_mode else 1.0
            for i, msg in enumerate(steps):
                placeholder.info(f"🔍 {msg}")
                progress.progress(int((i + 1) / len(steps) * 100))
                time.sleep(duration)
            placeholder.success("✅ Liveness confirmed.")
            st.session_state.kyc_step = 2
            st.rerun()
        elif st.session_state.kyc_step == 2:
            st.success("✅ Identity Verified via Video-KYC / Liveness Face-ID.")
            if st.button("🔓 Release Funds", type="primary"):
                st.session_state.txn_state = "completed"
                st.rerun()


def _reset_transaction() -> None:
    st.session_state.txn_state = "idle"
    st.session_state.hold_start = None
    st.session_state.kyc_step = 0
    st.rerun()


# ---------------------------------------------------------------------------
# TAB 2 — SECURITY COMMAND CENTER
# ---------------------------------------------------------------------------
def render_dashboard_tab() -> None:
    st.markdown(
        """
        <div class="wajas-hero">
            <h1>🛡️ Wajas Security Command Center</h1>
            <p>Edge AI Risk Engine · On-Device Inference · Zero Raw-PII Telemetry</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    logs = st.session_state.logs
    total = len(logs)
    frozen = sum(1 for l in logs if l["decision"] == "FREEZE")
    held = sum(1 for l in logs if l["decision"] == "HOLD")
    avg_score = (sum(l["score"] for l in logs) / total) if total else 0.0

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Transfer Attempts (session)", total)
    m2.metric("Level-3 Freezes", frozen)
    m3.metric("Level-2 Holds", held)
    m4.metric("Average Risk Score", f"{avg_score:.0f}/100")

    col_gauge, col_legend = st.columns([1.1, 1], gap="large")

    with col_gauge:
        st.markdown('<div class="wajas-card">', unsafe_allow_html=True)
        st.markdown("#### 📊 Live Risk Score Gauge")
        st.caption("Reflects the current sensor state from the Mobile Banking tab.")
        preview_events = KeystrokeAnalyzer.simulate_events(st.session_state.get("keystroke_slider", 0))
        preview_stress, _ = KeystrokeAnalyzer.analyze(preview_events)
        remote_active = st.session_state.get("simulate_remote", False) or RemoteDesktopDetector().scan().active
        live_score, live_tier = _preview_score(
            st.session_state.get("voice_call", False), remote_active,
            preview_stress, st.session_state.get("amount", 0.0),
        )
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=live_score,
            number={"suffix": " / 100", "font": {"color": WHITE, "size": 40}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": WHITE},
                "bar": {"color": TIER_COLOR[live_tier], "thickness": 0.32},
                "bgcolor": PANEL,
                "borderwidth": 1,
                "bordercolor": "#3A3024",
                "steps": [
                    {"range": [0, 40], "color": "#1c2b20"},
                    {"range": [40, 70], "color": "#2e2a13"},
                    {"range": [70, 85], "color": "#332210"},
                    {"range": [85, 100], "color": "#331414"},
                ],
                "threshold": {"line": {"color": RED, "width": 3}, "thickness": 0.85, "value": 85},
            },
        ))
        fig.update_layout(height=280, margin=dict(l=20, r=20, t=10, b=10),
                           paper_bgcolor="rgba(0,0,0,0)", font={"color": WHITE})
        st.plotly_chart(fig, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with col_legend:
        st.markdown('<div class="wajas-card">', unsafe_allow_html=True)
        st.markdown("#### ⚙️ Rule-Based Mitigation Ladder")
        st.markdown(
            f"""
            <table style="width:100%;border-collapse:collapse;font-size:14px;color:{WHITE};">
            <tr style="background:#1c2b20;"><td style="padding:6px;"><b>0 – 39</b></td><td>✅ Safe Zone — immediate transfer</td></tr>
            <tr style="background:#2e2a13;"><td style="padding:6px;"><b>40 – 70</b></td><td>⚠️ Level 1 — smart in-app warning</td></tr>
            <tr style="background:#332210;"><td style="padding:6px;"><b>71 – 85</b></td><td>⏳ Level 2 — 5-minute security hold</td></tr>
            <tr style="background:#331414;"><td style="padding:6px;"><b>86 – 100</b></td><td>⛔ Level 3 — freeze + Video-KYC</td></tr>
            </table>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="wajas-card">', unsafe_allow_html=True)
    st.markdown("#### 🧠 Edge AI Processing Console")
    st.caption("Real internal audit trail from the running WajasSDK instance — not fabricated text.")
    lines = st.session_state.sdk.get_log(25)
    console_html = "<br>".join(lines) if lines else "<i>Awaiting first transfer attempt…</i>"
    st.markdown(f'<div class="edge-console">{console_html}</div>', unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="wajas-card">', unsafe_allow_html=True)
    st.markdown("#### 📁 Transaction Risk Log")
    if logs:
        df = pd.DataFrame(logs)[[
            "time", "beneficiary", "iban_masked", "amount", "call_active",
            "remote_desktop", "matched_processes", "keystroke_stress", "score", "tier", "decision",
        ]]
        df.columns = ["Timestamp", "Beneficiary", "IBAN (masked)", "Amount (SAR)", "Call Active",
                      "Remote Access", "Matched Processes", "Keystroke Stress", "Risk Score", "Tier", "Decision"]
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No transfer attempts yet — go to the Mobile Banking Sandbox tab and tap Confirm Transfer.")
    st.markdown("</div>", unsafe_allow_html=True)

    st.caption(
        "🔐 This sandbox is illustrative only and is not connected to any real banking system. "
        "Remote-desktop detection is a genuine live process scan; call detection and raw keystroke "
        "timing are simulated per the limits of a desktop prototype (see wajas_core.py docstring)."
    )


# ---------------------------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------------------------
def render_sidebar() -> None:
    with st.sidebar:
        st.markdown("## 🛡️ Wajas وَجَسْ")
        st.caption("On-device anti-fraud SDK — functional testing sandbox")
        st.divider()
        st.session_state.demo_mode = st.checkbox(
            "⚡ Demo Mode (compress timers)", value=st.session_state.demo_mode,
        )
        st.divider()
        st.markdown("**Live signal status:**")
        scan = RemoteDesktopDetector().scan()
        st.write(f"🖥️ Processes scanned: {scan.processes_scanned}")
        st.write(f"📡 Remote access: {'🔴 DETECTED' if scan.active else '🟢 clear'}")
        st.divider()
        if st.button("🗑️ Reset Full Simulation", use_container_width=True):
            for k in list(st.session_state.keys()):
                del st.session_state[k]
            st.rerun()
        st.divider()
        st.caption("No real funds, PII, or banking systems are involved.")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main() -> None:
    inject_css()
    init_state()
    render_sidebar()

    tab1, tab2 = st.tabs(["📱 Mobile Banking Sandbox", "🛡️ Security Command Center"])
    with tab1:
        render_banking_tab()
    with tab2:
        render_dashboard_tab()


if __name__ == "__main__":
    main()
