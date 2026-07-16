"""
app_ar.py — منظومة وَجَسْ · لوحة الاختبار التفاعلية (النسخة العربية)
================================================================
واجهة Streamlit عربية بالكامل (اتجاه RTL) تعرض مخرجات حقيقية من
wajas_core_ar.py — لا يوجد أي رقم أو سطر سجل مُصطنع لأغراض العرض؛ كل
درجة خطورة وكل سطر في «سجل التدقيق» صادر فعليًا عن محرك WajasSDKArabic.
راجع التوثيق في wajas_core.py لمعرفة أي الإشارات حقيقية وأيها محاكاة.

يعمل جنبًا إلى جنب مع app.py (النسخة الإنجليزية) دون أي تعارض — كل
ملف مستقل بذاكرة جلسة (session_state) خاصة به عند تشغيله بمنفذ مختلف.

تشغيل:  streamlit run app_ar.py
المتطلبات: pip install -r requirements.txt
"""

import time

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from wajas_core import Decision, KeystrokeAnalyzer, RemoteDesktopDetector, RiskTier, WajasSDK
from wajas_core_ar import DECISION_LABELS_AR, TIER_LABELS_AR, WajasSDKArabic

# ---------------------------------------------------------------------------
# إعداد الصفحة
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="وَجَسْ | لوحة اختبار المنظومة",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# الهوية البصرية — نفس نظام الألوان الداكن/البيج المستخدم في app.py
# ---------------------------------------------------------------------------
BG = "#15100C"
PANEL = "#211A14"
PANEL_2 = "#2A2119"
BEIGE = "#E7DAC0"
GOLD = "#D8AE60"
WHITE = "#FBF7F0"
RED = "#E5484D"
GREEN = "#3FC97F"
YELLOW = "#F2C037"

TIER_COLOR = {RiskTier.SAFE: GREEN, RiskTier.LEVEL_1: YELLOW, RiskTier.LEVEL_2: "#E8873B", RiskTier.LEVEL_3: RED}
TIER_ICON = {RiskTier.SAFE: "✅", RiskTier.LEVEL_1: "⚠️", RiskTier.LEVEL_2: "⏳", RiskTier.LEVEL_3: "⛔"}


def inject_css() -> None:
    st.markdown(
        f"""
        <style>
        /* اتجاه الصفحة بالكامل من اليمين لليسار */
        .stApp {{ background-color: {BG}; direction: rtl; }}
        html, body, [class*="css"] {{ font-family: 'Tajawal','Segoe UI',Arial,sans-serif; color: {WHITE}; }}
        h1, h2, h3, h4, h5, p, span, label, .stMarkdown {{ color: {WHITE} !important; }}

        /* الحقول الرقمية/اللاتينية (الآيبان، المبلغ) تبقى LTR لسهولة القراءة */
        input, textarea {{ direction: ltr; text-align: left; }}

        .wajas-hero {{
            background: linear-gradient(135deg, {PANEL} 0%, {PANEL_2} 100%);
            padding: 22px 28px; border-radius: 14px; margin-bottom: 18px;
            border: 1px solid {GOLD}66; text-align: right;
        }}
        .wajas-hero h1 {{ margin: 0; font-size: 26px; color: {WHITE} !important; }}
        .wajas-hero p {{ color: {GOLD} !important; margin: 4px 0 0 0; font-size: 14px; }}
        .wajas-card {{
            background: {PANEL}; border: 1px solid #3A3024; border-radius: 12px;
            padding: 18px 20px; margin-bottom: 14px; text-align: right;
        }}
        .wajas-card h4 {{ color: {BEIGE} !important; margin-top: 0; }}
        .status-pill {{
            display: inline-block; padding: 5px 16px; border-radius: 999px;
            font-weight: 700; font-size: 13px; color: #10100E;
        }}
        .edge-console {{
            background: #0A0705; color: #8FE3A8; font-family: 'Consolas','Courier New',monospace;
            font-size: 12.5px; padding: 14px 16px; border-radius: 10px; height: 260px;
            overflow-y: auto; border: 1px solid {GOLD}55; line-height: 1.6; direction: ltr; text-align: left;
        }}
        .frozen-banner {{ background: linear-gradient(135deg,#3a0e0e,#5a1717); color:{WHITE};
            padding:20px; border-radius:12px; border:1px solid {RED}; text-align: right; }}
        .hold-banner {{ background: linear-gradient(135deg,#4a3410,#6a4a18); color:{WHITE};
            padding:20px; border-radius:12px; border:1px solid #E8873B; text-align: right; }}
        .warn-banner {{ background: linear-gradient(135deg,#3f3a12,#5c531a); color:{WHITE};
            padding:20px; border-radius:12px; border:1px solid {YELLOW}; text-align: right; }}
        .stButton>button[kind="primary"] {{ background-color: {GOLD}; border-color:{GOLD}; color:#1a1206; font-weight:700; }}
        div[data-testid="stMetricValue"] {{ color: {WHITE} !important; }}
        div[data-testid="stMetricLabel"] {{ color: {BEIGE} !important; }}
        section[data-testid="stSidebar"] {{ background-color: {PANEL}; direction: rtl; text-align: right; }}
        table {{ direction: rtl; }}
        </style>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# حالة الجلسة
# ---------------------------------------------------------------------------
def init_state() -> None:
    if "sdk" not in st.session_state:
        st.session_state.sdk = WajasSDKArabic()
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
        "الوقت": result.timestamp,
        "المستفيد": snapshot["beneficiary"],
        "الآيبان (مموّه)": masked_iban,
        "المبلغ": snapshot["amount"],
        "مكالمة نشطة": result.call_active,
        "تحكم عن بعد": result.remote_desktop_active,
        "العمليات المطابقة": ", ".join(result.matched_processes) or "-",
        "توتر الكتابة": result.keystroke_stress,
        "درجة الخطورة": result.score,
        "المستوى": TIER_LABELS_AR[result.tier],
        "القرار": DECISION_LABELS_AR[result.decision],
    })


# ---------------------------------------------------------------------------
# التبويب الأول — تطبيق البنك (منظور المستخدم)
# ---------------------------------------------------------------------------
def render_banking_tab() -> None:
    st.markdown(
        """
        <div class="wajas-hero">
            <h1>🏦 بنك الإنماء — تحويل الأموال (بيئة اختبار وَجَسْ)</h1>
            <p>منظومة وَجَسْ · محرك مخاطر يعمل على الجهاز، متصل بفحص حقيقي للعمليات النشطة</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_form, col_sensors = st.columns([1.1, 1], gap="large")

    with col_form:
        st.markdown('<div class="wajas-card">', unsafe_allow_html=True)
        st.markdown("#### 💳 الرصيد المتاح: **48,250.00 ريال سعودي**")
        st.markdown("##### عملية تحويل جديدة")
        beneficiary = st.text_input("اسم المستفيد", value="محمد القحطاني", key="beneficiary")
        iban = st.text_input("رقم الآيبان (IBAN)", value="SA44 2000 0001 2345 6789 1234", key="iban")
        amount = st.number_input("المبلغ (ريال سعودي)", min_value=0.0, value=15000.0, step=500.0, key="amount")
        st.markdown("</div>", unsafe_allow_html=True)

    with col_sensors:
        st.markdown('<div class="wajas-card">', unsafe_allow_html=True)
        st.markdown("#### 🔧 إشارات وَجَسْ الحية")

        # --- الإشارة ب: فحص حقيقي لبرامج التحكم عن بعد، يعمل مع كل تحديث ---
        scan = RemoteDesktopDetector().scan()
        simulate_remote = st.checkbox(
            "🧪 محاكاة عرضية: فرض رصد برنامج تحكم عن بعد",
            key="simulate_remote",
            help="لأغراض عرض الحكام في حال عدم توفر AnyDesk/TeamViewer — تتجاوز نتيجة الفحص الحقيقي أدناه.",
        )
        remote_active = simulate_remote or scan.active
        pill_color = RED if remote_active else GREEN
        pill_text = "نشط" if remote_active else "غير موجود"
        st.markdown(
            f'📡 **برنامج تحكم عن بعد** — '
            f'<span class="status-pill" style="background:{pill_color};">{pill_text}</span>',
            unsafe_allow_html=True,
        )
        st.caption(
            f"فحص حقيقي: {scan.processes_scanned} عملية خلال {scan.duration_ms} مللي ثانية · "
            f"المطابقات: {', '.join(scan.matched_processes) if scan.matched_processes else 'لا يوجد'}"
        )

        st.divider()

        voice_call = st.toggle("📞 رصد مكالمة صوتية نشطة (GSM/VoIP)", key="voice_call", value=False)
        st.caption("محاكاة هنا — الإصدار الفعلي يقرأ CallKit (آيفون) / TelephonyManager (أندرويد) مباشرة من النظام.")

        st.divider()

        keystroke_slider = st.slider(
            "⌨️ مستوى توتر/تردد الكتابة", 0, 100, 10, key="keystroke_slider",
            help="يولّد عينة إيقاع كتابة اصطناعية بهذا المستوى، ثم يمررها إلى المحلل الحقيقي KeystrokeAnalyzer.",
        )
        st.markdown("</div>", unsafe_allow_html=True)

    # --- معاينة حية: استدعاء حسابي حقيقي دون تسجيله في سجل التدقيق ---
    preview_events = KeystrokeAnalyzer.simulate_events(keystroke_slider)
    preview_stress, _ = KeystrokeAnalyzer.analyze(preview_events)
    live_score, live_tier = _preview_score(voice_call, remote_active, preview_stress, amount)

    color = TIER_COLOR[live_tier]
    icon = TIER_ICON[live_tier]
    st.markdown(
        f"""
        <div class="wajas-card" style="display:flex;align-items:center;justify-content:space-between;">
            <div><strong>درجة الخطورة الحية المتوقعة</strong><br>
            <span style="font-size:12px;color:{BEIGE};">تُحسب من جديد مع كل تفاعل، بناءً على الإشارات أعلاه.</span></div>
            <div><span class="status-pill" style="background:{color};">{icon} {live_score:.0f}/100 · {TIER_LABELS_AR[live_tier]}</span></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    confirm = st.button(
        "🔒 تأكيد التحويل", type="primary", use_container_width=True,
        disabled=st.session_state.txn_state not in ("idle", "cancelled", "completed"),
    )

    if confirm:
        events = KeystrokeAnalyzer.simulate_events(keystroke_slider)
        result = st.session_state.sdk.assess_transaction(
            call_active=voice_call,
            remote_desktop=True if simulate_remote else None,
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
    """معاينة سريعة لنفس أوزان WajasSDK دون كتابة سطر في سجل التدقيق مع
    كل تحديث — فقط الضغط على «تأكيد التحويل» يُنتج تقييمًا مسجّلًا."""
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
        tier = RiskTier.SAFE
    elif score <= 70:
        tier = RiskTier.LEVEL_1
    elif score <= 85:
        tier = RiskTier.LEVEL_2
    else:
        tier = RiskTier.LEVEL_3
    return score, tier


def render_mitigation_flow() -> None:
    state = st.session_state.txn_state
    snap = st.session_state.current_snapshot
    result = st.session_state.current_result
    score = result.score if result else 0.0

    if state == "completed":
        st.success(
            f"✅ تم تحويل **{snap.get('amount', 0):,.2f} ريال** إلى **{snap.get('beneficiary','')}** بنجاح. "
            f"(درجة الخطورة عند الموافقة: {score:.0f}/100)"
        )
        if st.button("↺ بدء تحويل جديد"):
            _reset_transaction()

    elif state == "cancelled":
        st.info("🛑 تم إلغاء التحويل من قبل المستخدم. لم يتم تحريك أي أموال.")
        if st.button("↺ بدء تحويل جديد"):
            _reset_transaction()

    elif state == "level1_warning":
        triggers = "، ".join(result.breakdown.keys())
        st.markdown(
            f"""
            <div class="warn-banner">
                <h3>⚠️ تنبيه أمني من وَجَسْ</h3>
                <p><strong>درجة الخطورة: {score:.0f}/100</strong> — الإشارات المرصودة: {triggers}</p>
                <p>غالبًا ما يبقى المحتالون على الهاتف معك أثناء إقناعك بتحويل الأموال بحجة
                "حمايتها" أو "التحقق من هويتك". <strong>بنك الإنماء لن يطلب منك أبدًا تحويل
                الأموال أثناء مكالمة هاتفية، أو تثبيت برنامج تحكم عن بعد على جهازك.</strong></p>
                <ul>
                    <li>أنهِ المكالمة واتصل برقم البنك الرسمي للتحقق من أي طلب.</li>
                    <li>لا تشارك رمز التحقق (OTP) أو رقم البطاقة أو تمنح تحكمًا عن بعد أثناء المكالمة.</li>
                    <li>عمليات الاسترداد أو التعليق الحقيقية لا تتطلب منك إرسال الأموال أولًا.</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )
        c1, c2 = st.columns(2)
        with c1:
            if st.button("❌ إلغاء التحويل (موصى به)", use_container_width=True):
                st.session_state.txn_state = "cancelled"
                st.rerun()
        with c2:
            if st.button("✅ أتفهم المخاطر — المتابعة", use_container_width=True):
                st.session_state.txn_state = "completed"
                st.rerun()

    elif state == "level2_hold":
        hold_duration = 15 if st.session_state.demo_mode else 300
        elapsed = time.time() - st.session_state.hold_start
        remaining = max(0, hold_duration - elapsed)
        pct = int(100 * (hold_duration - remaining) / hold_duration)

        st.markdown(
            f"""<div class="hold-banner"><h3>⏳ تعليق أمني نشط — درجة الخطورة {score:.0f}/100</h3>
            <p>تم تأخير التحويل مؤقتًا حتى يتمكن بنك الإنماء من حماية أموالك أثناء وجود نشاط غير معتاد.</p></div>""",
            unsafe_allow_html=True,
        )
        mm, ss = divmod(int(remaining), 60)
        st.metric("الوقت المتبقي", f"{mm:02d}:{ss:02d}")
        st.progress(pct)

        if remaining <= 0:
            st.success("انتهت فترة التعليق.")
            if st.button("✅ تحرير الأموال الآن", type="primary"):
                st.session_state.txn_state = "completed"
                st.rerun()
        else:
            st.caption("⚡ وضع العرض: تم اختصار المدة إلى 15 ثانية." if st.session_state.demo_mode else "")
            if st.button("❌ إلغاء التحويل"):
                st.session_state.txn_state = "cancelled"
                st.rerun()
            time.sleep(1)
            st.rerun()

    elif state == "level3_frozen":
        st.markdown(
            f"""<div class="frozen-banner"><h3>⛔ تم تجميد العملية — درجة الخطورة {score:.0f}/100</h3>
            <p>تم رصد نمط احتيال اجتماعي حي عالي الاحتمالية. أكمل إعادة التحقق من الهوية
            أدناه لتحرير الأموال.</p></div>""",
            unsafe_allow_html=True,
        )
        st.markdown("#### 🎥 التحقق بالفيديو / التحقق الحيوي من الوجه (Video-KYC)")

        if st.session_state.kyc_step == 0:
            st.warning("الأموال مقفلة حتى نجاح التحقق الحيوي.")
            if st.button("▶️ بدء التحقق الحيوي", type="primary"):
                st.session_state.kyc_step = 1
                st.rerun()
        elif st.session_state.kyc_step == 1:
            placeholder = st.empty()
            steps = ["طلب صلاحية الكاميرا…", "رصد الوجه…", "الرجاء الرمش بشكل طبيعي…",
                     "أدر رأسك قليلًا لليسار…", "أدر رأسك قليلًا لليمين…", "مطابقة البصمة الحيوية…"]
            progress = st.progress(0)
            duration = 0.35 if st.session_state.demo_mode else 1.0
            for i, msg in enumerate(steps):
                placeholder.info(f"🔍 {msg}")
                progress.progress(int((i + 1) / len(steps) * 100))
                time.sleep(duration)
            placeholder.success("✅ تم تأكيد التحقق الحيوي.")
            st.session_state.kyc_step = 2
            st.rerun()
        elif st.session_state.kyc_step == 2:
            st.success("✅ تم التحقق من الهوية عبر Video-KYC.")
            if st.button("🔓 تحرير الأموال", type="primary"):
                st.session_state.txn_state = "completed"
                st.rerun()


def _reset_transaction() -> None:
    st.session_state.txn_state = "idle"
    st.session_state.hold_start = None
    st.session_state.kyc_step = 0
    st.rerun()


# ---------------------------------------------------------------------------
# التبويب الثاني — مركز القيادة الأمنية
# ---------------------------------------------------------------------------
def render_dashboard_tab() -> None:
    st.markdown(
        """
        <div class="wajas-hero">
            <h1>🛡️ مركز القيادة الأمنية لوَجَسْ</h1>
            <p>محرك مخاطر Edge AI · استدلال على الجهاز · صفر بيانات شخصية مُرسَلة</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    logs = st.session_state.logs
    total = len(logs)
    frozen = sum(1 for l in logs if l["القرار"] == DECISION_LABELS_AR[Decision.FREEZE])
    held = sum(1 for l in logs if l["القرار"] == DECISION_LABELS_AR[Decision.HOLD])
    avg_score = (sum(l["درجة الخطورة"] for l in logs) / total) if total else 0.0

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("عدد محاولات التحويل (الجلسة)", total)
    m2.metric("حالات التجميد (مستوى 3)", frozen)
    m3.metric("حالات التعليق (مستوى 2)", held)
    m4.metric("متوسط درجة الخطورة", f"{avg_score:.0f}/100")

    col_gauge, col_legend = st.columns([1.1, 1], gap="large")

    with col_gauge:
        st.markdown('<div class="wajas-card">', unsafe_allow_html=True)
        st.markdown("#### 📊 مقياس الخطورة الحي")
        st.caption("يعكس حالة الإشارات الحالية من تبويب تطبيق البنك.")
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
        st.markdown("#### ⚙️ سلّم إجراءات المخاطر")
        st.markdown(
            f"""
            <table style="width:100%;border-collapse:collapse;font-size:14px;color:{WHITE};">
            <tr style="background:#1c2b20;"><td style="padding:6px;"><b>0 – 39</b></td><td>✅ منطقة آمنة — تحويل فوري</td></tr>
            <tr style="background:#2e2a13;"><td style="padding:6px;"><b>40 – 70</b></td><td>⚠️ المستوى الأول — تنبيه توعوي ذكي</td></tr>
            <tr style="background:#332210;"><td style="padding:6px;"><b>71 – 85</b></td><td>⏳ المستوى الثاني — تعليق أمني 5 دقائق</td></tr>
            <tr style="background:#331414;"><td style="padding:6px;"><b>86 – 100</b></td><td>⛔ المستوى الثالث — تجميد + Video-KYC</td></tr>
            </table>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="wajas-card">', unsafe_allow_html=True)
    st.markdown("#### 🧠 سجل معالجة Edge AI")
    st.caption("سجل تدقيق حقيقي من نسخة WajasSDKArabic قيد التشغيل — وليس نصًا مُصطنعًا.")
    lines = st.session_state.sdk.get_log(25)
    console_html = "<br>".join(lines) if lines else "<i>بانتظار أول محاولة تحويل…</i>"
    st.markdown(f'<div class="edge-console">{console_html}</div>', unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="wajas-card">', unsafe_allow_html=True)
    st.markdown("#### 📁 سجل مخاطر العمليات")
    if logs:
        df = pd.DataFrame(logs)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("لا توجد محاولات تحويل بعد — انتقل إلى تبويب تطبيق البنك واضغط «تأكيد التحويل».")
    st.markdown("</div>", unsafe_allow_html=True)

    st.caption(
        "🔐 هذه بيئة اختبار توضيحية فقط وغير متصلة بأي نظام بنكي حقيقي. رصد برامج التحكم عن بعد "
        "فحص حقيقي فعلي للعمليات، بينما رصد المكالمات وتوقيت الكتابة الدقيق محاكاة بحكم قيود "
        "نموذج أولي يعمل على حاسوب مكتبي (راجع توثيق wajas_core.py)."
    )


# ---------------------------------------------------------------------------
# الشريط الجانبي
# ---------------------------------------------------------------------------
def render_sidebar() -> None:
    with st.sidebar:
        st.markdown("## 🛡️ وَجَسْ")
        st.caption("منظومة مكافحة احتيال تعمل على الجهاز — بيئة اختبار وظيفية")
        st.divider()
        st.session_state.demo_mode = st.checkbox(
            "⚡ وضع العرض (اختصار المؤقتات)", value=st.session_state.demo_mode,
        )
        st.divider()
        st.markdown("**حالة الإشارات الحية:**")
        scan = RemoteDesktopDetector().scan()
        st.write(f"🖥️ عدد العمليات المفحوصة: {scan.processes_scanned}")
        st.write(f"📡 تحكم عن بعد: {'🔴 مرصود' if scan.active else '🟢 غير موجود'}")
        st.divider()
        if st.button("🗑️ إعادة تعيين المحاكاة بالكامل", use_container_width=True):
            for k in list(st.session_state.keys()):
                del st.session_state[k]
            st.rerun()
        st.divider()
        st.caption("لا توجد أموال حقيقية أو بيانات شخصية أو أنظمة بنكية فعلية.")


# ---------------------------------------------------------------------------
# نقطة التشغيل الرئيسية
# ---------------------------------------------------------------------------
def main() -> None:
    inject_css()
    init_state()
    render_sidebar()

    tab1, tab2 = st.tabs(["📱 تطبيق البنك (تجربة المستخدم)", "🛡️ مركز القيادة الأمنية"])
    with tab1:
        render_banking_tab()
    with tab2:
        render_dashboard_tab()


if __name__ == "__main__":
    main()
