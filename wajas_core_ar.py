"""
wajas_core_ar.py — المحرك الأساسي لمنظومة وَجَسْ (النسخة العربية)
================================================================
هذه هي النسخة العربية من محرك المخاطر. لا تُعيد كتابة منطق الكشف أو
الحساب من الصفر، بل تُعيد استخدامه بالكامل من wajas_core.py (نفس فحص
العمليات الحقيقي عبر psutil، ونفس محلل ديناميكية الكتابة، ونفس أوزان
وحدود محرك المخاطر) — الفرق الوحيد هنا هو أن أسباب الخطورة وسجل
التدقيق الداخلي (Edge AI console) تُكتب بالعربية لعرضها مباشرة في
واجهة app_ar.py، بدلاً من إعادة صياغة نفس المنطق بلغتين قد تنحرفان عن
بعضهما مع الوقت.

بعبارة أخرى: مصدر الحقيقة الوحيد للحساب الرقمي يبقى wajas_core.py.
أي تعديل مستقبلي على الأوزان أو حدود المستويات يجب أن يتم هناك فقط.

تشغيل مستقل للتأكد من عمل الفحص الحقيقي:  python wajas_core_ar.py
"""

from __future__ import annotations

import platform
from datetime import datetime
from typing import List, Optional

from wajas_core import (
    AssessmentResult,
    Decision,
    KeystrokeAnalyzer,
    RemoteDesktopDetector,
    RiskTier,
    WajasSDK,
)

# ---------------------------------------------------------------------------
# ترجمة تسميات القرارات والمستويات لعرضها في الواجهة العربية.
# القيم الداخلية للمحرك (Decision / RiskTier) تبقى بالإنجليزية عمدًا لأنها
# تُستخدم في المقارنات البرمجية (if result.decision == Decision.FREEZE) —
# الترجمة هنا للعرض فقط.
# ---------------------------------------------------------------------------
DECISION_LABELS_AR = {
    Decision.ALLOW: "سماح فوري",
    Decision.WARN: "تنبيه توعوي",
    Decision.HOLD: "تعليق أمني",
    Decision.FREEZE: "تجميد كامل",
}

TIER_LABELS_AR = {
    RiskTier.SAFE: "منطقة آمنة",
    RiskTier.LEVEL_1: "المستوى الأول",
    RiskTier.LEVEL_2: "المستوى الثاني",
    RiskTier.LEVEL_3: "المستوى الثالث",
}


class WajasSDKArabic(WajasSDK):
    """نفس محرك وَجَسْ تمامًا (نفس الكاشفات، نفس الأوزان، نفس الحدود عبر
    الوراثة من WajasSDK) — الاختلاف الوحيد أن أسباب الخطورة (breakdown)
    وسجل التدقيق الداخلي يُكتبان بالعربية بدلاً من الإنجليزية."""

    def __init__(self):
        super().__init__()
        # استبدال رسالة التهيئة الإنجليزية القادمة من الفئة الأساسية
        # برسالة عربية، دون التأثير على الكاشفات نفسها.
        self._log = []
        self._append_log(f"تم تشغيل محرك وَجَسْ على نظام {platform.system()} {platform.release()}.")

    def assess_transaction(
        self,
        call_active: bool = False,
        remote_desktop: Optional[bool] = None,
        keystroke_events: Optional[List[float]] = None,
        amount: float = 0.0,
    ) -> AssessmentResult:
        """نسخة عربية من assess_transaction الأصلية — نفس الحساب الرقمي
        تمامًا، لكن بأسباب خطورة وسجل تدقيق مكتوبَين بالعربية."""
        breakdown: dict = {}

        if remote_desktop is None:
            scan = self.remote_detector.scan()
            self._append_log(
                f"فحص العمليات: تم فحص {scan.processes_scanned} عملية خلال "
                f"{scan.duration_ms} مللي ثانية — عدد التطابقات: {len(scan.matched_processes)}."
            )
            if scan.matched_processes:
                self._append_log(f"تم رصد توقيع برنامج تحكم عن بعد: {', '.join(scan.matched_processes)}")
            remote_active = scan.active
            matched_processes = scan.matched_processes
            scan_duration_ms = scan.duration_ms
        else:
            remote_active = remote_desktop
            matched_processes = []
            scan_duration_ms = 0.0

        if call_active:
            breakdown["مكالمة نشطة أثناء تنفيذ العملية"] = self.W_CALL
        if remote_active:
            breakdown["تم رصد برنامج تحكم عن بعد"] = self.W_REMOTE

        keystroke_score = 0.0
        if keystroke_events:
            keystroke_score, ks_breakdown = KeystrokeAnalyzer.analyze(keystroke_events)
            weighted = round(keystroke_score * self.W_KEYSTROKE, 1)
            if weighted > 0:
                breakdown["نمط كتابة غير طبيعي (تردد/إملاء)"] = weighted
            self._append_log(f"محلل الكتابة: مستوى التوتر {keystroke_score}/100 ({ks_breakdown})")

        if call_active and remote_active:
            breakdown["نمط احتيال اجتماعي مركّب (مكالمة + تحكم عن بعد)"] = self.W_COMBO

        if amount >= self.HIGH_VALUE_THRESHOLD:
            breakdown["مضاعِف قيمة تحويل مرتفعة"] = self.W_HIGH_VALUE

        score = round(min(100.0, sum(breakdown.values())), 1)
        tier, decision = self._tier_for(score)

        self._append_log(
            f"درجة الخطورة {score}/100 ← المستوى: {TIER_LABELS_AR[tier]} ← القرار: {DECISION_LABELS_AR[decision]}."
        )

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
# واجهة الاستدعاء بسطر واحد — النسخة العربية
#
#     from wajas_core_ar import assess
#     result = assess(call_active=True, amount=15000)
#
# ---------------------------------------------------------------------------
_default_sdk_ar = WajasSDKArabic()


def assess(**kwargs) -> AssessmentResult:
    return _default_sdk_ar.assess_transaction(**kwargs)


def get_engine() -> WajasSDKArabic:
    return _default_sdk_ar


# ---------------------------------------------------------------------------
# اختبار ذاتي مستقل — python wajas_core_ar.py
# يثبت أن الفحص الحقيقي لبرامج التحكم عن بعد يعمل فعليًا على هذا الجهاز.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    # نوافذ (Windows) تستخدم افتراضيًا ترميز cp1252 في الطرفية، وهو لا يدعم
    # الأحرف العربية إطلاقًا ويتسبب في تعطل print() — نجبر الإخراج على
    # UTF-8 هنا حتى يعمل الاختبار الذاتي في أي طرفية دون إعداد مسبق.
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    print("وَجَسْ — اختبار ذاتي مستقل\n" + "-" * 40)

    sdk = WajasSDKArabic()

    print("\n[1] حالة أساسية آمنة (بدون إشارات):")
    r = sdk.assess_transaction(amount=2000)
    print(f"    الدرجة={r.score} المستوى={TIER_LABELS_AR[r.tier]} القرار={DECISION_LABELS_AR[r.decision]}")

    print("\n[2] فحص حقيقي لبرامج التحكم عن بعد + محاكاة كتابة متوترة + مكالمة نشطة:")
    fake_events = KeystrokeAnalyzer.simulate_events(stress_level=85)
    r = sdk.assess_transaction(call_active=True, keystroke_events=fake_events, amount=25000)
    print(f"    الدرجة={r.score} المستوى={TIER_LABELS_AR[r.tier]} القرار={DECISION_LABELS_AR[r.decision]}")
    print(f"    برنامج_تحكم_نشط={r.remote_desktop_active} المطابقات={r.matched_processes}")
    print(f"    التفصيل={r.breakdown}")

    print("\n[3] سجل التدقيق الداخلي (آخر 10 أسطر):")
    for line in sdk.get_log(10):
        print("    " + line)
