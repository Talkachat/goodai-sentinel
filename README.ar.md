# 🛡️ GoodAI Sentinel — الحارس

> **الذكاء الصالح** — وحدة ذكاء اصطناعي دفاعية مفتوحة المصدر تحمي من الهجمات، أيًّا كان مصدرها.

![الاختبارات](https://img.shields.io/badge/tests-88%20passing-brightgreen)
![الفريق الأحمر](https://img.shields.io/badge/red%20team-0%20breaches-brightgreen)
![الرخصة](https://img.shields.io/badge/license-MIT-blue)
![المنصات](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android%20%7C%20iOS-lightgrey)

> ⚠️ **للاستخدام الدفاعي فقط.** هذا المستودع يحتوي على *توقيعات* هجمات لغرض الكشف، لا للهجوم. راجع [`NOTICE_DEFENSIVE_USE.md`](NOTICE_DEFENSIVE_USE.md).
>
> 🇬🇧 English version: [`README.md`](README.md)

---

## يحمي ضد

- 🖥️ **أي هجمات سيبرانية**
- 🤖 **أي هجمات من وكلاء الذكاء الاصطناعي** (وكلاء، نماذج، روبوتات)
- 🐛 **أي برمجيات خبيثة**
- 🌐 **على كل الأسطح**:
  - 💻 الكمبيوتر (حاسوب مكتبي ومحمول)
  - 📱 الموبايل (أندرويد و iOS)
  - 🌍 الشبكة الخارجية
  - 🏠 الشبكة الداخلية
  - 🖧 السيرفرات عمومًا

---

## كيف يعمل

للحارس **مدخلان ومسار إنفاذ واحد**:

1. **مراقبة الجهاز** — مستشعرات تراقب العمليات والاتصالات الشبكية والملفات؛ كاشف (قواعد + خط أساس سلوكي) يقيّم كل حدث؛ ومستجيب يتصرّف على سلّم يبدأ بالإجراءات القابلة للتراجع: `تسجيل ← تنبيه ← تبطيء ← تجميد ← إنهاء ← حظر`.
2. **حارس الوكلاء** — أي وكيل يجب أن ينادي `request()` *قبل* أن يتصرّف، فيحصل على `allow` أو `deny` أو `require_approval` من سياسة تمنع كل شيء افتراضيًا، **ولا يستطيع أي وكيل تعطيلها أو تعديلها** — ولا حتى عبر تعطيل الحارس نفسه.

كل قرار قابل للتفسير ويُكتب في سجل تدقيق **مقاوم للعبث**.

```python
from sentinel.core import Sentinel
s = Sentinel(dry_run=True)

s.request("agent-1", "write:file", "/workspace/app.py")        # -> allow
s.request("agent-1", "shell:run", "systemctl stop sentinel")   # -> deny (تعطيل الدفاع)
s.request("agent-1", "deploy:prod", "v2")                      # -> require_approval
```

## البدء السريع

```bash
git clone https://github.com/<you>/goodai-sentinel.git
cd goodai-sentinel
pip install -e ".[test]"
pytest -q                 # 88 اختبارًا
python -m redteam.run     # بوابة الاختبار العدائي: صفر اختراقات
python -m sentinel --watch /etc ~     # راقب هذا الجهاز (وضع تجريبي افتراضيًا)
```

## البنية

```
sentinel/       النواة · المستشعرات · الكاشف · الحاجز · المستجيب · الرموز · التدقيق (غير متزامن + SQLite) · مراقب السياسة · طبقة النظام
integrations/   distai/  — حماية أسطول استدلال موزّع
mobile/         أندرويد (Kotlin) + iOS (Swift): حارس + حارس شبكة عبر VPN
redteam/        مجموعة هجمات عدائية + حلقة اكتشاف قواعد تكيّفية
policy/         agent_guardrails.yaml — منع افتراضي، YAML بسيط (إنجليزي + عربي)
docs/           المعمارية، خطة البحث، تقرير التهديد، سجل المراجعات (إنجليزي + عربي)
```

## الأمان والنطاق

- 🔒 أبلغ عن الثغرات بشكل خاص — راجع [`SECURITY.md`](SECURITY.md).
- 🧪 هذا **نموذج أولي** مُحصّن عبر أربع جولات مراجعة مستقلة (راجع `docs/REVIEW_2.md` … `REVIEW_4.md`). الطريق الصادق للإنتاج معماري: خدمة قرار سياسة مركزية، كاشف دلالي (غير regex)، واختبار حقيقي على الأجهزة.
- 🤝 للمساهمة: راجع [`CONTRIBUTING.md`](CONTRIBUTING.md).

## الرخصة
MIT — استخدمه، انسخه، ضمّنه. راجع [`LICENSE`](LICENSE).
