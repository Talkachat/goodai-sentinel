# Contributing / المساهمة

Thanks for helping make defensive AI better. شكرًا لمساهمتك في تطوير الذكاء الدفاعي.

## Ground rules / قواعد أساسية
- **Defensive only.** No offensive tooling. New attack strings are allowed **only** inside the
  red-team corpus (`redteam/`) or as detection patterns, never as working exploits.
  **دفاعي فقط** — أي أنماط هجوم تُضاف للكشف أو للاختبار فقط، مش كأدوات هجوم شغّالة.
- Be kind and constructive in issues and reviews.

## Before you open a PR / قبل ما تفتح PR
```bash
pip install -e ".[test]"
pytest -q                 # كل الاختبارات لازم تعدّي (all tests must pass)
python -m redteam.run     # لازم: 0 breaches / 0 over-blocks
```
A PR that reduces test count, weakens an assertion, or introduces a red-team breach or
over-block will not be merged. أي PR بيقلّل الاختبارات أو يضعّف تأكيد أو يفتح ثغرة لن يُدمج.

## Adding a detection rule / إضافة قاعدة كشف
1. Add the rule to `policy/agent_guardrails.yaml` (`forbidden_patterns`).
2. Add a regression case to `redteam/attacks.py` so it can never regress.
3. Run `python -m redteam.run` and confirm it still passes with no over-blocks.
4. If you found the gap with the adaptive loop (`python -m redteam.adaptive`), mention it in the PR.

## Reporting security issues / الإبلاغ عن ثغرة
Do **not** open a public issue — use private reporting. See [`SECURITY.md`](SECURITY.md).
متفتحش issue عام — استخدم الإبلاغ الخاص، راجع `SECURITY.md`.

## Style
- Python ≥ 3.10, standard library first; keep hot paths dependency-free.
- Every fix carries a test. Docs and policy comments welcome in English and/or العربية.
