# 🛡️ GoodAI Sentinel

> **الذكاء الصالح** — وحدة ذكاء اصطناعي دفاعية مفتوحة المصدر تحمي من الهجمات، أيًّا كان مصدرها.
> **The good AI** — an open-source defensive AI module that protects against attacks, whatever their source.

![tests](https://img.shields.io/badge/tests-88%20passing-brightgreen)
![red team](https://img.shields.io/badge/red%20team-0%20breaches-brightgreen)
![license](https://img.shields.io/badge/license-MIT-blue)
![platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android%20%7C%20iOS-lightgrey)

> 🇸🇦 النسخة العربية: [`README.ar.md`](README.ar.md)
>
> ⚠️ **Defensive-use only.** This repo contains attack *signatures* for detection, not for offense. See [`NOTICE_DEFENSIVE_USE.md`](NOTICE_DEFENSIVE_USE.md).

---

## يحمي ضد / Protects against

- 🖥️ **أي هجمات سيبرانية** — Any cyberattack
- 🤖 **أي هجمات من وكلاء الذكاء الاصطناعي** — Any attack from AI agents, models, or robots
- 🐛 **أي برمجيات خبيثة** — Any malicious software
- 🌐 **على كل الأسطح** — Across every surface:
  - 💻 الكمبيوتر / desktop & laptop
  - 📱 الموبايل / mobile (Android & iOS)
  - 🌍 الشبكة الخارجية / external network
  - 🏠 الشبكة الداخلية / internal network
  - 🖧 السيرفرات / servers

---

## How it works (نبذة)

Sentinel has **two entry points and one enforced path**:

1. **مراقبة الجهاز / Host monitoring** — sensors watch processes, network sockets and files;
   a detector (rules + behavioural baseline) scores every event; a responder acts on a
   reversible-first ladder: `log → alert → throttle → freeze → terminate → block`.
2. **حارس الوكلاء / AI-agent guardrail** — any agent must call `request()` *before* it acts and
   gets `allow` / `deny` / `require_approval` from a deny-by-default policy that **no agent can
   disable or modify** — not even by disabling Sentinel itself.

Every decision is explainable and written to a **tamper-evident** audit log.

```python
from sentinel.core import Sentinel
s = Sentinel(dry_run=True)

s.request("agent-1", "write:file", "/workspace/app.py")        # -> allow
s.request("agent-1", "shell:run", "systemctl stop sentinel")   # -> deny (disable_defense)
s.request("agent-1", "deploy:prod", "v2")                      # -> require_approval
```

## Quick start

```bash
git clone https://github.com/<you>/goodai-sentinel.git
cd goodai-sentinel
pip install -e ".[test]"
pytest -q                 # 88 tests
python -m redteam.run     # adversarial gate: 0 breaches
python -m sentinel --watch /etc ~     # monitor this machine (dry-run by default)
```

## Layout

```
sentinel/       core · sensors · detector · guardrail · responder · tokens · audit (async + SQLite) · policy watcher · platform
integrations/   distai/  — protect a distributed inference fleet
mobile/         Android (Kotlin) + iOS (Swift) guardrail & VPN network sentinel
redteam/        adversarial corpus + adaptive rule-discovery loop
policy/         agent_guardrails.yaml — deny-by-default, plain YAML (EN + AR)
docs/           architecture, research plan, threat report, review history (EN + AR)
```

## Security & scope

- 🔒 Report vulnerabilities privately — see [`SECURITY.md`](SECURITY.md).
- 🧪 This is a hardened **prototype**, refined across four independent review rounds
  (see `docs/REVIEW_2.md` … `REVIEW_4.md`). The honest path to production is architectural:
  a central policy-decision service, a semantic (non-regex) detector, and real device testing.
- 🌍 Docs and policy are bilingual (English + العربية).

## License
MIT — use it, fork it, embed it. See [`LICENSE`](LICENSE).
