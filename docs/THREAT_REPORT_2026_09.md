# What changed in Sentinel after Anthropic's September 2026 threat report

Source: *Detecting and countering misuse of AI: September 2026* (anthropic.com/threat-intelligence-report-september-2026).

| Report finding | Sentinel response | Where |
|---|---|---|
| Published IOCs: attacker domains, egress IPs, malware file names and hashes (GTG-20006, -50014, -50020, -50021, -50029, -84005) | Bundled intel feed; `ioc_ip` / `ioc_domain` / `ioc_filename` / `ioc_hash` rules → block/isolate. Agent actions targeting a listed domain are blocked. | `sentinel/intel/`, `rules_2026_09.py` |
| AI API keys and cloud tokens are the loot; stolen keys re-used for attack compute | `credential_exfil` (secret + transfer tool on a command line → terminate), `credential_on_cmdline`; guardrail `ai_key_exfil` pattern; DistAI node refuses to upload any output containing a credential-shaped string | rules, `policy/agent_guardrails.yaml`, `node_shield.check_result` |
| Prompt injection into LiteLLM wrappers and an eval sandbox dumped production keys | `env_or_metadata_dump` (169.254.169.254, `/proc/self/environ`, `printenv`, `os.environ`…) — critical for agent actions; guardrail `cloud_metadata` + `env_dump` forbidden patterns, checked before capabilities so injection cannot unlock them | rules, policy |
| Implants that freeze security updates so new signatures never arrive | `disable_security_updates` (wuauserv, unattended-upgrades, softwareupdate, Defender realtime) → terminate; guardrail `disable_updates` | rules, policy |
| Autonomous evasion loop: malware rebuilt until undetected | `polymorphic_rebuild`: same process name seen as ≥3 distinct binaries within an hour → isolate. Targets the *behaviour of evasion* rather than any signature | rules |
| Fake "Claude Code"/AI-harness installers stealing session tokens (GTG-50021) | `ai_branded_binary_from_temp`: AI-tool-branded executable running from Downloads/Temp → isolate; reseller domains in IOC feed | rules, intel |
| Webshells hidden in font assets, must-use plugins, poisoned uploads and backups (GTG-50029) | `webshell_drop` (PHP in uploads/mu-plugins/assets paths) and `webshell_in_asset` (PHP tags inside .woff/.css/.svg…) | rules |
| Actor-controlled device registration into victim tenants (GTG-20006) | Guardrail `register_device` pattern; `register:*` and `spawn:*` require human approval | policy |
| Agent swarms with persistent campaign memory | Rate limits + budgets per agent; `spawn:*` gated; `spawn_unbounded` forbidden | policy |
| Volunteer/agent compute environments (containers, deployed agents) are hunted for keys | DistAI layer 1: signed model manifest (anti-tamper, anti-rollback, expiry), job protocol validation (no tools, no multimodal, bounded tokens), coordinator-only egress, findings-only reporting | `integrations/distai/` |
| Detection cost has been inverted onto defenders | DistAI layer 2: fleet immune system — 3 nodes reporting the same destination → signed blocklist pushed to all nodes via the manifest; behavioural node scoring (failure ratio, replayed output, impossible latency, protocol violations) → throttle → quarantine | `coordinator_guard.py` |

**Also fixed while here:** the ransomware-window state was shared across `Detector` instances (from the earlier review); every detector now gets fresh stateful rules.

**What the report describes that Sentinel does not address:** device-code phishing of cloud email (defended at the identity provider), WhatsApp companion-device takeover, influence operations, distillation, biological and weapons misuse. Those are provider-side or identity-side problems and are out of scope by design.

Tests: `tests/test_report_2026_09.py` (one test per row) and `tests/test_distai.py`. 37 total.
