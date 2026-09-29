# Desktop Control Center

One icon for everything — start, stop, status, and the dashboard — instead of separate buttons.

## Install
Double-click `install-control-center.command` (in this folder). It creates
**🛡️ GoodAI Sentinel.app** on your Desktop.

First run: right-click the .command → Open → Open (macOS asks once for unsigned files).

## Use
Double-click **🛡️ GoodAI Sentinel.app**. A small menu opens:
```
  الحارس:  🟢 شغّال / 🔴 متوقّف
  اللوحة:  🟢 شغّالة → http://127.0.0.1:8787

  1) ▶️  تشغيل الحارس
  2) ⏸️  إيقاف الحارس
  3) 📊  فتح لوحة التحكم
  4) 🔄  إعادة تشغيل
  5) 📋  آخر 10 أحداث
  6) ❌  إيقاف اللوحة
  0) خروج
```
- Option 3 starts the dashboard (if not already running) and opens it in your browser.
- The menu shows live status of both the guard and the dashboard at the top.

## What it controls
- The guard = the `launchd` service (com.goodai.sentinel)
- The dashboard = the read-only web view on port 8787
Everything is local; nothing is exposed beyond your machine.
