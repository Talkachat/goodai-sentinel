#!/bin/bash
# GoodAI Sentinel — Control Center (one icon for everything)
PLIST="$HOME/Library/LaunchAgents/com.goodai.sentinel.plist"
AUDIT="$HOME/.goodai-sentinel/audit.jsonl"
PROJ="$HOME/goodai-sentinel"
PY="$(command -v python3.13 || command -v python3)"
DASH_PORT=8787

is_running() { launchctl list 2>/dev/null | grep -q com.goodai.sentinel; }
dash_running() { lsof -i :$DASH_PORT >/dev/null 2>&1; }

while true; do
  clear
  echo "╔══════════════════════════════════════╗"
  echo "║      🛡️  GoodAI Sentinel Control       ║"
  echo "╚══════════════════════════════════════╝"
  echo
  if is_running; then echo "   الحارس:   🟢 شغّال"; else echo "   الحارس:   🔴 متوقّف"; fi
  if dash_running; then echo "   اللوحة:   🟢 شغّالة  →  http://127.0.0.1:$DASH_PORT"; else echo "   اللوحة:   ⚪️ متوقّفة"; fi
  echo
  echo "──────────────────────────────────────"
  echo "  1)  ▶️  تشغيل الحارس"
  echo "  2)  ⏸️  إيقاف الحارس"
  echo "  3)  📊  فتح لوحة التحكم"
  echo "  4)  🔄  إعادة تشغيل الحارس"
  echo "  5)  📋  آخر 10 أحداث"
  echo "  6)  ❌  إيقاف اللوحة"
  echo "  0)  خروج"
  echo "──────────────────────────────────────"
  printf "  اختَر رقم: "
  read -r choice
  case "$choice" in
    1) launchctl load "$PLIST" 2>/dev/null && echo "  ✅ اتشغّل" || echo "  (شغّال بالفعل)"; sleep 1 ;;
    2) launchctl unload "$PLIST" 2>/dev/null && echo "  ⏸️ اتوقّف" || echo "  (متوقّف بالفعل)"; sleep 1 ;;
    3)
       if ! dash_running; then
         ( cd "$PROJ" && nohup "$PY" -m dashboard --audit "$AUDIT" --port $DASH_PORT >/dev/null 2>&1 & )
         sleep 2
       fi
       open "http://127.0.0.1:$DASH_PORT"
       echo "  📊 اللوحة مفتوحة في المتصفح"; sleep 1 ;;
    4) launchctl unload "$PLIST" 2>/dev/null; sleep 1; launchctl load "$PLIST" 2>/dev/null; echo "  🔄 اتعمل إعادة تشغيل"; sleep 1 ;;
    5)
       echo; echo "  آخر 10 أحداث:"; echo "  ──────────────"
       if [ -f "$AUDIT" ]; then tail -n 10 "$AUDIT" | "$PY" -c "
import sys,json
for line in sys.stdin:
    try:
        r=json.loads(line); f=r.get('finding',{})
        sev=f.get('severity') or r.get('severity') or ('deny' if r.get('verdict')=='deny' else 'info')
        what=f.get('rule') or r.get('event') or r.get('verdict') or '—'
        print(f'   [{sev:8}] {what}')
    except: pass
"
       else echo "   (لا يوجد سجل بعد)"; fi
       echo; printf "  اضغط Enter للرجوع..."; read -r _ ;;
    6) lsof -ti :$DASH_PORT | xargs kill 2>/dev/null && echo "  ❌ اللوحة اتوقّفت" || echo "  (متوقّفة بالفعل)"; sleep 1 ;;
    0) exit 0 ;;
    *) echo "  اختيار غير صحيح"; sleep 1 ;;
  esac
done
