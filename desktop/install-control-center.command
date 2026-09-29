#!/bin/bash
# Installs the GoodAI Sentinel Control Center as a real .app on the Desktop and in the project.
set -e
PROJ="$HOME/goodai-sentinel"
SRC="$PROJ/desktop/GoodAI-Sentinel.command"
APP="$HOME/Desktop/🛡️ GoodAI Sentinel.app"

echo "بناء أيقونة التطبيق..."
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# Info.plist
cat > "$APP/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>GoodAI Sentinel</string>
  <key>CFBundleDisplayName</key><string>GoodAI Sentinel</string>
  <key>CFBundleIdentifier</key><string>org.goodai.sentinel.control</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>launcher</string>
</dict></plist>
PLIST

# launcher: opens the control-center menu in Terminal
cat > "$APP/Contents/MacOS/launcher" << 'LAUNCH'
#!/bin/bash
open -a Terminal "$HOME/goodai-sentinel/desktop/GoodAI-Sentinel.command"
LAUNCH
chmod +x "$APP/Contents/MacOS/launcher"

echo "✅ تم إنشاء التطبيق على سطح المكتب: 🛡️ GoodAI Sentinel.app"
echo "   دبل كليك عليه يفتح مركز التحكم بكل الأزرار."
