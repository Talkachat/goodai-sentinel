package org.goodai.sentinel

import java.io.File

/** Cheap local signals that the device itself is compromised. Pair with Play Integrity API for a server-verifiable verdict. */
object DeviceIntegrity {
    private val ROOT_MARKERS = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/app/Superuser.apk",
        "/data/local/tmp/frida-server", "/data/adb/magisk")
    fun rooted() = ROOT_MARKERS.any { File(it).exists() } || android.os.Build.TAGS?.contains("test-keys") == true
    fun debuggerAttached() = android.os.Debug.isDebuggerConnected()
    fun findings(): List<String> = buildList {
        if (rooted()) add("device_rooted")
        if (debuggerAttached()) add("debugger_attached")
    }
}
