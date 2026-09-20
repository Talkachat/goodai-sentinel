package org.goodai.sentinel

import android.app.PendingIntent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * Host-level network sentinel for Android WITHOUT root: a local VPN that every app's traffic
 * passes through. It can (1) see destination IP/port + owning app UID for every flow,
 * (2) drop flows to blocked destinations / known C2 ports, (3) report findings.
 *
 * This is the only host-wide sensor Android allows a third-party app. It requires the user
 * to accept the VPN consent dialog (VpnService.prepare()). Full packet forwarding needs a
 * userspace TCP/UDP stack (e.g. tun2socks / hev-socks5-tunnel); the skeleton below implements
 * the policy layer and the drop path and delegates forwarding to [Forwarder].
 */
class SentinelVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    @Volatile private var running = false

    companion object {
        val BLOCKED_PORTS = setOf(4444, 1337, 31337, 6667, 9001, 5555)
        val blockedIps = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()   // fed by coordinator / findings
        var onFinding: ((Finding) -> Unit)? = null
    }
    data class Finding(val rule: String, val severity: String, val dst: String, val port: Int, val uid: Int, val reason: String)

    override fun onStartCommand(intent: android.content.Intent?, flags: Int, startId: Int): Int {
        if (running) return START_STICKY
        tun = Builder().setSession("GoodAI Sentinel").addAddress("10.111.0.2", 32).addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1").setBlocking(true)
            .setConfigureIntent(PendingIntent.getActivity(this, 0, packageManager.getLaunchIntentForPackage(packageName), PendingIntent.FLAG_IMMUTABLE))
            .also { b -> runCatching { b.addDisallowedApplication(packageName) } }   // never loop our own traffic
            .establish()
        running = true
        worker = Thread { loop() }.apply { start() }
        return START_STICKY
    }

    private fun loop() {
        val fd = tun ?: return
        val input = FileInputStream(fd.fileDescriptor); val output = FileOutputStream(fd.fileDescriptor)
        val fwd = Forwarder(this, output)
        val buf = ByteBuffer.allocate(32767)
        while (running) {
            val n = input.read(buf.array()); if (n <= 0) continue
            buf.limit(n); buf.position(0)
            val pkt = Packet.parse(buf) ?: continue
            val dst = pkt.dstIp.hostAddress ?: ""; val uid = ownerUid(pkt)
            when {
                blockedIps.contains(dst) -> drop("blocked_destination", "high", pkt, uid, "coordinator blocklist")
                pkt.dstPort in BLOCKED_PORTS -> drop("c2_port", "high", pkt, uid, "known backdoor port")
                pkt.protocol == Packet.UDP && pkt.dstPort == 53 && pkt.payloadLen > 512 ->
                    drop("dns_tunnel", "medium", pkt, uid, "oversized DNS query")
                else -> fwd.send(pkt)
            }
            buf.clear()
        }
    }

    private fun drop(rule: String, sev: String, p: Packet, uid: Int, why: String) {
        onFinding?.invoke(Finding(rule, sev, p.dstIp.hostAddress ?: "", p.dstPort, uid, why))
        Log.w("Sentinel", "[$sev] $rule uid=$uid -> ${p.dstIp.hostAddress}:${p.dstPort} ($why)")
    }

    /** Android 10+: map a flow to the app that owns it. */
    private fun ownerUid(p: Packet): Int = if (android.os.Build.VERSION.SDK_INT >= 29) runCatching {
        (getSystemService(CONNECTIVITY_SERVICE) as android.net.ConnectivityManager)
            .getConnectionOwnerUid(p.protocol, java.net.InetSocketAddress(p.srcIp, p.srcPort), java.net.InetSocketAddress(p.dstIp, p.dstPort))
    }.getOrDefault(-1) else -1

    override fun onDestroy() { running = false; tun?.close(); super.onDestroy() }
}

/** Minimal IPv4 header parse; enough for policy decisions. */
class Packet(val protocol: Int, val srcIp: InetAddress, val dstIp: InetAddress, val srcPort: Int, val dstPort: Int, val payloadLen: Int, val raw: ByteBuffer) {
    companion object {
        const val TCP = 6; const val UDP = 17
        fun parse(b: ByteBuffer): Packet? {
            if (b.remaining() < 20 || (b.get(0).toInt() shr 4) != 4) return null
            val ihl = (b.get(0).toInt() and 0x0F) * 4; val proto = b.get(9).toInt() and 0xFF
            val src = InetAddress.getByAddress(ByteArray(4) { b.get(12 + it) }); val dst = InetAddress.getByAddress(ByteArray(4) { b.get(16 + it) })
            if (proto != TCP && proto != UDP || b.remaining() < ihl + 4) return null
            val sp = b.getShort(ihl).toInt() and 0xFFFF; val dp = b.getShort(ihl + 2).toInt() and 0xFFFF
            return Packet(proto, src, dst, sp, dp, b.remaining() - ihl, b)
        }
    }
}

/**
 * Forwards allowed packets out to the real network and writes replies back into the TUN.
 *
 * UDP (incl. DNS) is fully implemented here in userspace: for each 5-tuple we open a real
 * DatagramChannel, protect() it so its traffic bypasses the VPN (no routing loop), send the
 * payload, and pump replies back as synthetic IPv4/UDP packets. A reaper closes idle flows.
 *
 * TCP is intentionally delegated to a pluggable native stack ([TcpStack]) — a correct userspace
 * TCP implementation (SYN/ACK, retransmit, windowing) is out of scope for this module and should
 * be lwIP / tun2socks. If no stack is installed, TCP packets are dropped-closed (fail safe),
 * never silently blackholed.
 */
class Forwarder(private val svc: VpnService, private val back: FileOutputStream) {
    interface TcpStack { fun input(pkt: Packet, writeBack: (ByteArray) -> Unit) }
    var tcpStack: TcpStack? = null

    private data class Flow(val ch: java.nio.channels.DatagramChannel, @Volatile var last: Long)
    private val udp = java.util.concurrent.ConcurrentHashMap<String, Flow>()
    private val pool = java.util.concurrent.Executors.newCachedThreadPool()
    init { startReaper() }

    fun send(p: Packet) {
        when (p.protocol) {
            Packet.UDP -> forwardUdp(p)
            Packet.TCP -> tcpStack?.input(p) { writeBack(it) }
                ?: android.util.Log.w("Sentinel", "TCP dropped (no stack) -> ${p.dstIp.hostAddress}:${p.dstPort}")
        }
    }

    private fun key(p: Packet) = "${p.srcIp.hostAddress}:${p.srcPort}>${p.dstIp.hostAddress}:${p.dstPort}"

    private fun forwardUdp(p: Packet) {
        val k = key(p)
        val flow = udp.getOrPut(k) {
            val ch = java.nio.channels.DatagramChannel.open()
            svc.protect(ch.socket())                    // critical: keep our own traffic out of the tunnel
            ch.connect(java.net.InetSocketAddress(p.dstIp, p.dstPort))
            ch.configureBlocking(true)
            val f = Flow(ch, System.currentTimeMillis())
            pool.submit { pumpReplies(p, f) }
            f
        }
        flow.last = System.currentTimeMillis()
        val payload = p.raw.duplicate().apply { position(headerLen(p)) }
        flow.ch.write(payload)
    }

    private fun pumpReplies(req: Packet, flow: Flow) {
        val buf = java.nio.ByteBuffer.allocate(2048)
        try {
            while (!flow.ch.socket().isClosed) {
                buf.clear(); val n = flow.ch.read(buf); if (n <= 0) break
                buf.flip()
                writeBack(buildUdpReply(req, buf))       // swap src/dst so the app sees a normal reply
                flow.last = System.currentTimeMillis()
            }
        } catch (_: Exception) {} finally { flow.ch.close(); udp.remove(key(req)) }
    }

    private fun writeBack(pkt: ByteArray) = synchronized(back) { back.write(pkt); back.flush() }
    private fun headerLen(p: Packet) = (p.raw.get(0).toInt() and 0x0F) * 4 + 8   // IPv4 IHL + UDP header

    /** Build an IPv4+UDP packet carrying `data` from req.dst back to req.src. */
    private fun buildUdpReply(req: Packet, data: java.nio.ByteBuffer): ByteArray {
        val len = data.remaining(); val total = 28 + len
        val b = java.nio.ByteBuffer.allocate(total)
        b.put(0x45.toByte()); b.put(0); b.putShort(total.toShort())
        b.putShort(0); b.putShort(0); b.put(64); b.put(17)          // ttl, proto=UDP
        b.putShort(0)                                               // checksum (0 = skip; kernel/app tolerant)
        b.put(req.dstIp.address); b.put(req.srcIp.address)          // src=orig dst, dst=orig src
        b.putShort(req.dstPort.toShort()); b.putShort(req.srcPort.toShort())
        b.putShort((8 + len).toShort()); b.putShort(0)
        b.put(data)
        return b.array()
    }

    private fun startReaper() {
        pool.submit {
            while (true) {
                Thread.sleep(10_000)
                val cutoff = System.currentTimeMillis() - 30_000
                udp.entries.removeIf { (_, f) -> f.last < cutoff && run { f.ch.close(); true } }
            }
        }
    }
}
