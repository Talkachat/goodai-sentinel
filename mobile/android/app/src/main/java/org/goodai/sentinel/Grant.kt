package org.goodai.sentinel

import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import android.util.Base64
import org.json.JSONObject

/** Hot-path capability token: one guardrail decision, then local validate() in a loop. Mirrors sentinel/tokens.py. */
class Grant internal constructor(
    val token: String, val agentId: String, private val action: Regex, private val target: Regex?,
    count: Int, val expiresMs: Long
) {
    private val remaining = AtomicInteger(count)
    @Volatile internal var revoked = false
    val left get() = remaining.get()

    fun validate(action: String? = null, target: String? = null): Boolean {
        if (revoked || System.currentTimeMillis() > expiresMs) return false
        if (action != null && !this.action.matches(action)) return false
        if (target != null && this.target != null && !this.target.matches(target.replace('\\', '/').lowercase())) return false
        while (true) {
            val n = remaining.get(); if (n <= 0) return false
            if (remaining.compareAndSet(n, n - 1)) return true
        }
    }
    internal fun kill() { revoked = true; remaining.set(0) }
}

class TokenIssuer(private val guardrail: Guardrail, private val secret: ByteArray) {
    private val live = HashMap<String, Grant>()

    private fun glob(g: String) = Regex("^" + g.replace('\\', '/').lowercase().split("*").joinToString(".*") { Regex.escape(it) } + "$")

    private fun sign(body: String): String {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(secret, "HmacSHA256")) }
        return mac.doFinal(body.toByteArray()).joinToString("") { "%02x".format(it) }.take(32)
    }

    /** novelty in 0..1 shrinks the grant (count and ttl) like the Python issuer. */
    fun grant(agentId: String, action: String, target: String = "", count: Int = 1000, ttlS: Double = 60.0,
              novelty: Double = 0.0, cost: Double = 0.0): Pair<Decision, Grant?> {
        val d = guardrail.decide(agentId, action, target, cost)
        if (!d.allowed) return d to null
        val scale = maxOf(0.05, 1.0 - novelty)
        val n = maxOf(1, Math.round(count * scale).toInt()); val ttl = maxOf(1.0, ttlS * scale)
        val exp = System.currentTimeMillis() + (ttl * 1000).toLong()
        val id = java.util.UUID.randomUUID().toString().replace("-", "").take(16)
        val body = Base64.encodeToString(JSONObject(mapOf("id" to id, "agent" to agentId, "action" to action,
            "target" to target, "n" to n, "exp" to exp)).toString().toByteArray(), Base64.URL_SAFE or Base64.NO_WRAP)
        val g = Grant("$body.${sign(body)}", agentId, glob(action), if (target.isEmpty()) null else glob(target), n, exp)
        synchronized(live) { live[id] = g }
        return d to g
    }

    fun revoke(agentId: String? = null, tokenId: String? = null) = synchronized(live) {
        live.entries.filter { (id, g) -> id == tokenId || (agentId != null && g.agentId == agentId) }
            .forEach { (id, g) -> g.kill(); live.remove(id) }
    }
}
