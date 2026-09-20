package org.goodai.sentinel

import org.json.JSONArray
import org.json.JSONObject
import java.util.ArrayDeque

/** Verdict for one proposed action. Mirrors sentinel/guardrail.py exactly (same order, same names). */
data class Decision(val verdict: String, val reason: String, val policy: String = "") {
    val allowed get() = verdict == "allow"
}

private data class AgentCfg(
    val capabilities: List<Regex>, val denyTargets: List<Regex>, val allowTargets: List<Regex>,
    val requireApproval: List<Regex>, val rateMax: Int?, val rateWindowS: Int?, val budget: Double?
)

/**
 * Deny-by-default policy engine for AI agents, loaded from policy.json
 * (exported by mobile/export_policy.py). Thread-safe.
 */
class Guardrail(policyJson: String) {
    @Volatile var killSwitch: Boolean
    private val forbidden: List<Pair<String, Regex>>
    private val defaults: AgentCfg
    private val agents: List<Pair<Regex, AgentCfg>>
    private val rate = HashMap<String, ArrayDeque<Long>>()
    private val spent = HashMap<String, Double>()
    private val lock = Any()

    init {
        val doc = JSONObject(policyJson)
        killSwitch = doc.optBoolean("killSwitch", false)
        val fb = doc.getJSONArray("forbidden")
        forbidden = (0 until fb.length()).map { i ->
            val o = fb.getJSONObject(i); o.getString("name") to Regex(o.getString("regex"), RegexOption.IGNORE_CASE)
        }
        defaults = parseCfg(doc.getJSONObject("defaults"))
        val ag = doc.getJSONArray("agents")
        agents = (0 until ag.length()).map { i ->
            val o = ag.getJSONObject(i); Regex(o.getString("match")) to parseCfg(o.getJSONObject("config"))
        }
    }

    private fun JSONArray?.regexes() = if (this == null) emptyList() else (0 until length()).map { Regex(getString(it)) }
    private fun parseCfg(o: JSONObject): AgentCfg {
        val rl = o.optJSONObject("rateLimit")
        return AgentCfg(
            o.optJSONArray("capabilities").regexes(), o.optJSONArray("denyTargets").regexes(),
            o.optJSONArray("allowTargets").regexes(), o.optJSONArray("requireApproval").regexes(),
            rl?.optInt("max"), rl?.optInt("window_s"), if (o.isNull("budget")) null else o.optDouble("budget")
        )
    }

    private fun cfgFor(agentId: String): AgentCfg =
        agents.firstOrNull { it.first.matches(agentId) }?.second ?: defaults

    private fun rateOk(agent: String, max: Int, windowS: Int): Boolean {
        val q = rate.getOrPut(agent) { ArrayDeque() }
        val now = System.currentTimeMillis()
        while (q.isNotEmpty() && now - q.first() > windowS * 1000L) q.removeFirst()
        if (q.size >= max) return false
        q.addLast(now); return true
    }

    /** Normalise like sentinel/platform.py: forward slashes, case-folded (mobile always folds). */
    fun norm(p: String) = p.replace('\\', '/').lowercase()

    fun decide(agentId: String, action: String, rawTarget: String = "", cost: Double = 0.0): Decision = synchronized(lock) {
        val target = norm(rawTarget)
        val cfg = cfgFor(agentId)
        val blob = "$action $target"
        if (killSwitch) return Decision("deny", "global kill switch engaged", "kill_switch")
        for ((name, rx) in forbidden) if (rx.containsMatchIn(blob))
            return Decision("deny", "matches forbidden pattern '$name'", "forbidden_patterns")
        if (cfg.capabilities.none { it.matches(action) })
            return Decision("deny", "'$action' outside capabilities", "capabilities")
        if (cfg.denyTargets.any { it.matches(target) })
            return Decision("deny", "target '$target' is in deny_targets", "deny_targets")
        if (cfg.allowTargets.isNotEmpty() && target.isNotEmpty() && cfg.allowTargets.none { it.matches(target) })
            return Decision("deny", "target '$target' not in allow_targets", "allow_targets")
        if (cfg.rateMax != null && !rateOk(agentId, cfg.rateMax, cfg.rateWindowS ?: 60))
            return Decision("deny", "rate limit exceeded", "rate_limit")
        if (cfg.budget != null && (spent[agentId] ?: 0.0) + cost > cfg.budget)
            return Decision("deny", "budget ${cfg.budget} exhausted", "budget")
        spent[agentId] = (spent[agentId] ?: 0.0) + cost
        if (cfg.requireApproval.any { it.matches(action) || it.matches(target) })
            return Decision("require_approval", "'$action' on '$target' needs a human", "require_approval")
        Decision("allow", "within policy")
    }
}
