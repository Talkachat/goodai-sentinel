import Foundation

/// Verdict for one proposed action. Mirrors sentinel/guardrail.py and the Kotlin port (same order, same names).
public struct Decision: Equatable {
    public let verdict: String   // allow | deny | require_approval
    public let reason: String
    public let policy: String
    public var allowed: Bool { verdict == "allow" }
}

private struct AgentCfg {
    let capabilities: [NSRegularExpression], denyTargets: [NSRegularExpression]
    let allowTargets: [NSRegularExpression], requireApproval: [NSRegularExpression]
    let rateMax: Int?, rateWindowS: Int?, budget: Double?
}

private extension NSRegularExpression {
    func matches(_ s: String) -> Bool {
        firstMatch(in: s, range: NSRange(s.startIndex..., in: s)).map { $0.range.length == s.utf16.count && $0.range.location == 0 } ?? false
    }
    func contains(_ s: String) -> Bool { firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil }
}

/// Deny-by-default policy engine for AI agents, loaded from policy.json (mobile/export_policy.py). Thread-safe.
public final class Guardrail {
    public var killSwitch: Bool
    private let forbidden: [(String, NSRegularExpression)]
    private let defaults: AgentCfg
    private let agents: [(NSRegularExpression, AgentCfg)]
    private var rate: [String: [TimeInterval]] = [:]
    private var spent: [String: Double] = [:]
    private let lock = NSLock()

    public init(policyJSON: Data) throws {
        let doc = try JSONSerialization.jsonObject(with: policyJSON) as! [String: Any]
        killSwitch = doc["killSwitch"] as? Bool ?? false
        forbidden = try (doc["forbidden"] as! [[String: Any]]).map {
            ($0["name"] as! String, try NSRegularExpression(pattern: $0["regex"] as! String, options: [.caseInsensitive]))
        }
        defaults = try Guardrail.parseCfg(doc["defaults"] as! [String: Any])
        agents = try (doc["agents"] as! [[String: Any]]).map {
            (try NSRegularExpression(pattern: $0["match"] as! String), try Guardrail.parseCfg($0["config"] as! [String: Any]))
        }
    }

    private static func rx(_ a: Any?) throws -> [NSRegularExpression] {
        try (a as? [String] ?? []).map { try NSRegularExpression(pattern: $0) }
    }
    private static func parseCfg(_ o: [String: Any]) throws -> AgentCfg {
        let rl = o["rateLimit"] as? [String: Any]
        return AgentCfg(capabilities: try rx(o["capabilities"]), denyTargets: try rx(o["denyTargets"]),
                        allowTargets: try rx(o["allowTargets"]), requireApproval: try rx(o["requireApproval"]),
                        rateMax: rl?["max"] as? Int, rateWindowS: rl?["window_s"] as? Int, budget: o["budget"] as? Double)
    }
    private func cfg(for agent: String) -> AgentCfg { agents.first { $0.0.matches(agent) }?.1 ?? defaults }

    private func rateOK(_ agent: String, max: Int, window: Int) -> Bool {
        let now = Date().timeIntervalSince1970
        var q = (rate[agent] ?? []).filter { now - $0 <= Double(window) }
        if q.count >= max { rate[agent] = q; return false }
        q.append(now); rate[agent] = q; return true
    }

    /// Normalise like sentinel/platform.py: forward slashes, case-folded (mobile always folds).
    public func norm(_ p: String) -> String { p.replacingOccurrences(of: "\\", with: "/").lowercased() }

    public func decide(agent: String, action: String, target rawTarget: String = "", cost: Double = 0) -> Decision {
        lock.lock(); defer { lock.unlock() }
        let target = norm(rawTarget), c = cfg(for: agent), blob = "\(action) \(target)"
        if killSwitch { return Decision(verdict: "deny", reason: "global kill switch engaged", policy: "kill_switch") }
        for (name, rx) in forbidden where rx.contains(blob) {
            return Decision(verdict: "deny", reason: "matches forbidden pattern '\(name)'", policy: "forbidden_patterns")
        }
        if !c.capabilities.contains(where: { $0.matches(action) }) {
            return Decision(verdict: "deny", reason: "'\(action)' outside capabilities", policy: "capabilities")
        }
        if c.denyTargets.contains(where: { $0.matches(target) }) {
            return Decision(verdict: "deny", reason: "target '\(target)' is in deny_targets", policy: "deny_targets")
        }
        if !c.allowTargets.isEmpty && !target.isEmpty && !c.allowTargets.contains(where: { $0.matches(target) }) {
            return Decision(verdict: "deny", reason: "target '\(target)' not in allow_targets", policy: "allow_targets")
        }
        if let m = c.rateMax, !rateOK(agent, max: m, window: c.rateWindowS ?? 60) {
            return Decision(verdict: "deny", reason: "rate limit exceeded", policy: "rate_limit")
        }
        if let b = c.budget, (spent[agent] ?? 0) + cost > b {
            return Decision(verdict: "deny", reason: "budget \(b) exhausted", policy: "budget")
        }
        spent[agent, default: 0] += cost
        if c.requireApproval.contains(where: { $0.matches(action) || $0.matches(target) }) {
            return Decision(verdict: "require_approval", reason: "'\(action)' on '\(target)' needs a human", policy: "require_approval")
        }
        return Decision(verdict: "allow", reason: "within policy", policy: "")
    }
}
