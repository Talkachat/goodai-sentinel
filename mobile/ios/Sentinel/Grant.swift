import Foundation
import CryptoKit

/// Hot-path capability token: one guardrail decision, then local validate() in a loop. Mirrors sentinel/tokens.py.
public final class Grant {
    public let token: String, agentId: String, expires: TimeInterval
    private let action: NSRegularExpression, target: NSRegularExpression?
    private var remaining: Int
    fileprivate var revoked = false
    private let lock = NSLock()
    public var left: Int { lock.lock(); defer { lock.unlock() }; return remaining }

    init(token: String, agentId: String, action: NSRegularExpression, target: NSRegularExpression?, count: Int, expires: TimeInterval) {
        self.token = token; self.agentId = agentId; self.action = action; self.target = target; self.remaining = count; self.expires = expires
    }
    private func full(_ rx: NSRegularExpression, _ s: String) -> Bool {
        rx.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)).map { $0.range.location == 0 && $0.range.length == s.utf16.count } ?? false
    }
    public func validate(action: String? = nil, target: String? = nil) -> Bool {
        if revoked || Date().timeIntervalSince1970 > expires { return false }
        if let a = action, !full(self.action, a) { return false }
        if let t = target, let trx = self.target, !full(trx, t.replacingOccurrences(of: "\\", with: "/").lowercased()) { return false }
        lock.lock(); defer { lock.unlock() }
        if remaining <= 0 { return false }
        remaining -= 1; return true
    }
    fileprivate func kill() { lock.lock(); revoked = true; remaining = 0; lock.unlock() }
}

public final class TokenIssuer {
    private let guardrail: Guardrail, key: SymmetricKey
    private var live: [String: Grant] = [:]
    private let lock = NSLock()

    public init(guardrail: Guardrail, secret: Data) { self.guardrail = guardrail; key = SymmetricKey(data: secret) }

    private func glob(_ g: String) throws -> NSRegularExpression {
        let parts = g.replacingOccurrences(of: "\\", with: "/").lowercased().split(separator: "*", omittingEmptySubsequences: false)
        return try NSRegularExpression(pattern: "^" + parts.map { NSRegularExpression.escapedPattern(for: String($0)) }.joined(separator: ".*") + "$")
    }
    private func sign(_ body: String) -> String {
        HMAC<SHA256>.authenticationCode(for: Data(body.utf8), using: key).map { String(format: "%02x", $0) }.joined().prefix(32).description
    }

    /// novelty in 0...1 shrinks the grant (count and ttl) like the Python issuer.
    public func grant(agent: String, action: String, target: String = "", count: Int = 1000, ttl: Double = 60,
                      novelty: Double = 0, cost: Double = 0) throws -> (Decision, Grant?) {
        let d = guardrail.decide(agent: agent, action: action, target: target, cost: cost)
        if !d.allowed { return (d, nil) }
        let scale = max(0.05, 1 - novelty)
        let n = max(1, Int((Double(count) * scale).rounded())), t = max(1, ttl * scale)
        let exp = Date().timeIntervalSince1970 + t
        let id = UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(16).description
        let payload: [String: Any] = ["id": id, "agent": agent, "action": action, "target": target, "n": n, "exp": exp]
        let body = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]).base64EncodedString()
        let g = Grant(token: "\(body).\(sign(body))", agentId: agent, action: try glob(action),
                      target: target.isEmpty ? nil : try glob(target), count: n, expires: exp)
        lock.lock(); live[id] = g; lock.unlock()
        return (d, g)
    }
    public func revoke(agent: String? = nil, tokenId: String? = nil) {
        lock.lock(); defer { lock.unlock() }
        for (id, g) in live where id == tokenId || (agent != nil && g.agentId == agent) { g.kill(); live[id] = nil }
    }
}
