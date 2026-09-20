import NetworkExtension
import Network

/// Host-level network sentinel for iOS WITHOUT jailbreak or MDM: a local packet-tunnel VPN that all
/// apps' traffic passes through. It can see destination IP/port for every flow, drop flows to blocked
/// destinations / known C2 ports, and report findings to the containing app via App Group storage.
///
/// Requires the "Network Extensions" entitlement (packet-tunnel-provider) and user consent when the
/// profile is installed. Cannot attribute flows to apps (iOS never exposes that); NEFilterDataProvider
/// can, but only on supervised/MDM devices. Full forwarding needs a userspace stack (e.g. tun2socks);
/// the skeleton implements the policy + drop path.
class PacketTunnelProvider: NEPacketTunnelProvider {
    static let blockedPorts: Set<UInt16> = [4444, 1337, 31337, 6667, 9001, 5555]
    var blockedIPs = Set<String>()          // fed by coordinator through App Group UserDefaults
    let group = UserDefaults(suiteName: "group.org.goodai.sentinel")

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.111.0.1")
        settings.ipv4Settings = NEIPv4Settings(addresses: ["10.111.0.2"], subnetMasks: ["255.255.255.255"])
        settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
        settings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1"])
        settings.mtu = 1500
        blockedIPs = Set(group?.stringArray(forKey: "blockedIPs") ?? [])
        setTunnelNetworkSettings(settings) { err in
            if err == nil { Forwarder.shared.flow = self.packetFlow; self.startReaper(); self.readLoop() }
            completionHandler(err)
        }
    }

    private func readLoop() {
        packetFlow.readPackets { packets, protocols in
            for (pkt, proto) in zip(packets, protocols) where proto.int32Value == AF_INET {
                guard let p = IPv4Packet(pkt) else { continue }
                if self.blockedIPs.contains(p.dst) { self.report("blocked_destination", "high", p, "coordinator blocklist"); continue }
                if Self.blockedPorts.contains(p.dstPort) { self.report("c2_port", "high", p, "known backdoor port"); continue }
                if p.proto == 17 && p.dstPort == 53 && p.payloadLen > 512 { self.report("dns_tunnel", "medium", p, "oversized DNS query"); continue }
                Forwarder.shared.send(pkt, p)      // allowed
            }
            self.readLoop()
        }
    }

    private func report(_ rule: String, _ sev: String, _ p: IPv4Packet, _ why: String) {
        var log = group?.array(forKey: "findings") as? [[String: Any]] ?? []
        log.append(["ts": Date().timeIntervalSince1970, "rule": rule, "severity": sev, "dst": p.dst, "port": Int(p.dstPort), "reason": why])
        group?.set(Array(log.suffix(500)), forKey: "findings")
    }

    private func startReaper() {
        DispatchQueue.global().asyncAfter(deadline: .now() + 10) { [weak self] in
            guard self != nil else { return }
            Forwarder.shared.reapIdle(); self?.startReaper()
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) { completionHandler() }
}

/// Minimal IPv4 header parse; enough for policy decisions.
struct IPv4Packet {
    let proto: UInt8
    let src: String, dst: String
    let srcPort: UInt16, dstPort: UInt16
    let ihl: Int
    let raw: Data
    var payload: Data { raw.subdata(in: (ihl + (proto == 17 ? 8 : dataOffsetTCP())) ..< raw.count) }
    var udpPayload: Data { raw.subdata(in: (ihl + 8) ..< raw.count) }
    init?(_ d: Data) {
        guard d.count >= 24, d[0] >> 4 == 4 else { return nil }
        let h = Int(d[0] & 0x0F) * 4; proto = d[9]; ihl = h; raw = d
        guard proto == 6 || proto == 17, d.count >= h + 4 else { return nil }
        src = "\(d[12]).\(d[13]).\(d[14]).\(d[15])"
        dst = "\(d[16]).\(d[17]).\(d[18]).\(d[19])"
        srcPort = UInt16(d[h])     << 8 | UInt16(d[h + 1])
        dstPort = UInt16(d[h + 2]) << 8 | UInt16(d[h + 3])
    }
    private func dataOffsetTCP() -> Int { Int((raw[ihl + 12] >> 4)) * 4 }
    var payloadLen: Int { raw.count - ihl }
}

/// Forwards allowed packets out via Network.framework and writes replies back into the TUN.
///
/// UDP (incl. DNS) is fully implemented: one NWConnection per 5-tuple, replies rebuilt as
/// IPv4/UDP packets addressed back to the app. Idle connections are reaped. TCP is delegated to
/// an optional userspace stack (`tcpStack`); with none installed it is dropped-closed (fail safe),
/// never silently blackholed. Network.framework sockets do not route back through our own tunnel,
/// so no protect() equivalent is needed on iOS.
import Network
final class Forwarder {
    static let shared = Forwarder()
    weak var flow: NEPacketTunnelFlow?          // set by the provider to write replies back
    var tcpStack: ((IPv4Packet, @escaping (Data) -> Void) -> Void)?
    private var udp = [String: (conn: NWConnection, last: Date)]()
    private let q = DispatchQueue(label: "sentinel.forwarder")

    func send(_ raw: Data, _ p: IPv4Packet) {
        switch p.proto {
        case 17: forwardUDP(p)
        case 6:  tcpStack?(p) { [weak self] in self?.writeBack($0) }
                 ?? NSLog("Sentinel: TCP dropped (no stack) -> \(p.dst):\(p.dstPort)")
        default: break
        }
    }

    private func key(_ p: IPv4Packet) -> String { "\(p.src):\(p.srcPort)>\(p.dst):\(p.dstPort)" }

    private func forwardUDP(_ p: IPv4Packet) {
        q.sync {
            let k = key(p)
            let conn: NWConnection
            if let existing = udp[k] { conn = existing.conn } else {
                conn = NWConnection(host: .init(p.dst), port: .init(rawValue: p.dstPort)!, using: .udp)
                conn.start(queue: q)
                receiveLoop(conn, req: p, k: k)
                udp[k] = (conn, Date())
            }
            udp[k]?.last = Date()
            conn.send(content: p.udpPayload, completion: .contentProcessed { _ in })
        }
    }

    private func receiveLoop(_ conn: NWConnection, req: IPv4Packet, k: String) {
        conn.receiveMessage { [weak self] data, _, _, err in
            guard let self = self else { return }
            if let data = data, !data.isEmpty {
                self.writeBack(PacketMath.buildUDPReply(srcIP: req.dst, dstIP: req.src,
                                                        srcPort: req.dstPort, dstPort: req.srcPort, payload: data))
                self.q.async { self.udp[k]?.last = Date() }
            }
            if err == nil { self.receiveLoop(conn, req: req, k: k) }
            else { conn.cancel(); self.q.async { self.udp[k] = nil } }
        }
    }

    private func writeBack(_ pkt: Data) {
        flow?.writePackets([pkt], withProtocols: [NSNumber(value: AF_INET)])
    }

    func reapIdle() {
        q.async {
            let cutoff = Date().addingTimeInterval(-30)
            for (k, v) in self.udp where v.last < cutoff { v.conn.cancel(); self.udp[k] = nil }
        }
    }
}


/// Framework-free packet construction (mirrors Android Forwarder.buildUdpReply). Unit-tested offline.
enum PacketMath {
    static func ipv4(_ s: String) -> [UInt8] { s.split(separator: ".").map { UInt8($0) ?? 0 } }
    static func buildUDPReply(srcIP: String, dstIP: String, srcPort: UInt16, dstPort: UInt16, payload: Data) -> Data {
        let total = 28 + payload.count
        var b = [UInt8](); b.reserveCapacity(total)
        b += [0x45, 0]; b += be16(UInt16(total)); b += [0,0,0,0, 64, 17]; b += [0,0]   // ttl, proto=UDP, csum=0
        b += ipv4(srcIP); b += ipv4(dstIP)
        b += be16(srcPort); b += be16(dstPort); b += be16(UInt16(8 + payload.count)); b += [0,0]
        b += [UInt8](payload)
        return Data(b)
    }
    static func be16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xFF)] }
}