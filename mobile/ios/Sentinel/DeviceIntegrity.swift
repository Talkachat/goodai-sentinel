import Foundation
import DeviceCheck
import CryptoKit

/// Local jailbreak signals plus App Attest for a server-verifiable device/app integrity verdict.
public enum DeviceIntegrity {
    static let markers = ["/Applications/Cydia.app", "/Applications/Sileo.app", "/Library/MobileSubstrate/MobileSubstrate.dylib",
                          "/usr/sbin/sshd", "/bin/bash", "/private/var/lib/apt", "/usr/libexec/frida-server"]
    public static func jailbroken() -> Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        if markers.contains(where: { FileManager.default.fileExists(atPath: $0) }) { return true }
        do { try "x".write(toFile: "/private/sentinel_probe", atomically: true, encoding: .utf8)
             try FileManager.default.removeItem(atPath: "/private/sentinel_probe"); return true } catch { return false }
        #endif
    }
    public static func findings() -> [String] { jailbroken() ? ["device_jailbroken"] : [] }
    /// Ask Apple to attest this app instance; send the result to your Sentinel coordinator to verify.
    public static func attest(challenge: Data, completion: @escaping (Result<(keyId: String, attestation: Data), Error>) -> Void) {
        let svc = DCAppAttestService.shared
        guard svc.isSupported else { return completion(.failure(NSError(domain: "Sentinel", code: 1))) }
        svc.generateKey { keyId, err in
            guard let keyId = keyId else { return completion(.failure(err!)) }
            svc.attestKey(keyId, clientDataHash: Data(SHA256.hash(data: challenge))) { att, err in
                att.map { completion(.success((keyId, $0))) } ?? completion(.failure(err!))
            }
        }
    }
}

