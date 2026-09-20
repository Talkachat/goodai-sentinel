# Sentinel on iOS and Android

Neither OS lets a third-party app see other apps' processes, files, or sockets, so the desktop host monitor cannot be ported. Here is what **is** possible without root or jailbreak, and what this folder ships.

## What works on mobile

| Layer | Android | iOS | Shipped here |
|---|---|---|---|
| AI-agent guardrail (`decide`) — the "ask before you act" API | ✔ full parity | ✔ full parity | `Guardrail.kt`, `Guardrail.swift` |
| Capability grants for hot paths (`grant` / `validate`) | ✔ | ✔ | `Grant.kt`, `Grant.swift` |
| Network sentinel: see and block every outbound flow (all apps) | ✔ `VpnService` | ✔ `NEPacketTunnelProvider` | `SentinelVpnService.kt`, `PacketTunnelProvider.swift` |
| Attribute a flow to the app that made it | ✔ Android 10+ (`getConnectionOwnerUid`) | ✖ (only via `NEFilterDataProvider` on supervised/MDM devices) | Kotlin only |
| Device-integrity signals (root/jailbreak, debugger) + server-verifiable attestation | ✔ + Play Integrity API | ✔ + App Attest | `DeviceIntegrity.kt/.swift` |
| Process monitoring, other apps' file integrity | ✖ | ✖ | — |
| Freeze/terminate another app | ✖ (only Device Owner / MDM) | ✖ | — |

Forwarding status (enhancement #4, honest breakdown):
- **Android UDP (incl. DNS): implemented.** `Forwarder` opens a `protect()`ed `DatagramChannel`
  per flow, forwards the payload, and pumps replies back as synthetic IPv4/UDP packets, with an
  idle-flow reaper. The packet-building math is unit-tested offline (compiled with kotlinc).
- **Android TCP: delegated, fail-safe.** Correct userspace TCP (handshake, retransmit, windowing)
  is out of scope; wire a native stack via the `Forwarder.TcpStack` interface (lwIP / tun2socks).
  With no stack installed, TCP is dropped-closed, never silently blackholed.
- **iOS: skeleton.** `NEPacketTunnelProvider` sees and drops flows; forwarding is not implemented.
- Not device-tested. The Android-framework glue (`VpnService`, `ParcelFileDescriptor`) cannot be
  compiled offline; only the framework-free packet logic is verified here.

## Policy is shared, not re-implemented

`python -m mobile.export_policy` turns `policy/agent_guardrails.yaml` into `policy.json` (globs pre-compiled to regexes, so no fnmatch on mobile) and `conformance.json`, 15 cases with the verdict the Python engine gives. Every port must pass them.

- **Kotlin:** compiled with kotlinc 2.1 and run against the conformance file — 15/15 pass.
- **Swift:** mirrors the verified Kotlin line-for-line but has not been compiled here (no Xcode in this environment). Run the conformance file in an XCTest before shipping.

Evaluation order is identical everywhere: kill switch → forbidden patterns → capabilities → deny targets → allow targets → rate limit → budget → approval gates → allow. Mobile always normalises targets (forward slashes, case-folded).

## Using it in an app

```kotlin
val g = Guardrail(assets.open("policy.json").bufferedReader().readText())
val d = g.decide("assistant-1", "send:message", "contacts/mom")      // -> require_approval
val issuer = TokenIssuer(g, secretFromKeystore)
val (dec, grant) = issuer.grant("assistant-1", "read:calendar", "calendar/*", count = 500)
```

```swift
let g = try Guardrail(policyJSON: Data(contentsOf: Bundle.main.url(forResource: "policy", withExtension: "json")!))
let d = g.decide(agent: "assistant-1", action: "send:message", target: "contacts/mom")
```

Keep the HMAC secret in Android Keystore / iOS Keychain; ship `policy.json` inside the app bundle (read-only) and update it only through signed releases or a signed download from your coordinator.

## Permissions and store review
- **Android:** `BIND_VPN_SERVICE`; the user must accept the VPN consent dialog. Google Play requires a VPN-policy declaration for apps using `VpnService`.
- **iOS:** `com.apple.developer.networking.networkextension` (packet-tunnel-provider) entitlement; the tunnel lives in a Network Extension target and shares findings with the app through an App Group.
- Both stores reject apps that "scan other apps"; describe the feature as network protection, which is what it is.
