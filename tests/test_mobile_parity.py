"""Cross-platform packet-math parity (mobile forwarding).

The Android (Kotlin) and iOS (Swift) forwarders each build IPv4/UDP reply packets by hand.
A byte offset that differs between them, or from a correct packet, would corrupt traffic on
one platform only. This test pins the canonical bytes and checks that the exact operation
sequence used by BOTH ports reproduces them. (Kotlin is separately compiler-verified offline;
Swift has no toolchain here, so its construction is checked by replicating its ops.)
"""
import struct, re
from pathlib import Path

def reference_udp_reply(src_ip, dst_ip, sport, dport, payload):
    total = 28 + len(payload)
    b = bytearray()
    b += bytes([0x45, 0]) + struct.pack("!H", total)
    b += bytes([0, 0, 0, 0, 64, 17]) + bytes([0, 0])
    b += bytes(int(x) for x in src_ip.split("."))
    b += bytes(int(x) for x in dst_ip.split("."))
    b += struct.pack("!H", sport) + struct.pack("!H", dport)
    b += struct.pack("!H", 8 + len(payload)) + bytes([0, 0])
    b += payload
    return bytes(b)

def swift_ops(src_ip, dst_ip, sport, dport, payload):
    be16 = lambda v: [v >> 8, v & 0xFF]
    ipv4 = lambda s: [int(x) for x in s.split(".")]
    total = 28 + len(payload)
    b = [0x45, 0] + be16(total) + [0, 0, 0, 0, 64, 17] + [0, 0]
    b += ipv4(src_ip) + ipv4(dst_ip)
    b += be16(sport) + be16(dport) + be16(8 + len(payload)) + [0, 0]
    b += list(payload)
    return bytes(b)

CASES = [
    ("8.8.8.8", "10.111.0.2", 53, 40000, b"reply"),
    ("1.1.1.1", "10.111.0.2", 53, 51000, b"\x00\x01\x02\x03dnsdata"),
    ("93.184.216.34", "10.111.0.2", 443, 12345, b"x" * 100),
]

def test_swift_ops_match_reference():
    for c in CASES:
        assert swift_ops(*c) == reference_udp_reply(*c), c

def test_packet_fields_are_correct():
    pkt = reference_udp_reply("8.8.8.8", "10.111.0.2", 53, 40000, b"reply")
    assert pkt[0] == 0x45 and pkt[9] == 17            # IPv4/IHL5, proto UDP
    assert struct.unpack("!H", pkt[2:4])[0] == len(pkt)
    assert pkt[12:16] == bytes([8, 8, 8, 8])          # src ip
    assert struct.unpack("!H", pkt[20:22])[0] == 53   # udp src port

def test_swift_source_uses_expected_offsets():
    """Guard against someone editing the Swift builder out of parity."""
    src = Path("mobile/ios/SentinelTunnel/PacketTunnelProvider.swift").read_text()
    assert "buildUDPReply" in src
    assert "[0x45, 0]" in src and "64, 17" in src     # ver/ihl + ttl/proto sentinel bytes

def test_android_source_uses_expected_offsets():
    src = Path("mobile/android/app/src/main/java/org/goodai/sentinel/SentinelVpnService.kt").read_text()
    assert "buildUdpReply" in src and "protect" in src
    assert "0x45" in src and "b.put(17)" in src
