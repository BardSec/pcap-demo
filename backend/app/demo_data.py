"""
Demo mode seed data.

Creates a demo user and 5 pre-analyzed sample captures so the app can be
explored without uploading real PCAP files or logging in.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta

from sqlalchemy.orm import Session

from app.database import engine
from app.models import Capture, User

logger = logging.getLogger(__name__)

DEMO_USER_EMAIL = "demo@pcap-demo.local"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _beacon_intervals(mean: float, std: float, count: int) -> list[float]:
    """Generate pseudo-regular beacon intervals around a mean."""
    import random
    random.seed(42)
    intervals = []
    t = 0.0
    for _ in range(count):
        t += max(1.0, random.gauss(mean, std))
        intervals.append(round(t, 2))
    return intervals


# ---------------------------------------------------------------------------
# Pre-built analysis results for each scenario
# ---------------------------------------------------------------------------

def _results_cobalt_strike() -> dict:
    intervals = _beacon_intervals(60.2, 4.8, 44)
    return {
        "c2_beaconing": [
            {
                "src_ip": "10.10.5.22",
                "dst_ip": "185.220.101.72",
                "dst_port": 443,
                "protocol": "TCP",
                "cv": 0.08,
                "mean_interval_sec": 60.2,
                "std_interval_sec": 4.8,
                "connection_count": 45,
                "severity": "CRITICAL",
                "interval_series": intervals,
                "rel_timestamps": intervals,
                "beacon_period_display": "1.0m",
            }
        ],
        "dns_tunneling": {"tunnel_domains": [], "suspicious_queries": []},
        "ntlm_hashes": [
            {
                "type": "AUTHENTICATE",
                "username": "jsmith",
                "domain": "CORP",
                "workstation": "DESKTOP-A4F2",
                "server_challenge": "a3f1c2d4e5b6a7f8",
                "nt_response": "8c3d1a2b4e5f6789abcdef0123456789aabbccdd00112233",
                "hashcat_hash": "jsmith::CORP:a3f1c2d4e5b6a7f8:8c3d1a2b4e5f6789abcdef01:0101000000000000abcdef012345678900000000",
                "severity": "CRITICAL",
            },
            {
                "type": "AUTHENTICATE",
                "username": "adm.baker",
                "domain": "CORP",
                "workstation": "DESKTOP-A4F2",
                "server_challenge": "b4e2d3c5f6a7b8c9",
                "nt_response": "9d4e2b3c5f6a7890bcdef1234567890bbccddeeff001122",
                "hashcat_hash": "adm.baker::CORP:b4e2d3c5f6a7b8c9:9d4e2b3c5f6a7890bcdef123:0101000000000000bcdef0123456789000000000",
                "severity": "CRITICAL",
            },
            {
                "type": "AUTHENTICATE",
                "username": "svc_backup",
                "domain": "CORP",
                "workstation": "SRV-BACKUP01",
                "server_challenge": "c5f3e4d6a7b8c9d0",
                "nt_response": "ae5f3c4d6a7b8901cdef23456789012ccddee0011223344",
                "hashcat_hash": "svc_backup::CORP:c5f3e4d6a7b8c9d0:ae5f3c4d6a7b8901cdef2345:0101000000000000cdef01234567890000000000",
                "severity": "CRITICAL",
            },
        ],
        "cleartext_credentials": [],
        "exfiltration": [],
        "connection_failures": {
            "rst_flows": [
                {"src_ip": "10.10.5.22", "dst_ip": "185.220.101.72", "dst_port": 8080, "count": 3},
            ],
            "icmp_unreachable": [],
            "blocked_destinations": [{"ip": "185.220.101.72", "port": 8080, "rst_count": 3}],
        },
        "dns_health": {"timeouts": [], "nxdomains": [], "slow_responses": []},
        "tls_inspection": {"issues": [], "self_signed": [], "expired": [], "alerts": []},
        "traffic_timeline": {
            "conversations": [
                {"src": "10.10.5.22", "dst": "185.220.101.72", "port": 443, "packets": 2160, "bytes": 483210},
                {"src": "10.10.5.22", "dst": "8.8.8.8", "port": 53, "packets": 420, "bytes": 38640},
                {"src": "10.10.5.22", "dst": "10.10.0.1", "port": 445, "packets": 318, "bytes": 71200},
            ],
        },
        "packet_count": 45231,
        "summary": {
            "c2_beacon_count": 1,
            "dns_tunnel_domain_count": 0,
            "ntlm_hash_count": 3,
            "cleartext_cred_count": 0,
            "exfil_flow_count": 0,
            "blocked_dest_count": 1,
            "dns_failure_count": 0,
            "tls_issue_count": 0,
            "conversation_count": 3,
        },
    }


def _results_dns_exfil() -> dict:
    intervals = _beacon_intervals(300.5, 12.3, 18)
    return {
        "c2_beaconing": [
            {
                "src_ip": "192.168.1.45",
                "dst_ip": "104.21.56.99",
                "dst_port": 53,
                "protocol": "UDP",
                "cv": 0.04,
                "mean_interval_sec": 300.5,
                "std_interval_sec": 12.3,
                "connection_count": 19,
                "severity": "CRITICAL",
                "interval_series": intervals,
                "rel_timestamps": intervals,
                "beacon_period_display": "5.0m",
            }
        ],
        "dns_tunneling": {
            "tunnel_domains": [
                {
                    "domain": "c2tunnel.dnsexfil.net",
                    "query_count": 847,
                    "max_entropy": 4.91,
                    "avg_label_length": 58,
                    "suspicious_record_types": ["TXT", "NULL"],
                    "estimated_exfil_bytes": 218430,
                    "severity": "CRITICAL",
                },
                {
                    "domain": "data.xfil-pipe.io",
                    "query_count": 312,
                    "max_entropy": 4.62,
                    "avg_label_length": 52,
                    "suspicious_record_types": ["TXT"],
                    "estimated_exfil_bytes": 80640,
                    "severity": "HIGH",
                },
            ],
            "suspicious_queries": [
                {"name": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.c2tunnel.dnsexfil.net", "entropy": 4.91, "record_type": "TXT"},
                {"name": "dGhpcyBpcyBhbm90aGVyIHRlc3QgcGFja2V0.c2tunnel.dnsexfil.net", "entropy": 4.88, "record_type": "NULL"},
                {"name": "ZXhhbXBsZSBleGZpbCBkYXRhIGhlcmU.data.xfil-pipe.io", "entropy": 4.62, "record_type": "TXT"},
            ],
        },
        "ntlm_hashes": [],
        "cleartext_credentials": [],
        "exfiltration": [
            {
                "src_ip": "192.168.1.45",
                "dst_ip": "104.21.56.99",
                "dst_port": 53,
                "outbound_bytes": 299070,
                "inbound_bytes": 18240,
                "asymmetry_ratio": 16.4,
                "bandwidth_bps": 6840,
                "duration_sec": 349.8,
                "severity": "CRITICAL",
                "bar_data": {"outbound_mb": 0.29, "inbound_mb": 0.02},
            }
        ],
        "connection_failures": {"rst_flows": [], "icmp_unreachable": [], "blocked_destinations": []},
        "dns_health": {
            "timeouts": [{"query": "c2tunnel.dnsexfil.net", "count": 4}],
            "nxdomains": [],
            "slow_responses": [],
        },
        "tls_inspection": {"issues": [], "self_signed": [], "expired": [], "alerts": []},
        "traffic_timeline": {
            "conversations": [
                {"src": "192.168.1.45", "dst": "104.21.56.99", "port": 53, "packets": 1159, "bytes": 317310},
                {"src": "192.168.1.45", "dst": "8.8.8.8", "port": 53, "packets": 88, "bytes": 9240},
            ],
        },
        "packet_count": 12847,
        "summary": {
            "c2_beacon_count": 1,
            "dns_tunnel_domain_count": 2,
            "ntlm_hash_count": 0,
            "cleartext_cred_count": 0,
            "exfil_flow_count": 1,
            "blocked_dest_count": 0,
            "dns_failure_count": 4,
            "tls_issue_count": 0,
            "conversation_count": 2,
        },
    }


def _results_cleartext_creds() -> dict:
    return {
        "c2_beaconing": [],
        "dns_tunneling": {"tunnel_domains": [], "suspicious_queries": []},
        "ntlm_hashes": [],
        "cleartext_credentials": [
            {
                "type": "FTP",
                "protocol": "FTP",
                "src_ip": "10.0.1.14",
                "dst_ip": "10.0.1.5",
                "dst_port": 21,
                "username": "ftpadmin",
                "password_masked": "Pa****23",
                "timestamp": 1710000120.4,
                "severity": "CRITICAL",
            },
            {
                "type": "FTP",
                "protocol": "FTP",
                "src_ip": "10.0.1.14",
                "dst_ip": "10.0.1.5",
                "dst_port": 21,
                "username": "backup_svc",
                "password_masked": "ba****01",
                "timestamp": 1710000184.1,
                "severity": "CRITICAL",
            },
            {
                "type": "FTP",
                "protocol": "FTP",
                "src_ip": "10.0.1.22",
                "dst_ip": "10.0.1.5",
                "dst_port": 21,
                "username": "reports",
                "password_masked": "re****rt",
                "timestamp": 1710000310.8,
                "severity": "CRITICAL",
            },
            {
                "type": "FTP",
                "protocol": "FTP",
                "src_ip": "10.0.1.31",
                "dst_ip": "10.0.1.5",
                "dst_port": 21,
                "username": "jdoe",
                "password_masked": "su****er",
                "timestamp": 1710000512.2,
                "severity": "CRITICAL",
            },
            {
                "type": "FTP",
                "protocol": "FTP",
                "src_ip": "10.0.1.44",
                "dst_ip": "10.0.1.5",
                "dst_port": 21,
                "username": "guest",
                "password_masked": "gu****23",
                "timestamp": 1710000698.5,
                "severity": "CRITICAL",
            },
            {
                "type": "HTTP_BASIC_AUTH",
                "protocol": "HTTP",
                "src_ip": "10.0.1.14",
                "dst_ip": "10.0.2.10",
                "dst_port": 80,
                "username": "admin",
                "password_masked": "ad****23",
                "timestamp": 1710001002.9,
                "severity": "HIGH",
            },
            {
                "type": "HTTP_BASIC_AUTH",
                "protocol": "HTTP",
                "src_ip": "10.0.1.22",
                "dst_ip": "10.0.2.10",
                "dst_port": 80,
                "username": "monitor",
                "password_masked": "mo****or",
                "timestamp": 1710001187.3,
                "severity": "HIGH",
            },
        ],
        "exfiltration": [],
        "connection_failures": {
            "rst_flows": [
                {"src_ip": "10.0.1.14", "dst_ip": "10.0.1.5", "dst_port": 22, "count": 8},
                {"src_ip": "10.0.1.22", "dst_ip": "10.0.1.5", "dst_port": 22, "count": 5},
            ],
            "icmp_unreachable": [
                {"src_ip": "10.0.1.5", "dst_ip": "10.0.1.14", "type": 3, "code": 3, "count": 2},
            ],
            "blocked_destinations": [
                {"ip": "10.0.1.5", "port": 22, "rst_count": 13},
            ],
        },
        "dns_health": {"timeouts": [], "nxdomains": [], "slow_responses": []},
        "tls_inspection": {"issues": [], "self_signed": [], "expired": [], "alerts": []},
        "traffic_timeline": {
            "conversations": [
                {"src": "10.0.1.14", "dst": "10.0.1.5", "port": 21, "packets": 842, "bytes": 120400},
                {"src": "10.0.1.22", "dst": "10.0.1.5", "port": 21, "packets": 610, "bytes": 88200},
                {"src": "10.0.1.31", "dst": "10.0.1.5", "port": 21, "packets": 398, "bytes": 57300},
                {"src": "10.0.1.14", "dst": "10.0.2.10", "port": 80, "packets": 215, "bytes": 31800},
            ],
        },
        "packet_count": 8512,
        "summary": {
            "c2_beacon_count": 0,
            "dns_tunnel_domain_count": 0,
            "ntlm_hash_count": 0,
            "cleartext_cred_count": 7,
            "exfil_flow_count": 0,
            "blocked_dest_count": 1,
            "dns_failure_count": 0,
            "tls_issue_count": 0,
            "conversation_count": 4,
        },
    }


def _results_lateral_movement() -> dict:
    intervals_c2 = _beacon_intervals(120.8, 22.4, 28)
    return {
        "c2_beaconing": [
            {
                "src_ip": "10.1.2.55",
                "dst_ip": "198.51.100.42",
                "dst_port": 4444,
                "protocol": "TCP",
                "cv": 0.19,
                "mean_interval_sec": 120.8,
                "std_interval_sec": 22.4,
                "connection_count": 29,
                "severity": "HIGH",
                "interval_series": intervals_c2,
                "rel_timestamps": intervals_c2,
                "beacon_period_display": "2.0m",
            }
        ],
        "dns_tunneling": {"tunnel_domains": [], "suspicious_queries": []},
        "ntlm_hashes": [
            {
                "type": "AUTHENTICATE",
                "username": "mwilson",
                "domain": "ENTERPRISE",
                "workstation": "WS-MWILSON",
                "server_challenge": "d6a4f5e7b8c9d0e1",
                "nt_response": "bf6a4f5e7b8c9d0e1f234567890abcde11223344aabb",
                "hashcat_hash": "mwilson::ENTERPRISE:d6a4f5e7b8c9d0e1:bf6a4f5e7b8c9d0e1f234567:0101000000000000d6a4f5e7b8c9d0e100000000",
                "severity": "CRITICAL",
            },
            {
                "type": "AUTHENTICATE",
                "username": "mwilson",
                "domain": "ENTERPRISE",
                "workstation": "SRV-FS01",
                "server_challenge": "e7b5a6f8c9d0e1f2",
                "nt_response": "c07b5a6f8c9d0e1f2345678901abcdef2233445566bb",
                "hashcat_hash": "mwilson::ENTERPRISE:e7b5a6f8c9d0e1f2:c07b5a6f8c9d0e1f23456789:0101000000000000e7b5a6f8c9d0e1f200000000",
                "severity": "CRITICAL",
            },
            {
                "type": "AUTHENTICATE",
                "username": "mwilson",
                "domain": "ENTERPRISE",
                "workstation": "SRV-DC01",
                "server_challenge": "f8c6b7a9d0e1f203",
                "nt_response": "d18c6b7a9d0e1f20345678902abcdef0334455667788",
                "hashcat_hash": "mwilson::ENTERPRISE:f8c6b7a9d0e1f203:d18c6b7a9d0e1f2034567890:0101000000000000f8c6b7a9d0e1f20300000000",
                "severity": "CRITICAL",
            },
            {
                "type": "AUTHENTICATE",
                "username": "mwilson",
                "domain": "ENTERPRISE",
                "workstation": "SRV-EXCH01",
                "server_challenge": "09d7c8b0e1f20314",
                "nt_response": "e29d7c8b0e1f203145678903abcdef01445566778899",
                "hashcat_hash": "mwilson::ENTERPRISE:09d7c8b0e1f20314:e29d7c8b0e1f20314567890a:010100000000000009d7c8b0e1f2031400000000",
                "severity": "CRITICAL",
            },
            {
                "type": "AUTHENTICATE",
                "username": "adm.it",
                "domain": "ENTERPRISE",
                "workstation": "WS-MWILSON",
                "server_challenge": "1ae8d9c1f2031425",
                "nt_response": "f3ae8d9c1f2031425678904abcdef0255667788990a",
                "hashcat_hash": "adm.it::ENTERPRISE:1ae8d9c1f2031425:f3ae8d9c1f20314256789045:01010000000000001ae8d9c1f203142500000000",
                "severity": "CRITICAL",
            },
            {
                "type": "AUTHENTICATE",
                "username": "adm.it",
                "domain": "ENTERPRISE",
                "workstation": "SRV-DC01",
                "server_challenge": "2bf9e0d2031425a6",
                "nt_response": "04bf9e0d2031425a67890a5abcdef03667788990a1b",
                "hashcat_hash": "adm.it::ENTERPRISE:2bf9e0d2031425a6:04bf9e0d2031425a67890a5a:01010000000000002bf9e0d2031425a600000000",
                "severity": "CRITICAL",
            },
        ],
        "cleartext_credentials": [],
        "exfiltration": [
            {
                "src_ip": "10.1.2.55",
                "dst_ip": "198.51.100.42",
                "dst_port": 4444,
                "outbound_bytes": 2483200,
                "inbound_bytes": 341200,
                "asymmetry_ratio": 7.3,
                "bandwidth_bps": 58240,
                "duration_sec": 341.8,
                "severity": "CRITICAL",
                "bar_data": {"outbound_mb": 2.37, "inbound_mb": 0.33},
            }
        ],
        "connection_failures": {
            "rst_flows": [
                {"src_ip": "10.1.2.55", "dst_ip": "10.1.0.1", "dst_port": 3389, "count": 12},
                {"src_ip": "10.1.2.55", "dst_ip": "10.1.0.5", "dst_port": 3389, "count": 7},
            ],
            "icmp_unreachable": [],
            "blocked_destinations": [
                {"ip": "10.1.0.1", "port": 3389, "rst_count": 12},
                {"ip": "10.1.0.5", "port": 3389, "rst_count": 7},
            ],
        },
        "dns_health": {"timeouts": [], "nxdomains": [], "slow_responses": []},
        "tls_inspection": {
            "issues": [
                {"type": "self_signed", "host": "198.51.100.42", "port": 4444, "detail": "Certificate issuer matches subject"},
                {"type": "self_signed", "host": "10.1.2.1", "port": 8443, "detail": "Certificate issuer matches subject"},
            ],
            "self_signed": [
                {"host": "198.51.100.42", "port": 4444},
                {"host": "10.1.2.1", "port": 8443},
            ],
            "expired": [],
            "alerts": [{"host": "198.51.100.42", "type": "certificate_unknown", "level": "fatal"}],
        },
        "traffic_timeline": {
            "conversations": [
                {"src": "10.1.2.55", "dst": "198.51.100.42", "port": 4444, "packets": 4820, "bytes": 2824400},
                {"src": "10.1.2.55", "dst": "10.1.0.1", "port": 445, "packets": 1284, "bytes": 387200},
                {"src": "10.1.2.55", "dst": "10.1.0.5", "port": 445, "packets": 892, "bytes": 268400},
                {"src": "10.1.2.55", "dst": "SRV-DC01", "port": 389, "packets": 440, "bytes": 132000},
            ],
        },
        "packet_count": 31962,
        "summary": {
            "c2_beacon_count": 1,
            "dns_tunnel_domain_count": 0,
            "ntlm_hash_count": 6,
            "cleartext_cred_count": 0,
            "exfil_flow_count": 1,
            "blocked_dest_count": 2,
            "dns_failure_count": 0,
            "tls_issue_count": 2,
            "conversation_count": 4,
        },
    }


def _results_network_baseline() -> dict:
    return {
        "c2_beaconing": [],
        "dns_tunneling": {"tunnel_domains": [], "suspicious_queries": []},
        "ntlm_hashes": [],
        "cleartext_credentials": [],
        "exfiltration": [],
        "connection_failures": {
            "rst_flows": [
                {"src_ip": "172.16.0.12", "dst_ip": "172.16.0.1", "dst_port": 8080, "count": 2},
            ],
            "icmp_unreachable": [
                {"src_ip": "172.16.0.1", "dst_ip": "172.16.0.12", "type": 3, "code": 1, "count": 1},
            ],
            "blocked_destinations": [
                {"ip": "172.16.0.1", "port": 8080, "rst_count": 2},
            ],
        },
        "dns_health": {
            "timeouts": [
                {"query": "updates.corp.internal", "count": 5, "server": "172.16.0.1"},
                {"query": "fileshare.corp.internal", "count": 3, "server": "172.16.0.1"},
            ],
            "nxdomains": [
                {"query": "old-intranet.corp.local", "count": 12},
                {"query": "legacy-app.corp.local", "count": 8},
                {"query": "retired-server.corp.local", "count": 4},
            ],
            "slow_responses": [
                {"query": "updates.corp.internal", "avg_ms": 1240, "server": "172.16.0.1"},
            ],
        },
        "tls_inspection": {
            "issues": [
                {"type": "tls_1_0", "host": "172.16.0.20", "port": 443, "detail": "TLS 1.0 negotiated (deprecated)"},
            ],
            "self_signed": [],
            "expired": [],
            "alerts": [],
        },
        "traffic_timeline": {
            "conversations": [
                {"src": "172.16.0.12", "dst": "172.16.0.1", "port": 53, "packets": 1820, "bytes": 167240},
                {"src": "172.16.0.15", "dst": "172.16.0.1", "port": 53, "packets": 1140, "bytes": 104880},
                {"src": "172.16.0.12", "dst": "172.16.0.20", "port": 443, "packets": 640, "bytes": 192000},
                {"src": "172.16.0.15", "dst": "172.16.0.20", "port": 443, "packets": 420, "bytes": 126000},
                {"src": "172.16.0.12", "dst": "8.8.8.8", "port": 53, "packets": 210, "bytes": 19320},
            ],
        },
        "packet_count": 6203,
        "summary": {
            "c2_beacon_count": 0,
            "dns_tunnel_domain_count": 0,
            "ntlm_hash_count": 0,
            "cleartext_cred_count": 0,
            "exfil_flow_count": 0,
            "blocked_dest_count": 1,
            "dns_failure_count": 32,
            "tls_issue_count": 1,
            "conversation_count": 5,
        },
    }


# ---------------------------------------------------------------------------
# Seeding function
# ---------------------------------------------------------------------------

DEMO_CAPTURES = [
    {
        "filename": "cobalt-strike-beacon.pcap",
        "file_size": 46316544,
        "packet_count": 45231,
        "description": "C2 beaconing + NTLM hash capture",
        "results_fn": _results_cobalt_strike,
    },
    {
        "filename": "dns-exfiltration-iodine.pcap",
        "file_size": 13155328,
        "packet_count": 12847,
        "description": "DNS tunneling exfiltration campaign",
        "results_fn": _results_dns_exfil,
    },
    {
        "filename": "cleartext-credentials.pcap",
        "file_size": 8716288,
        "packet_count": 8512,
        "description": "FTP and HTTP cleartext credential exposure",
        "results_fn": _results_cleartext_creds,
    },
    {
        "filename": "lateral-movement-smb.pcap",
        "file_size": 32729088,
        "packet_count": 31962,
        "description": "SMB lateral movement with C2 and exfiltration",
        "results_fn": _results_lateral_movement,
    },
    {
        "filename": "network-health-audit.pcap",
        "file_size": 6351872,
        "packet_count": 6203,
        "description": "Baseline traffic with DNS and TLS health issues",
        "results_fn": _results_network_baseline,
    },
]


def seed_demo_data() -> None:
    """Idempotent — safe to call on every startup."""
    with Session(engine) as db:
        # 1. Get or create demo user
        user = db.query(User).filter(User.email == DEMO_USER_EMAIL).first()
        if not user:
            user = User(
                email=DEMO_USER_EMAIL,
                display_name="Demo User",
                provider="demo",
                provider_id="demo",
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            logger.info("Demo user created (id=%s)", user.id)

        # 2. Seed captures that don't already exist
        existing = {
            c.filename
            for c in db.query(Capture.filename).filter(Capture.user_id == user.id).all()
        }

        base_time = datetime(2024, 10, 14, 9, 0, 0, tzinfo=timezone.utc)
        for i, spec in enumerate(DEMO_CAPTURES):
            if spec["filename"] in existing:
                continue

            results = spec["results_fn"]()
            created_at = base_time + timedelta(hours=i * 3)
            completed_at = created_at + timedelta(seconds=12)

            capture = Capture(
                user_id=user.id,
                filename=spec["filename"],
                file_path=f"/demo/{spec['filename']}",
                file_size=spec["file_size"],
                status="complete",
                results=json.dumps(results),
                packet_count=spec["packet_count"],
                created_at=created_at,
                completed_at=completed_at,
            )
            db.add(capture)
            logger.info("Seeded demo capture: %s", spec["filename"])

        db.commit()
