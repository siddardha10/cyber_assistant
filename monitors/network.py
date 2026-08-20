"""
monitors/network.py

Optional. Requires:
  - `pip install scapy`
  - Npcap installed on Windows (with "WinPcap API-compatible mode" checked)
  - Running as Administrator

Disabled by default (CS_ENABLE_SNIFFER=false) because raw packet capture is
the most invasive and most likely to need extra setup — a student project
should demo the rest of the system without being blocked on Npcap install.

Provides:
  - DNS query logging (what domains is this machine resolving)
  - Port scan heuristic: same source IP hitting N distinct ports within a
    short window is logged as a possible scan
"""

import threading
import time
from collections import defaultdict, deque

import config
from db import database as db
from utils.logger import get_logger

log = get_logger("monitor.network")

try:
    from scapy.all import sniff, DNS, DNSQR, IP, TCP
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False

# src_ip -> deque[(timestamp, dst_port)]
_syn_tracker = defaultdict(deque)


def _handle_packet(pkt):
    try:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            domain = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            db.insert("dns_queries", {
                "timestamp": db.now_iso(),
                "domain": domain,
                "pid": None,  # PID attribution needs OS-level socket correlation, out of scope for a raw sniffer
                "process_name": None,
            })

        if pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt[TCP].flags == "S":
            src = pkt[IP].src
            dst_port = pkt[TCP].dport
            now = time.time()
            q = _syn_tracker[src]
            q.append((now, dst_port))
            while q and now - q[0][0] > config.PORT_SCAN_WINDOW_SEC:
                q.popleft()
            distinct_ports = {p for _, p in q}
            if len(distinct_ports) >= config.PORT_SCAN_PORT_COUNT:
                db.insert_alert(
                    category="port_scan",
                    severity="HIGH",
                    message=f"Possible port scan from {src}: {len(distinct_ports)} ports in {config.PORT_SCAN_WINDOW_SEC}s",
                    reason=(
                        "Hitting many different ports on your machine in a few seconds is how attackers "
                        "map which services you're running before targeting one — normal traffic doesn't "
                        "look like this. Worth checking if this IP is on your own network (some "
                        "network scanners/monitoring tools also trigger this)."
                    ),
                    source_table="network_events",
                    dedup_key=f"port_scan:{src}",
                )
                db.insert("network_events", {
                    "timestamp": db.now_iso(), "src_ip": src, "dst_ip": pkt[IP].dst,
                    "protocol": "TCP", "size": len(pkt), "pid": None, "event_type": "port_scan",
                })
                q.clear()
    except Exception:
        log.exception("Failed processing a captured packet — continuing")


def run_forever(stop_event: threading.Event):
    if not config.ENABLE_NETWORK_SNIFFER:
        log.info("Network sniffer disabled via config (CS_ENABLE_SNIFFER=false)")
        return
    if not _SCAPY_AVAILABLE:
        log.warning("Network sniffer disabled: `pip install scapy` + Npcap to enable it")
        return

    log.info("Network sniffer started — requires admin privileges and Npcap")
    try:
        while not stop_event.is_set():
            sniff(timeout=5, prn=_handle_packet, store=False)
    except Exception:
        log.exception("Network sniffer failed to start (admin rights / Npcap required)")
