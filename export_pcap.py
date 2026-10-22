"""Export the simulated packet log to a real .pcap file that Wireshark can open.

IMPORTANT: these packets are *synthesised* from the simulation log (correct protocol layouts,
simulated timing and MAC addresses). They are not captured from a live network. State this
clearly in your report. Requires: pip install scapy
"""
from __future__ import annotations

import io
import struct

from .network import mac_of


def _wire_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def build_pcap(log: list, path: str | None = None) -> bytes:
    from scapy.all import (BOOTP, DHCP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw,
                           PcapWriter)

    pkts = []
    nxt: dict = {}                      # (ip, port) -> next TCP sequence number
    base = 1_700_000_000.0

    def eth(rec):
        src = mac_of(rec["src_name"]) if rec.get("src_name") else "02:00:00:00:00:01"
        dst = mac_of(rec["dst_name"]) if rec.get("dst_name") else "ff:ff:ff:ff:ff:ff"
        return Ether(src=src, dst=dst)

    for rec in log:
        m, proto = rec["meta"], rec["proto"]
        if not rec["ok"] or not rec["src"] or not rec["dst"]:
            continue                                    # unanswered packets are not "on the wire" views
        l2 = eth(rec)
        ip = IP(src=rec["src"], dst=rec["dst"])
        p = None
        if proto == "ICMP":
            t = 8 if m.get("icmp_type") == "echo-request" else 0
            p = l2 / ip / ICMP(type=t, id=m["icmp_id"], seq=m["icmp_seq"]) / Raw(b"smallbiz-sim-ping-" * 3)
        elif proto == "DHCP":
            mt = m["message_type"].lower()
            mac = bytes.fromhex(m["client_mac"].replace(":", ""))
            xid = int(m["xid"], 16)
            if mt in ("discover", "request"):
                opts = [("message-type", mt)]
                if mt == "request":
                    opts += [("requested_addr", m["requested_ip"]), ("server_id", m["server_id"])]
                p = l2 / ip / UDP(sport=67, dport=67) / BOOTP(op=1, xid=xid, chaddr=mac,
                                                               giaddr=m["giaddr"]) / DHCP(options=opts + ["end"])
            else:
                opts = [("message-type", "offer" if mt == "offer" else "ack"),
                        ("server_id", m["server_id"]), ("lease_time", m["lease_time_s"]),
                        ("subnet_mask", m["subnet_mask"]), ("router", m["router"]),
                        ("name_server", m["dns_server"])]
                p = l2 / ip / UDP(sport=67, dport=67) / BOOTP(op=2, xid=xid, chaddr=mac, yiaddr=m["yiaddr"],
                                                               siaddr=m["server_id"], giaddr=m["giaddr"]) \
                    / DHCP(options=opts + ["end"])
        elif proto == "DNS":
            qtype = {"A": 1, "MX": 15, "CNAME": 5}.get(m["qtype"], 1)
            if "rcode" not in m:
                p = l2 / ip / UDP(sport=m["sport"], dport=53) / DNS(id=m["txid"], rd=1,
                                                                     qd=DNSQR(qname=m["qname"], qtype=qtype))
            else:
                rrs = None
                for a in m["answers"]:
                    if a["type"] == "A":
                        rr = DNSRR(rrname=a["name"], type="A", ttl=a["ttl"], rdata=a["value"])
                    elif a["type"] == "CNAME":
                        rr = DNSRR(rrname=a["name"], type="CNAME", ttl=a["ttl"], rdata=a["value"])
                    else:   # MX: 2-byte preference + wire-format name
                        rr = DNSRR(rrname=a["name"], type="MX", ttl=a["ttl"],
                                   rdata=struct.pack("!H", a["pref"] or 0) + _wire_name(a["value"]))
                    rrs = rr if rrs is None else rrs / rr
                rc = {"NOERROR": 0, "NXDOMAIN": 3, "SERVFAIL": 2}.get(m["rcode"], 0)
                p = l2 / ip / UDP(sport=53, dport=m["dport"]) / DNS(
                    id=m["txid"], qr=1, aa=int(m.get("answered_by") == "authoritative"), rd=1, ra=1,
                    rcode=rc, qd=DNSQR(qname=m["qname"], qtype=qtype), an=rrs, ancount=len(m["answers"]))
        elif "flags" in m:       # TCP-based: TCP, HTTP, SMTP, POP
            sp, dp = m["sport"], m["dport"]
            payload = (m.get("payload") or "").encode()
            fl = m["flags"]
            src_k, dst_k = (rec["src"], sp), (rec["dst"], dp)
            nxt.setdefault(src_k, 1000 + (hash(src_k) % 90000))
            nxt.setdefault(dst_k, 5000 + (hash(dst_k) % 90000))
            ack = nxt[dst_k] if "A" in fl else 0
            p = l2 / ip / TCP(sport=sp, dport=dp, flags=fl, seq=nxt[src_k], ack=ack, window=64240)
            if payload:
                p = p / Raw(payload)
            nxt[src_k] += len(payload) + (1 if ("S" in fl or "F" in fl) else 0)
        if p is None:
            continue
        p.time = base + rec["t"] / 1000.0
        pkts.append(p)

    buf = io.BytesIO()
    w = PcapWriter(buf, sync=True)
    for p in pkts:
        w.write(p)
    w.flush()
    data = buf.getvalue()
    if path:
        with open(path, "wb") as f:
            f.write(data)
    return data
