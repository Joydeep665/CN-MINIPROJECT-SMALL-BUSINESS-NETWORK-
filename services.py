"""Application-layer services: DHCP (with relay), DNS, Web (HTTP) and Email (SMTP/POP3).

Servers are plain Python objects registered on the Network. Clients are functions
(dhcp_request, dns_query, http_get, send_mail, fetch_mail) that exchange logged
"packets" over the simulated network, advancing the simulated clock as they go.
"""
from __future__ import annotations

import hashlib
import ipaddress
import itertools
from dataclasses import dataclass
from urllib.parse import urlparse

from .network import Network

DOMAIN = "smallbiz.local"


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


class Session:
    """One conversation between a client node and a server IP; logs every packet."""
    _ports = itertools.count(49152)

    def __init__(self, net: Network, src: str, dst_ip: str, dport: int, transport: str = "tcp"):
        self.net, self.src, self.dst_ip = net, src, dst_ip
        self.sport, self.dport, self.transport = next(Session._ports), dport, transport
        self.src_ip = net.primary_ip(src)
        effective_ip = dst_ip
        if hasattr(net, "nat_translate"):
            trans = net.nat_translate(dst_ip, dport)
            if trans:
                effective_ip = trans
        self.effective_ip = effective_ip
        self.dst = net.owner_of_ip(effective_ip)
        self.rt = net.round_trip(src, dst_ip, proto=transport, dport=dport) if self.dst else None
        self.ok = bool(self.rt and self.rt.ok)
        self.reason = self.rt.reason if self.rt else "Destination host unreachable (ARP failed)"
        self.one_way = self.rt.rtt_ms / 2 if self.ok else 0.0
        self.elapsed = 0.0
        self.nat = getattr(self.rt, "nat", None)
        if not self.nat and effective_ip != dst_ip:
            self.nat = {"orig_dst": f"{dst_ip}:{dport}", "new_dst": f"{effective_ip}:{dport}"}

    def tx(self, frm: str, proto: str, info: str, length: int = 60, proc: float = 0.0, **meta):
        fwd = frm == "c"
        src_ip, dst_ip = (self.src_ip, self.dst_ip) if fwd else (self.dst_ip, self.src_ip)
        sn, dn = (self.src, self.dst) if fwd else (self.dst, self.src)
        nodes = self.rt.nodes if fwd else list(reversed(self.rt.nodes))
        step = self.one_way + proc
        self.net.advance(step)
        self.elapsed += step
        sp, dp = (self.sport, self.dport) if fwd else (self.dport, self.sport)
        meta.update(sport=sp, dport=dp, transport=self.transport)
        if self.nat:
            meta["nat"] = self.nat
        return self.net.record(src_ip, dst_ip, proto, info, nodes, length, True, meta, sn, dn)

    def lost(self, proto: str, info: str, **meta):
        """A packet that never gets an answer (drawn up to the point where it died)."""
        nodes = self.rt.nodes if self.rt else [self.src]
        meta.update(sport=self.sport, dport=self.dport, transport=self.transport, error=self.reason)
        if self.nat:
            meta["nat"] = self.nat
        return self.net.record(self.src_ip, self.dst_ip, proto, info + "  [no response]", nodes, 60,
                               False, meta, self.src, self.dst)


# ======================================================================== DHCP
@dataclass
class Pool:
    seg: str
    gateway: str
    dns: str
    first: str
    last: str
    lease_s: int = 3600


class DHCPServer:
    def __init__(self, net: Network, node: str, pools):
        self.net, self.node = net, node
        self.pools = {p.seg: p for p in pools}
        self.leases: dict = {}
        self.stats = {"discover": 0, "offer": 0, "request": 0, "ack": 0, "timeouts": 0}

    def allocate(self, seg: str, mac: str):
        lease = self.leases.get(mac)
        if lease and lease["seg"] == seg:
            return lease["ip"]
        p = self.pools[seg]
        used = {l["ip"] for l in self.leases.values()}
        a, last = ipaddress.ip_address(p.first), ipaddress.ip_address(p.last)
        while a <= last:
            if str(a) not in used:
                return str(a)
            a += 1
        return None


def _dhcp_path(net: Network, host, relay: str, server_ip: str):
    """client -> relay agent (L2 broadcast domain) -> DHCP server (routed unicast)."""
    p1 = net.l2_path(host.segment, host.name, relay)
    if p1 is None:
        return None, "relay agent unreachable (no layer-2 path)"
    d2 = net.deliver(relay, server_ip, acl=False)
    if not d2.ok:
        return None, d2.reason
    nodes = p1[0] + d2.nodes[1:]
    one_way = net.path_delay(p1[0], p1[1]) + d2.one_way_ms
    return (nodes, one_way), ""


def dhcp_request(net: Network, host_name: str, renew: bool = True) -> dict:
    host = net.nodes[host_name]
    srv: DHCPServer = net.svc["dhcp"]
    srv_ip = net.primary_ip(srv.node)
    t0 = net.clock
    if renew:
        host.ip = host.mask = host.gw = host.dns = None
        host.apipa = False
    out = {"host": host_name, "ok": False, "apipa": False, "ip": None, "reason": "", "ms": 0.0,
           "messages": []}
    xid = int(hashlib.md5(host_name.encode()).hexdigest()[:8], 16)
    relay = net.relay_router(host.segment)
    if not host.up:
        out["reason"] = f"{host_name} is powered off"
        return out
    if relay is None:
        path, why = None, "no DHCP relay (ip helper-address) configured on this segment"
    else:
        path, why = _dhcp_path(net, host, relay, srv_ip)
    if path is None or not net.nodes[srv.node].up:
        why = why or f"{srv.node} is powered off"
        for i in range(3):
            net.record("0.0.0.0", "255.255.255.255", "DHCP",
                       f"DHCP Discover - Transaction ID 0x{xid:08x}  (attempt {i + 1}, no response)",
                       [host_name], 64, False,
                       {"message_type": "Discover", "client_mac": host.mac, "xid": f"0x{xid:08x}",
                        "error": why, "sport": 68, "dport": 67, "transport": "udp", "view": "client"},
                       host_name, None)
            net.advance(2000)
        srv.stats["timeouts"] += 1
        h = hashlib.md5(host_name.encode()).digest()
        host.ip, host.mask, host.gw, host.dns, host.apipa = (
            f"169.254.{1 + h[0] % 254}.{1 + h[1] % 254}", "255.255.0.0", None, None, True)
        out.update(apipa=True, ip=host.ip, reason=f"DHCP timeout: {why}. Fell back to APIPA.",
                   ms=net.clock - t0)
        return out

    nodes, one_way = path
    seg = host.segment
    pool = srv.pools[seg]
    giaddr = str(net.nodes[relay].ifaces[seg].ip)
    ip = srv.allocate(seg, host.mac)
    if ip is None:
        out["reason"] = "DHCP pool exhausted"
        return out
    mask = str(net.subnets[seg].netmask)
    rnodes = list(reversed(nodes))
    common = {"xid": f"0x{xid:08x}", "client_mac": host.mac, "giaddr": giaddr, "relay_agent": relay,
              "sport": 67, "dport": 67, "transport": "udp", "view": "relayed"}
    flow = [
        ("Discover", "DISCOVER", giaddr, srv_ip, host_name, srv.node, nodes, {}),
        ("Offer", "OFFER", srv_ip, giaddr, srv.node, relay, rnodes,
         {"yiaddr": ip, "subnet_mask": mask, "router": pool.gateway, "dns_server": pool.dns,
          "lease_time_s": pool.lease_s, "server_id": srv_ip}),
        ("Request", "REQUEST", giaddr, srv_ip, host_name, srv.node, nodes,
         {"requested_ip": ip, "server_id": srv_ip}),
        ("Ack", "ACK", srv_ip, giaddr, srv.node, relay, rnodes,
         {"yiaddr": ip, "subnet_mask": mask, "router": pool.gateway, "dns_server": pool.dns,
          "lease_time_s": pool.lease_s, "server_id": srv_ip}),
    ]
    for mtype, label, sip, dip, sn, dn, pth, extra in flow:
        net.advance(one_way + (1.5 if sn == srv.node else 0.0))
        key = label.lower()
        srv.stats[key] += 1 if key in srv.stats else 0
        fields = dict(common, message_type=mtype, **extra)
        info = (f"DHCP {mtype} - Transaction ID 0x{xid:08x}"
                + (f"  offered {ip}" if mtype in ("Offer", "Ack") else "")
                + f"  (relayed by {relay}, giaddr={giaddr})")
        net.record(sip, dip, "DHCP", info, pth, 342, True, fields, sn, dn)
        out["messages"].append({"msg": label, "from": sn, "to": dn, "info": info})
    srv.leases[host.mac] = {"ip": ip, "seg": seg, "host": host_name,
                            "expires": net.clock + pool.lease_s * 1000}
    host.ip, host.mask, host.gw, host.dns, host.apipa = ip, mask, pool.gateway, pool.dns, False
    out.update(ok=True, ip=ip, ms=net.clock - t0, mask=mask, gw=pool.gateway, dns=pool.dns,
               lease_s=pool.lease_s, path=nodes)
    return out


# ========================================================================= DNS
class DNSServer:
    def __init__(self, net: Network, node: str, domain: str = DOMAIN):
        self.net, self.node, self.domain = net, node, domain
        self.zone: dict = {}
        self.upstream: dict = {}
        self.upstream_ip = None
        self.cache: dict = {}
        self.stats = {"queries": 0, "authoritative": 0, "cache_hits": 0, "cache_misses": 0,
                      "nxdomain": 0, "servfail": 0}

    def add(self, name, rtype, value, ttl=3600, pref=None, upstream=False):
        rec = {"name": name.lower(), "type": rtype, "value": value, "ttl": ttl, "pref": pref}
        (self.upstream if upstream else self.zone).setdefault((rec["name"], rtype), []).append(rec)

    def lookup(self, qname: str, qtype: str) -> dict:
        q = qname.lower().rstrip(".")
        self.stats["queries"] += 1
        if q == self.domain or q.endswith("." + self.domain):
            self.stats["authoritative"] += 1
            recs = list(self.zone.get((q, qtype), []))
            if not recs and qtype == "A" and (q, "CNAME") in self.zone:
                cn = self.zone[(q, "CNAME")][0]
                recs = [cn] + list(self.zone.get((cn["value"], "A"), []))
            if recs:
                return {"rcode": "NOERROR", "answers": recs, "source": "authoritative", "extra_ms": 0.2}
            if any(k[0] == q for k in self.zone):
                return {"rcode": "NOERROR", "answers": [], "source": "authoritative", "extra_ms": 0.2}
            self.stats["nxdomain"] += 1
            return {"rcode": "NXDOMAIN", "answers": [], "source": "authoritative", "extra_ms": 0.2}
        key = (q, qtype)
        c = self.cache.get(key)
        if c and c["expires"] > self.net.clock:
            self.stats["cache_hits"] += 1
            return {"rcode": "NOERROR", "answers": c["answers"], "source": "cache", "extra_ms": 0.1}
        self.stats["cache_misses"] += 1
        up = self.net.round_trip(self.node, self.upstream_ip, acl=False)
        if not up.ok:
            self.stats["servfail"] += 1
            return {"rcode": "SERVFAIL", "answers": [], "source": "forwarder unreachable",
                    "extra_ms": 800.0}
        recs = self.upstream.get(key)
        if not recs:
            self.stats["nxdomain"] += 1
            return {"rcode": "NXDOMAIN", "answers": [], "source": "forwarded", "extra_ms": up.rtt_ms + 8}
        self.cache[key] = {"answers": recs,
                           "expires": self.net.clock + min(r["ttl"] for r in recs) * 1000}
        return {"rcode": "NOERROR", "answers": recs, "source": "forwarded", "extra_ms": up.rtt_ms + 8}


def _fmt_answers(answers):
    parts = []
    for a in answers:
        if a["type"] == "MX":
            parts.append(f"MX {a['pref']} {a['value']}")
        else:
            parts.append(f"{a['type']} {a['value']}")
    return ", ".join(parts)


def dns_query(net: Network, host_name: str, qname: str, qtype: str = "A", server_ip=None) -> dict:
    host = net.nodes[host_name]
    out = {"ok": False, "qname": qname, "qtype": qtype, "answers": [], "rcode": None,
           "source": None, "ms": 0.0, "reason": "", "path": []}
    t0 = net.clock
    if not host.ip:
        out["reason"] = "host has no IP configuration"
        return out
    srv_ip = server_ip or host.dns
    if not srv_ip:
        out["reason"] = "no DNS server configured (DHCP did not supply one)"
        return out
    q = qname.lower().rstrip(".")
    if "." not in q:
        q += "." + DOMAIN
    out["qname"] = q
    txid = int(hashlib.md5(f"{host_name}{q}{net._seq}".encode()).hexdigest()[:4], 16)
    s = Session(net, host_name, srv_ip, 53, "udp")
    info_q = f"Standard query 0x{txid:04x} {qtype} {q}"
    if not s.ok:
        s.lost("DNS", info_q, qname=q, qtype=qtype, txid=txid)
        net.advance(2000)
        out.update(reason=f"no response from DNS server {srv_ip} ({s.reason})", rcode="TIMEOUT",
                   ms=net.clock - t0, path=s.rt.nodes if s.rt else [])
        return out
    dns = None
    if hasattr(net, "dns_servers"):
        dns = net.dns_servers.get(s.dst)
    if dns is None:
        dns_candidate = net.svc.get("dns")
        if dns_candidate and s.dst == getattr(dns_candidate, "node", None):
            dns = dns_candidate
    if dns is None:
        s.lost("DNS", info_q, qname=q, qtype=qtype, txid=txid)
        net.advance(2000)
        out.update(reason=f"{srv_ip} is not running a DNS service", rcode="TIMEOUT", ms=net.clock - t0)
        return out
    s.tx("c", "DNS", info_q, 70, qname=q, qtype=qtype, txid=txid, flags="RD")
    res = dns.lookup(q, qtype)
    net.advance(res["extra_ms"])
    s.elapsed += res["extra_ms"]
    info_r = f"Standard query response 0x{txid:04x} {qtype} {q} " + (
        _fmt_answers(res["answers"]) if res["answers"] else res["rcode"])
    s.tx("s", "DNS", info_r, 90, qname=q, qtype=qtype, txid=txid, rcode=res["rcode"],
         answers=[dict(a) for a in res["answers"]], answered_by=res["source"])
    out.update(ok=res["rcode"] == "NOERROR", answers=res["answers"], rcode=res["rcode"],
               source=res["source"], ms=net.clock - t0, path=s.rt.nodes)
    if not out["ok"]:
        out["reason"] = res["rcode"]
    return out


# ========================================================================= Web
class WebServer:
    def __init__(self, node: str, name: str, pages: dict):
        self.node, self.name, self.pages = node, name, pages
        self.hits = 0

    def get(self, path: str):
        self.hits += 1
        if path in self.pages:
            return 200, self.pages[path]
        return 404, "<html><body><h1>404 Not Found</h1></body></html>"


def http_get(net: Network, host_name: str, url: str) -> dict:
    out = {"ok": False, "url": url, "status": None, "ms": 0.0, "ip": None, "body": "",
           "reason": "", "dns": None, "path": []}
    h = net.nodes[host_name]
    t0 = net.clock
    if not h.ip:
        out["reason"] = "host has no IP configuration"
        return out
    if "://" not in url:
        url = "http://" + url
    u = urlparse(url)
    hostname, path = u.hostname or "", u.path or "/"
    if _is_ip(hostname):
        ip = hostname
    else:
        d = dns_query(net, host_name, hostname, "A")
        out["dns"] = {k: d[k] for k in ("ok", "rcode", "source", "ms", "reason")}
        a = [x for x in d["answers"] if x["type"] == "A"]
        if not d["ok"] or not a:
            out.update(reason=f"could not resolve host '{hostname}' ({d['rcode'] or d['reason']})",
                       ms=net.clock - t0)
            return out
        ip = a[0]["value"]
    out["ip"] = ip
    s = Session(net, host_name, ip, 80)
    if not s.ok:
        s.lost("TCP", f"{s.src_ip}:{s.sport} -> {ip}:80 [SYN]", flags="S")
        net.advance(3000)
        out.update(reason=f"connection timed out ({s.reason})", ms=net.clock - t0,
                   path=s.rt.nodes if s.rt else [])
        return out
    out["path"] = s.rt.nodes
    web = net.web_servers.get(s.dst)
    if web is None:
        s.tx("c", "TCP", f"{s.sport} -> 80 [SYN]", 60, flags="S")
        s.tx("s", "TCP", f"80 -> {s.sport} [RST, ACK]  connection refused", 60, flags="RA")
        out.update(reason="connection refused (nothing listening on port 80)", ms=net.clock - t0)
        return out
    s.tx("c", "TCP", f"{s.sport} -> 80 [SYN]", 60, flags="S")
    s.tx("s", "TCP", f"80 -> {s.sport} [SYN, ACK]", 60, flags="SA")
    s.tx("c", "TCP", f"{s.sport} -> 80 [ACK]", 54, flags="A")
    req = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: smallbiz-sim/1.0\r\nConnection: close\r\n\r\n"
    s.tx("c", "HTTP", f"GET {path} HTTP/1.1  Host: {hostname}", 120, flags="PA", payload=req)
    status, body = web.get(path)
    reason = "OK" if status == 200 else "Not Found"
    resp = (f"HTTP/1.1 {status} {reason}\r\nServer: smallbiz-sim\r\nContent-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}")
    s.tx("s", "HTTP", f"HTTP/1.1 {status} {reason}  ({len(body)} bytes text/html)", 120 + len(body),
         proc=4.0, flags="PA", payload=resp, status=status)
    s.tx("c", "TCP", f"{s.sport} -> 80 [FIN, ACK]", 54, flags="FA")
    s.tx("s", "TCP", f"80 -> {s.sport} [FIN, ACK]", 54, flags="FA")
    out.update(ok=status == 200, status=status, body=body, ms=net.clock - t0)
    if status != 200:
        out["reason"] = f"HTTP {status}"
    return out


# ======================================================================== Mail
class MailServer:
    def __init__(self, net: Network, node: str, domain: str, users: dict):
        self.net, self.node, self.domain, self.users = net, node, domain, users
        self.mailboxes = {u: [] for u in users}
        self.queue: list = []
        self._ids = itertools.count(1)

    def deliver_local(self, user, msg):
        self.mailboxes[user].append(msg)

    def new_id(self):
        return f"Q{next(self._ids):04d}"


def _smtp_exchange(s: Session, cmd: str, reply: str, proc: float = 1.0):
    s.tx("c", "SMTP", f"C: {cmd}", 60 + len(cmd), flags="PA", payload=cmd + "\r\n")
    s.tx("s", "SMTP", f"S: {reply}", 60 + len(reply), proc=proc, flags="PA", payload=reply + "\r\n")


def _relay_external(net: Network, ms: MailServer, rcpt: str, msg: dict, mid: str) -> str:
    """Server-to-server delivery: MX lookup, then SMTP to the remote MX."""
    dom = rcpt.split("@", 1)[1]
    dns: DNSServer = net.svc["dns"]
    mx = dns.lookup(dom, "MX")
    if mx["rcode"] == "SERVFAIL":      # temporary DNS failure -> keep the message and retry later
        return "deferred: DNS lookup for " + dom + " failed (Internet unreachable)"
    if mx["rcode"] != "NOERROR" or not mx["answers"]:
        return "failed: no MX record for " + dom
    mx_host = sorted(mx["answers"], key=lambda r: r["pref"] or 0)[0]["value"]
    a = dns.lookup(mx_host, "A")
    if a["rcode"] == "SERVFAIL":
        return "deferred: cannot resolve MX host " + mx_host + " (Internet unreachable)"
    if not a["answers"]:
        return "failed: cannot resolve MX host " + mx_host
    ip = a["answers"][0]["value"]
    s = Session(net, ms.node, ip, 25)
    if not s.ok:
        s.lost("SMTP", f"relay to {mx_host} ({ip}):25 [SYN]", flags="S")
        return "deferred: " + s.reason
    remote = net.mail_servers.get(s.dst)
    user = rcpt.split("@")[0]
    if remote is None or user not in remote.mailboxes:
        s.tx("c", "SMTP", f"C: RCPT TO:<{rcpt}>", 80, flags="PA")
        s.tx("s", "SMTP", "S: 550 5.1.1 User unknown", 70, flags="PA")
        return "bounced: 550 user unknown"
    s.tx("c", "SMTP", f"C: MAIL FROM:<{msg['from']}>  RCPT TO:<{rcpt}>  DATA", 140, flags="PA",
         payload=f"MAIL FROM:<{msg['from']}>\r\nRCPT TO:<{rcpt}>\r\nDATA\r\n")
    s.tx("s", "SMTP", f"S: 250 2.0.0 OK queued as {mid} (relay accepted)", 90, proc=2.0, flags="PA")
    remote.deliver_local(user, dict(msg, delivered_via=ms.node))
    return "delivered"


def send_mail(net: Network, host_name: str, mail_from: str, rcpt: str, subject: str, body: str,
              smtp_host: str = "mail." + DOMAIN) -> dict:
    out = {"ok": False, "status": "", "reason": "", "ms": 0.0, "id": None, "dns": None, "path": []}
    t0 = net.clock
    h = net.nodes[host_name]
    if not h.ip:
        out["reason"] = "host has no IP configuration"
        return out
    d = dns_query(net, host_name, smtp_host, "A")
    out["dns"] = {k: d[k] for k in ("ok", "rcode", "source", "ms", "reason")}
    a = [x for x in d["answers"] if x["type"] == "A"]
    if not d["ok"] or not a:
        out.update(reason=f"cannot resolve SMTP server '{smtp_host}' ({d['rcode'] or d['reason']})",
                   ms=net.clock - t0)
        return out
    s = Session(net, host_name, a[0]["value"], 25)
    if not s.ok:
        s.lost("SMTP", f"{s.src_ip}:{s.sport} -> {a[0]['value']}:25 [SYN]", flags="S")
        net.advance(3000)
        out.update(reason=f"cannot connect to SMTP server ({s.reason})", ms=net.clock - t0,
                   path=s.rt.nodes if s.rt else [])
        return out
    ms = net.mail_servers.get(s.dst)
    out["path"] = s.rt.nodes
    if ms is None:
        s.tx("c", "TCP", f"{s.sport} -> 25 [SYN]", 60, flags="S")
        s.tx("s", "TCP", f"25 -> {s.sport} [RST, ACK]  connection refused", 60, flags="RA")
        out.update(reason="connection refused (no SMTP service)", ms=net.clock - t0)
        return out
    s.tx("c", "TCP", f"{s.sport} -> 25 [SYN]", 60, flags="S")
    s.tx("s", "TCP", f"25 -> {s.sport} [SYN, ACK]", 60, flags="SA")
    s.tx("c", "TCP", f"{s.sport} -> 25 [ACK]", 54, flags="A")
    s.tx("s", "SMTP", f"S: 220 mail.{ms.domain} ESMTP ready", 80, flags="PA",
         payload=f"220 mail.{ms.domain} ESMTP ready\r\n")
    _smtp_exchange(s, f"EHLO {host_name.lower()}.{DOMAIN}", f"250 mail.{ms.domain} Hello {host_name}")
    _smtp_exchange(s, f"MAIL FROM:<{mail_from}>", "250 2.1.0 Sender OK")
    local = rcpt.lower().endswith("@" + ms.domain)
    user = rcpt.split("@")[0].lower()
    if local and user not in ms.mailboxes:
        _smtp_exchange(s, f"RCPT TO:<{rcpt}>", "550 5.1.1 User unknown")
        _smtp_exchange(s, "QUIT", "221 2.0.0 Bye")
        out.update(status="rejected", reason="550 5.1.1 recipient unknown", ms=net.clock - t0)
        return out
    _smtp_exchange(s, f"RCPT TO:<{rcpt}>", "250 2.1.5 Recipient OK")
    _smtp_exchange(s, "DATA", "354 End data with <CR><LF>.<CR><LF>")
    mid = ms.new_id()
    msg = {"id": mid, "from": mail_from, "to": rcpt, "subject": subject, "body": body,
           "date": round(net.clock / 1000, 3), "size": len(body) + len(subject) + 120}
    data = f"From: {mail_from}\r\nTo: {rcpt}\r\nSubject: {subject}\r\n\r\n{body}\r\n."
    s.tx("c", "SMTP", f"C: [message body, {len(data)} bytes]", 60 + len(data), flags="PA", payload=data + "\r\n")
    s.tx("s", "SMTP", f"S: 250 2.0.0 OK queued as {mid}", 80, proc=2.0, flags="PA",
         payload=f"250 2.0.0 OK queued as {mid}\r\n")
    _smtp_exchange(s, "QUIT", "221 2.0.0 Bye")
    if local:
        ms.deliver_local(user, msg)
        status = "delivered"
    else:
        status = _relay_external(net, ms, rcpt, msg, mid)
        if status.startswith("deferred"):
            ms.queue.append({"id": mid, "msg": msg, "rcpt": rcpt, "reason": status})
    out.update(ok=status in ("delivered",) or status.startswith("deferred"), status=status, id=mid,
               ms=net.clock - t0)
    if status.startswith("deferred"):
        out["reason"] = "message queued on mail server for retry (" + status + ")"
    elif status != "delivered":
        out["ok"] = False
        out["reason"] = status
    return out


def flush_mail_queue(net: Network, node: str) -> list:
    ms = net.mail_servers[node]
    results, remaining = [], []
    for item in ms.queue:
        st = _relay_external(net, ms, item["rcpt"], item["msg"], item["id"])
        results.append({"id": item["id"], "rcpt": item["rcpt"], "status": st})
        if st.startswith("deferred"):
            remaining.append(item)
    ms.queue = remaining
    return results


def fetch_mail(net: Network, host_name: str, user: str, password: str,
               pop_host: str = "mail." + DOMAIN) -> dict:
    out = {"ok": False, "messages": [], "reason": "", "ms": 0.0, "path": []}
    t0 = net.clock
    d = dns_query(net, host_name, pop_host, "A")
    a = [x for x in d["answers"] if x["type"] == "A"]
    if not d["ok"] or not a:
        out.update(reason=f"cannot resolve POP3 server ({d['rcode'] or d['reason']})", ms=net.clock - t0)
        return out
    s = Session(net, host_name, a[0]["value"], 110)
    if not s.ok:
        s.lost("TCP", f"{s.src_ip}:{s.sport} -> {a[0]['value']}:110 [SYN]", flags="S")
        net.advance(3000)
        out.update(reason=f"cannot connect to POP3 server ({s.reason})", ms=net.clock - t0)
        return out
    ms = net.mail_servers.get(s.dst)
    out["path"] = s.rt.nodes
    if ms is None:
        out.update(reason="connection refused (no POP3 service)", ms=net.clock - t0)
        return out

    def ex(cmd, reply):
        s.tx("c", "POP", f"C: {cmd}", 60 + len(cmd), flags="PA", payload=cmd + "\r\n")
        s.tx("s", "POP", f"S: {reply}", 60 + len(reply), proc=1.0, flags="PA", payload=reply + "\r\n")

    s.tx("c", "TCP", f"{s.sport} -> 110 [SYN]", 60, flags="S")
    s.tx("s", "TCP", f"110 -> {s.sport} [SYN, ACK]", 60, flags="SA")
    s.tx("c", "TCP", f"{s.sport} -> 110 [ACK]", 54, flags="A")
    s.tx("s", "POP", "S: +OK POP3 server ready", 70, flags="PA", payload="+OK POP3 server ready\r\n")
    user = user.lower().split("@")[0]
    ex(f"USER {user}", "+OK" if user in ms.users else "-ERR no such user")
    if user not in ms.users or ms.users[user] != password:
        if user in ms.users:
            ex("PASS ********", "-ERR authentication failed")
        ex("QUIT", "+OK bye")
        out.update(reason="authentication failed", ms=net.clock - t0)
        return out
    ex("PASS ********", "+OK logged in")
    box = ms.mailboxes[user]
    ex("STAT", f"+OK {len(box)} {sum(m['size'] for m in box)}")
    for i, m in enumerate(box, 1):
        ex(f"RETR {i}", f"+OK {m['size']} octets  Subject: {m['subject']}")
    ex("QUIT", "+OK bye")
    out.update(ok=True, messages=[dict(m) for m in box], ms=net.clock - t0)
    return out
