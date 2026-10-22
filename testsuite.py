"""Automated test cases: normal operation and failure conditions.

Each test builds a fresh network so tests cannot influence each other.
`run_all()` returns a list of result dicts (used by the dashboard and by tests/test_simulation.py).
"""
from __future__ import annotations

import ipaddress

from .services import (dhcp_request, dns_query, fetch_mail, flush_mail_queue, http_get, send_mail)
from .tools import ping
from .topology import PCS, boot_all, build_smallbiz, DNS_IP, INET_IP


def _fresh():
    net = build_smallbiz()
    boot_all(net)
    net.clear_log()
    return net


def _r(tid, cat, name, expected, passed, actual):
    return {"id": tid, "category": cat, "name": name, "expected": expected,
            "actual": actual, "passed": bool(passed)}


def converge(net, src, dst_ip, limit_ms=60000, step=50):
    """Advance simulated time until src can reach dst_ip. Returns elapsed ms or None."""
    t = 0
    while t <= limit_ms:
        if net.round_trip(src, dst_ip).ok:
            return t
        net.advance(step)
        t += step
    return None


# ------------------------------------------------------------------ normal
def t01():
    net = _fresh()
    bad, ips = [], []
    exp = {"EMP": ("10.10.1.0/26", "10.10.1.1"), "MGT": ("10.10.1.64/27", "10.10.1.65")}
    for pc in PCS:
        n = net.nodes[pc]
        cidr, gw = exp[n.segment]
        if not (n.ip and ipaddress.ip_address(n.ip) in ipaddress.ip_network(cidr)
                and n.gw == gw and n.dns == DNS_IP):
            bad.append(pc)
        ips.append(n.ip)
    ok = not bad and len(set(ips)) == len(ips)
    return _r("N1", "Normal", "DHCP assigns correct IP, mask, gateway and DNS",
              "Every PC gets an address from its own pool; no duplicates",
              ok, ", ".join(f"{p}={net.nodes[p].ip}" for p in PCS) if ok else f"wrong config on {bad}")


def t02():
    net = _fresh()
    res = {f"{s}->{d}": ping(net, s, d, 4)["received"] for s, d in
           (("EMP-PC1", "10.10.1.100"), ("MGT-PC1", "10.10.1.101"), ("EMP-PC1", "10.10.1.70"
            if False else INET_IP), ("MGT-PC2", "10.10.1.11"))}
    ok = all(v == 4 for v in res.values())
    return _r("N2", "Normal", "Inter-subnet routing (ping across subnets)",
              "4/4 replies for Employees->Servers, Management->Servers/Employees, ->Internet", ok,
              ", ".join(f"{k}: {v}/4" for k, v in res.items()))


def t03():
    net = _fresh()
    a = dns_query(net, "EMP-PC1", "www.smallbiz.local", "A")
    mx = dns_query(net, "EMP-PC1", "smallbiz.local", "MX")
    cn = dns_query(net, "EMP-PC1", "intranet", "A")
    nx = dns_query(net, "EMP-PC1", "nothing.smallbiz.local", "A")
    ok = (a["answers"] and a["answers"][0]["value"] == "10.10.1.100"
          and mx["answers"] and mx["answers"][0]["value"] == "mail.smallbiz.local"
          and any(x["type"] == "A" for x in cn["answers"]) and nx["rcode"] == "NXDOMAIN")
    return _r("N3", "Normal", "DNS resolves A, MX, CNAME and returns NXDOMAIN for unknown names",
              "www -> 10.10.1.100; MX -> mail.smallbiz.local (pref 10); unknown -> NXDOMAIN", ok,
              f"A={a['answers'][0]['value'] if a['answers'] else None}, "
              f"MX={mx['answers'][0]['value'] if mx['answers'] else None}, unknown={nx['rcode']}")


def t04():
    net = _fresh()
    r = http_get(net, "EMP-PC2", "http://www.smallbiz.local/")
    ok = r["ok"] and "SmallBiz" in r["body"]
    return _r("N4", "Normal", "Browse the company site by name", "HTTP 200 with the company page", ok,
              f"status={r['status']} in {r['ms']:.1f} ms" if r["ok"] else r["reason"])


def t05():
    net = _fresh()
    s = send_mail(net, "EMP-PC1", "alice@smallbiz.local", "carol@smallbiz.local", "Q3 report", "Numbers attached.")
    f = fetch_mail(net, "MGT-PC1", "carol", "carol123")
    ok = s["status"] == "delivered" and any(m["subject"] == "Q3 report" for m in f["messages"])
    return _r("N5", "Normal", "Email from an employee to a manager (SMTP) and retrieval (POP3)",
              "Message delivered and visible in carol's mailbox", ok,
              f"SMTP={s['status']}, carol has {len(f['messages'])} message(s)")


def t06():
    net = _fresh()
    blocked = ping(net, "EMP-PC1", "10.10.1.70", 2)
    allowed = ping(net, "MGT-PC1", "10.10.1.10", 2)
    srv = ping(net, "EMP-PC1", "10.10.1.100", 2)
    ok = blocked["received"] == 0 and "prohibited" in (blocked["error"] or "") \
        and allowed["received"] == 2 and srv["received"] == 2
    return _r("N6", "Security", "ACL blocks Employees -> Management only",
              "Employees->Management dropped; Management->Employees and Employees->Servers allowed", ok,
              f"EMP->MGT: {blocked['received']}/2 ({blocked['error']}); MGT->EMP: {allowed['received']}/2; "
              f"EMP->SRV: {srv['received']}/2")


def t07():
    net = _fresh()
    a = dns_query(net, "EMP-PC1", "www.example.com", "A")
    b = dns_query(net, "EMP-PC2", "www.example.com", "A")
    ok = a["source"] == "forwarded" and b["source"] == "cache" and b["ms"] < a["ms"]
    return _r("N7", "Normal", "DNS cache: second lookup of an external name is served from cache",
              "1st lookup forwarded to the Internet; 2nd answered from cache and faster", ok,
              f"1st: {a['source']} {a['ms']:.1f} ms; 2nd: {b['source']} {b['ms']:.1f} ms")


def t08():
    net = _fresh()
    r = http_get(net, "MGT-PC2", "http://www.example.com/")
    return _r("N8", "Normal", "Internet access through the edge router and R3",
              "HTTP 200 from www.example.com", r["ok"],
              f"status={r['status']} in {r['ms']:.1f} ms" if r["ok"] else r["reason"])


# ----------------------------------------------------------------- failures
def f01():
    net = _fresh()
    net.set_node("DHCP-SRV", False)
    r = dhcp_request(net, "EMP-PC3")
    ok = r["apipa"] and r["ip"].startswith("169.254.") and net.nodes["EMP-PC3"].gw is None
    return _r("F1", "Failure", "DHCP server down",
              "New client falls back to a 169.254.x.x (APIPA) address with no gateway", ok,
              f"ip={r['ip']}, gateway={net.nodes['EMP-PC3'].gw}, waited {r['ms'] / 1000:.0f} s")


def f02():
    net = _fresh()
    net.set_node("DNS-SRV", False)
    by_ip = ping(net, "EMP-PC1", "10.10.1.100", 2)
    by_name = ping(net, "EMP-PC1", "www.smallbiz.local", 2)
    web = http_get(net, "EMP-PC1", "http://www.smallbiz.local/")
    ok = by_ip["received"] == 2 and by_name["received"] == 0 and not web["ok"]
    return _r("F2", "Failure", "DNS server down",
              "Ping by IP works; ping and browsing by name fail", ok,
              f"by IP: {by_ip['received']}/2; by name: {by_name['received']}/2; browser: {web['reason']}")


def f03():
    net = _fresh()
    net.set_node("WEB-SRV", False)
    d = dns_query(net, "EMP-PC1", "www.smallbiz.local")
    w = http_get(net, "EMP-PC1", "http://www.smallbiz.local/")
    ok = d["ok"] and not w["ok"]
    return _r("F3", "Failure", "Web server down", "DNS still resolves; HTTP connection times out", ok,
              f"DNS ok={d['ok']}; HTTP: {w['reason']}")


def f04():
    net = _fresh()
    net.set_node("MAIL-SRV", False)
    s = send_mail(net, "EMP-PC1", "alice@smallbiz.local", "carol@smallbiz.local", "x", "y")
    return _r("F4", "Failure", "Mail server down", "SMTP connection fails; nothing is delivered",
              not s["ok"], s["reason"] or s["status"])


def f05():
    net = _fresh()
    base = ping(net, "EMP-PC1", INET_IP, 1)["avg"]
    net.set_link("R1~R3", False)
    first = net.round_trip("EMP-PC1", INET_IP)
    t = converge(net, "EMP-PC1", INET_IP)
    after = ping(net, "EMP-PC1", INET_IP, 1)
    ok = (not first.ok) and t is not None and 2000 <= t <= 6000 and after["avg"] > base
    return _r("F5", "Failure", "WAN link fails with OSPF routing",
              "Traffic drops, then re-routes via R2 after convergence (a few seconds); RTT rises", ok,
              f"converged after {t} ms; RTT {base:.1f} -> {after['avg']:.1f} ms (backup path via R2)"
              if t is not None else "did not converge")


def f06():
    net = _fresh()
    net.set_routing_mode("static")
    net.set_link("R1~R3", False)
    t = converge(net, "EMP-PC1", INET_IP, limit_ms=60000, step=1000)
    return _r("F6", "Failure", "WAN link fails with static routing",
              "Internet stays unreachable (static route does not adapt)", t is None,
              "still unreachable after 60 s of simulated time" if t is None else f"recovered after {t} ms")


def f07():
    net = _fresh()
    net.set_link("R1~R3", False)
    net.set_link("R1~R2", False)
    net.advance(10000)
    s = send_mail(net, "EMP-PC1", "alice@smallbiz.local", "partner@example.com", "Quote", "Please quote.")
    internal = send_mail(net, "EMP-PC2", "bob@smallbiz.local", "carol@smallbiz.local", "Lunch", "12:30?")
    q_before = len(net.mail_servers["MAIL-SRV"].queue)
    net.set_link("R1~R3", True)
    net.set_link("R1~R2", True)
    net.advance(10000)
    flushed = flush_mail_queue(net, "MAIL-SRV")
    got = any(m["subject"] == "Quote" for m in net.mail_servers["INET-HOST"].mailboxes["partner"])
    ok = s["status"].startswith("deferred") and q_before == 1 and internal["status"] == "delivered" and got
    return _r("F7", "Failure", "ISP outage: external email queued, then delivered after recovery",
              "Mail to example.com is deferred; internal mail still works; queue flushes when link returns", ok,
              f"external={s['status'].split(':')[0]}, internal={internal['status']}, "
              f"queued={q_before}, after restore: {flushed[0]['status'] if flushed else 'n/a'}")


def f08():
    net = _fresh()
    net.set_node("SW-EMP", False)
    emp = ping(net, "EMP-PC1", "10.10.1.100", 2)
    mgt = ping(net, "MGT-PC1", "10.10.1.100", 2)
    ok = emp["received"] == 0 and mgt["received"] == 2
    return _r("F8", "Failure", "Employee access switch down",
              "Employees isolated; Management and Servers unaffected", ok,
              f"EMP: {emp['received']}/2 ({emp['error']}); MGT: {mgt['received']}/2")


def f09():
    net = _fresh()
    net.set_node("R1", False)
    inter = ping(net, "EMP-PC1", "10.10.1.100", 2)
    intra = ping(net, "EMP-PC1", net.nodes["EMP-PC2"].ip, 2)
    ok = inter["received"] == 0 and intra["received"] == 2
    return _r("F9", "Failure", "Edge router R1 down",
              "Inter-subnet traffic fails; traffic inside one subnet still works", ok,
              f"inter-subnet: {inter['received']}/2; intra-subnet: {intra['received']}/2")


def f10():
    net = _fresh()
    net.links["SW-EMP~EMP-PC1"].loss = 0.10
    r = ping(net, "EMP-PC1", "10.10.1.100", 200)
    ok = 10 <= r["loss_pct"] <= 30
    return _r("F10", "Failure", "Lossy access link (10% per direction)",
              "Measured loss close to the theoretical 19%", ok,
              f"{r['loss_pct']}% loss over 200 pings, avg RTT {r['avg']} ms")


# ------------------------------------------------------------------ external
def e01():
    net = _fresh()
    r = http_get(net, "EXT-PC", "http://www.smallbiz.local/")
    ok = r["ok"] and "SmallBiz" in r["body"]
    return _r("E1", "External", "External web via NAT",
              "HTTP 200 via port forwarding 198.51.100.2:80 -> 10.10.1.100:80", ok,
              f"status={r['status']} in {r['ms']:.1f} ms" if r["ok"] else r["reason"])


def e02():
    net = _fresh()
    a = dns_query(net, "EXT-PC", "www.smallbiz.local", "A")
    mx = dns_query(net, "EXT-PC", "smallbiz.local", "MX")
    ok = (a["ok"] and a["answers"] and a["answers"][0]["value"] == "198.51.100.2"
          and mx["ok"] and mx["answers"] and mx["answers"][0]["value"] == "mail.smallbiz.local")
    return _r("E2", "External", "External DNS gets the public view",
              "www -> 198.51.100.2 (public IP); MX -> mail.smallbiz.local", ok,
              f"A={a['answers'][0]['value'] if a['answers'] else None}, "
              f"MX={mx['answers'][0]['value'] if mx['answers'] else None}")


def e03():
    net = _fresh()
    s = send_mail(net, "EXT-PC", "partner@example.com", "carol@smallbiz.local",
                  "Contract", "Please find the agreement attached.")
    box = net.mail_servers["MAIL-SRV"].mailboxes["carol"]
    got = any(m["subject"] == "Contract" for m in box)
    ok = s["status"] == "delivered" and got
    return _r("E3", "External", "Inbound mail delivered",
              "External mail to carol@smallbiz.local delivered to carol's mailbox via port forward 25", ok,
              f"status={s['status']}, carol has {len(box)} message(s)")


def e04():
    net = _fresh()
    p1 = ping(net, "EXT-PC", "10.10.1.100", 2)
    p2 = ping(net, "EXT-PC", "10.10.1.70", 2)
    ok = p1["received"] == 0 and "private address" in (p1["error"] or "") \
        and p2["received"] == 0 and "private address" in (p2["error"] or "")
    return _r("E4", "External", "Internal addresses unreachable from outside",
              "Ping to 10.10.1.100 and 10.10.1.70 fails with 'no route / private address'", ok,
              f"10.10.1.100: {p1['received']}/2 ({p1['error']}); 10.10.1.70: {p2['received']}/2 ({p2['error']})")


def e05():
    net = _fresh()
    f = fetch_mail(net, "EXT-PC", "carol", "carol123", pop_host="mail.smallbiz.local")
    ok = not f["ok"]
    return _r("E5", "External", "Unpublished service (POP3) blocked",
              "POP3 port 110 connection is blocked by WAN ACL", ok,
              f"ok={f['ok']}, reason={f['reason']}")


def e06():
    net = _fresh()
    net.set_link("R1~R3", False)
    net.set_link("R1~R2", False)
    net.advance(10000)
    down = http_get(net, "EXT-PC", "http://www.smallbiz.local/")
    net.set_link("R1~R3", True)
    net.set_link("R1~R2", True)
    net.advance(10000)
    up = http_get(net, "EXT-PC", "http://www.smallbiz.local/")
    ok = (not down["ok"]) and up["ok"] and "SmallBiz" in up["body"]
    return _r("E6", "External",
              "Website unreachable from outside when R1-R3 and R1-R2 are both down (and recovers after restore)",
              "Fails during full WAN outage, recovers (HTTP 200) after links restored", ok,
              f"during outage: {down['reason']}; after restore: status={up['status']} in {up['ms']:.1f} ms")


ALL = [t01, t02, t03, t04, t05, t06, t07, t08,
       f01, f02, f03, f04, f05, f06, f07, f08, f09, f10,
       e01, e02, e03, e04, e05, e06]


def run_all() -> list:
    results = []
    for fn in ALL:
        try:
            results.append(fn())
        except Exception as e:  # report instead of crashing the whole run
            results.append(_r(fn.__name__.upper(), "Error", fn.__name__, "no exception", False, repr(e)))
    return results
