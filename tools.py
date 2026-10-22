"""ping / traceroute built on the network engine."""
from __future__ import annotations

import statistics

from .network import Network
from .services import DOMAIN, dns_query, _is_ip


def resolve_target(net: Network, src: str, target: str):
    """Return (ip, dns_result_or_None, error_or_None)."""
    if _is_ip(target):
        return target, None, None
    d = dns_query(net, src, target, "A")
    a = [x for x in d["answers"] if x["type"] == "A"]
    if not d["ok"] or not a:
        return None, d, f"Ping request could not find host {target}. ({d['rcode'] or d['reason']})"
    return a[0]["value"], d, None


def ping(net: Network, src: str, target: str, count: int = 4, size: int = 56) -> dict:
    out = {"target": target, "ip": None, "sent": 0, "received": 0, "loss_pct": 100.0, "rtts": [],
           "replies": [], "min": None, "avg": None, "max": None, "jitter": None, "path": [],
           "ok": False, "error": None}
    if not net.nodes[src].ip:
        out["error"] = "host has no IP configuration"
        return out
    ip, _, err = resolve_target(net, src, target)
    if err:
        out["error"] = err
        return out
    out["ip"] = ip
    sip = net.nodes[src].ip
    ident = 0x1000 + (net._seq % 0xEFFF)
    for seq in range(1, count + 1):
        out["sent"] += 1
        rt = net.round_trip(src, ip, size=size + 8, proto="icmp")
        base = dict(icmp_id=ident, icmp_seq=seq, transport="icmp")
        if rt.ok:
            half = rt.rtt_ms / 2
            net.advance(half)
            net.record(sip, ip, "ICMP", f"Echo (ping) request  id=0x{ident:04x}, seq={seq}", rt.nodes,
                       size + 42, True, dict(base, icmp_type="echo-request"), src, net.owner_of_ip(ip))
            net.advance(half)
            net.record(ip, sip, "ICMP", f"Echo (ping) reply  id=0x{ident:04x}, seq={seq}, rtt={rt.rtt_ms:.2f} ms",
                       list(reversed(rt.nodes)), size + 42, True, dict(base, icmp_type="echo-reply"),
                       net.owner_of_ip(ip), src)
            out["received"] += 1
            out["rtts"].append(round(rt.rtt_ms, 3))
            out["replies"].append({"seq": seq, "ok": True, "rtt": round(rt.rtt_ms, 3)})
            out["path"] = rt.nodes
        else:
            net.record(sip, ip, "ICMP", f"Echo (ping) request  id=0x{ident:04x}, seq={seq}  [{rt.reason}]",
                       rt.nodes, size + 42, False, dict(base, icmp_type="echo-request", error=rt.reason),
                       src, net.owner_of_ip(ip))
            out["replies"].append({"seq": seq, "ok": False, "reason": rt.reason})
            out["error"] = rt.reason
            if not out["path"]:
                out["path"] = rt.nodes
            net.advance(1000)
        net.advance(5)
    r = out["rtts"]
    out["loss_pct"] = round(100 * (out["sent"] - out["received"]) / out["sent"], 1)
    out["ok"] = out["received"] > 0
    if r:
        out.update(min=round(min(r), 3), avg=round(sum(r) / len(r), 3), max=round(max(r), 3),
                   jitter=round(statistics.mean(abs(a - b) for a, b in zip(r, r[1:])), 3) if len(r) > 1 else 0.0)
        out["error"] = None if out["received"] == out["sent"] else out["error"]
    return out


def traceroute(net: Network, src: str, target: str) -> dict:
    out = {"target": target, "ip": None, "hops": [], "reached": False, "path": [], "error": None}
    ip, _, err = resolve_target(net, src, target)
    if err:
        out["error"] = err
        return out
    out["ip"] = ip
    d = net.deliver(src, ip)
    out["path"] = d.nodes
    if not d.ok:
        out["error"] = d.reason
        # still show the routers that were reached
    cum, nodes, links = 0.0, d.nodes, d.links
    # cumulative one-way delay at each router reached
    li = 0
    delays = {}
    acc = 0.0
    for i, n in enumerate(nodes):
        acc += net.path_delay([n], [])
        if i > 0 and li < len(links):
            acc += net.links[links[li]].delay_ms
            li += 1
        delays[n] = acc
    for idx, (router, ing) in enumerate(d.hops, 1):
        out["hops"].append({"hop": idx, "node": router, "ip": ing or net.primary_ip(router),
                            "rtt": round(2 * delays.get(router, 0), 3)})
    if d.ok:
        owner = net.owner_of_ip(ip)
        if owner and (not d.hops or d.hops[-1][0] != owner):
            out["hops"].append({"hop": len(d.hops) + 1, "node": owner, "ip": ip,
                                "rtt": round(2 * delays.get(owner, 0), 3)})
        out["reached"] = True
    return out
