"""Performance measurements: latency, jitter, loss, throughput, DHCP/DNS timing, cache-hit ratio,
and routing convergence. Throughput is *modelled* (window/RTT and Mathis loss limits), not measured
on a real wire - see README."""
from __future__ import annotations

import math
import statistics

from .services import dhcp_request, dns_query
from .tools import ping
from .topology import PCS, INET_IP, boot_all, build_smallbiz

WINDOW_BYTES = 65535
MSS = 1460
EFFICIENCY = 0.94      # TCP/IP header overhead


def _fresh(seed=42):
    net = build_smallbiz(seed)
    boot_all(net)
    net.clear_log()
    return net


def _lat(net, src, dst, n=100):
    r = ping(net, src, dst, n)
    return {"min": r["min"], "avg": r["avg"], "max": r["max"], "jitter": r["jitter"],
            "loss_pct": r["loss_pct"], "n": n}


def _lat_tcp(net, src, dst, port=80, n=100):
    rtts = []
    for _ in range(n):
        rt = net.round_trip(src, dst, proto="tcp", dport=port)
        if rt.ok:
            rtts.append(round(rt.rtt_ms, 3))
    if not rtts:
        return {"min": None, "avg": None, "max": None, "jitter": None, "loss_pct": 100.0, "n": n}
    return {"min": round(min(rtts), 3), "avg": round(sum(rtts) / len(rtts), 3),
            "max": round(max(rtts), 3),
            "jitter": round(statistics.mean(abs(a - b) for a, b in zip(rtts, rtts[1:])), 3) if len(rtts) > 1 else 0.0,
            "loss_pct": round(100 * (n - len(rtts)) / n, 1), "n": n}


def tcp_throughput(bottleneck_mbps, rtt_ms, loss_p):
    window_limit = WINDOW_BYTES * 8 / (rtt_ms * 1000.0)
    limit = min(bottleneck_mbps, window_limit)
    if loss_p > 0:
        limit = min(limit, 1.22 * MSS * 8 / ((rtt_ms / 1000.0) * math.sqrt(loss_p)) / 1e6)
    return round(limit * EFFICIENCY, 2)


def convergence(mode: str) -> dict:
    net = _fresh()
    net.set_routing_mode(mode)
    net.set_link("R1~R3", False)
    step, horizon = 50, 10000
    lost = total = 0
    conv = None
    t = 0
    while t < horizon:
        ok = net.round_trip("EMP-PC1", INET_IP).ok
        total += 1
        if ok:
            conv = conv if conv is not None else t
        else:
            lost += 1
        net.advance(step)
        t += step
    return {"mode": mode, "convergence_ms": conv, "probes": total, "lost": lost,
            "loss_pct": round(100 * lost / total, 1)}


def run_performance() -> dict:
    res = {}
    net = _fresh()
    emp2 = net.nodes["EMP-PC2"].ip
    res["latency"] = [
        {"scenario": "Same subnet (EMP-PC1 to EMP-PC2)", **_lat(net, "EMP-PC1", emp2)},
        {"scenario": "Across subnets (EMP-PC1 to WEB-SRV)", **_lat(net, "EMP-PC1", "10.10.1.100")},
        {"scenario": "Management to Servers (MGT-PC1 to MAIL-SRV)", **_lat(net, "MGT-PC1", "10.10.1.101")},
        {"scenario": "To the Internet via R1-R3 (EMP-PC1)", **_lat(net, "EMP-PC1", INET_IP)},
        {"scenario": "External PC to Web Server via NAT (EXT-PC)", **_lat_tcp(net, "EXT-PC", "198.51.100.2", 80)},
    ]
    # throughput model
    rows = []
    for label, dst in (("Same subnet", emp2), ("EMP to Servers", "10.10.1.100"), ("EMP to Internet", INET_IP)):
        rt = net.round_trip("EMP-PC1", dst)
        rows.append({"scenario": label, "bottleneck_mbps": rt.bottleneck_mbps, "rtt_ms": round(rt.rtt_ms, 2),
                     "loss_pct": 0.0, "tcp_mbps": tcp_throughput(rt.bottleneck_mbps, rt.rtt_ms, 0.0)})
    lossy = _fresh()
    lossy.links["R1~R3"].loss = 0.01
    rt = lossy.round_trip("EMP-PC1", INET_IP)
    rows.append({"scenario": "EMP to Internet, 1% WAN loss", "bottleneck_mbps": rt.bottleneck_mbps,
                 "rtt_ms": round(rt.rtt_ms, 2), "loss_pct": 2.0,
                 "tcp_mbps": tcp_throughput(rt.bottleneck_mbps, rt.rtt_ms, 0.0199)})
    res["throughput"] = rows

    # DHCP: full DORA time
    times = []
    for pc in PCS:
        n2 = _fresh()
        times.append(dhcp_request(n2, pc)["ms"])
    n3 = _fresh()
    n3.set_node("DHCP-SRV", False)
    fb = dhcp_request(n3, "EMP-PC1")["ms"]
    res["dhcp"] = {"dora_avg_ms": round(statistics.mean(times), 2), "dora_max_ms": round(max(times), 2),
                   "timeout_to_apipa_ms": round(fb, 0), "clients": len(times)}

    # DNS: authoritative vs forwarded vs cached + hit ratio over a mixed workload
    n4 = _fresh()
    auth = dns_query(n4, "EMP-PC1", "www.smallbiz.local")["ms"]
    cold = dns_query(n4, "EMP-PC1", "www.example.com")["ms"]
    warm = dns_query(n4, "EMP-PC2", "www.example.com")["ms"]
    names = ["www.example.com", "mail.example.com", "news.example.org", "cdn.example.net",
             "docs.example.com"]
    weights = [0.40, 0.20, 0.20, 0.10, 0.10]
    n5 = _fresh()
    pcs = ["EMP-PC1", "EMP-PC2", "EMP-PC3", "MGT-PC1", "MGT-PC2"]
    for i in range(200):
        nm = n5.rng.choices(names, weights)[0]
        dns_query(n5, pcs[i % 5], nm)
    st = n5.svc["dns"].stats
    ext = st["cache_hits"] + st["cache_misses"]
    res["dns"] = {"authoritative_ms": round(auth, 2), "forwarded_ms": round(cold, 2),
                  "cached_ms": round(warm, 2), "external_queries": ext, "cache_hits": st["cache_hits"],
                  "cache_hit_ratio_pct": round(100 * st["cache_hits"] / ext, 1) if ext else 0.0}

    res["convergence"] = [convergence("ospf"), convergence("static")]
    return res
