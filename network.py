"""Core network simulation engine.

Models a small enterprise network at the packet-path level:

* Layer 2 segments (switches, hosts) with link state, delay, bandwidth and loss
* Layer 3 forwarding through routers using per-router routing tables
* An OSPF-style routing model (dead-timer detection + SPF delay) and a static mode
* Stateful-style ACLs evaluated on router ingress
* A packet log used by the front end and the .pcap exporter

It is a *simulation*: no real sockets or packets are sent. All timing comes from
the link parameters below plus a seeded random generator, so results are
reproducible.
"""
from __future__ import annotations

import hashlib
import heapq
import ipaddress
import random
from dataclasses import dataclass, field
from typing import Optional

PROC_MS = {"router": 0.30, "switch": 0.05, "pc": 0.02, "server": 0.05, "internet": 0.05}


def mac_of(name: str) -> str:
    """Deterministic, locally-administered MAC address derived from a device name."""
    h = hashlib.md5(name.encode()).hexdigest()
    return ":".join(["02"] + [h[i:i + 2] for i in range(0, 10, 2)])


@dataclass
class Link:
    id: str
    a: str
    b: str
    segment: str
    delay_ms: float = 0.5
    bw_mbps: float = 100.0
    loss: float = 0.0          # probability 0..1 per traversal
    cost: int = 10             # OSPF cost (router-router links only)
    up: bool = True

    def other(self, n: str) -> str:
        return self.b if n == self.a else self.a


@dataclass
class Node:
    name: str
    kind: str                   # router | switch | pc | server | internet
    x: float = 0.0
    y: float = 0.0
    segment: Optional[str] = None
    up: bool = True
    ip: Optional[str] = None
    mask: Optional[str] = None
    gw: Optional[str] = None
    dns: Optional[str] = None
    apipa: bool = False
    role: str = ""
    ifaces: dict = field(default_factory=dict)    # segment -> IPv4Interface (routers)
    helpers: dict = field(default_factory=dict)   # segment -> DHCP server IP (ip helper-address)

    @property
    def mac(self) -> str:
        return mac_of(self.name)


@dataclass
class Delivery:
    ok: bool
    reason: str = ""
    nodes: list = field(default_factory=list)
    links: list = field(default_factory=list)
    one_way_ms: float = 0.0
    hops: list = field(default_factory=list)      # [(router, ingress_ip)]
    blocked_by: Optional[str] = None
    loss_p: float = 0.0
    bottleneck_mbps: float = 1000.0


@dataclass
class RoundTrip:
    ok: bool
    reason: str = ""
    rtt_ms: float = 0.0
    nodes: list = field(default_factory=list)
    links: list = field(default_factory=list)
    hops: list = field(default_factory=list)
    blocked_by: Optional[str] = None
    loss_p: float = 0.0
    bottleneck_mbps: float = 1000.0


class Network:
    def __init__(self, seed: int = 42):
        self.seed = seed
        self.rng = random.Random(seed)
        self.nodes: dict[str, Node] = {}
        self.links: dict[str, Link] = {}
        self.subnets: dict[str, ipaddress.IPv4Network] = {}
        self.subnet_labels: dict[str, str] = {}
        self.acls: list[dict] = []
        self.clock = 0.0                       # simulated time in ms
        self.routing_mode = "ospf"             # "ospf" | "static"
        self.ospf = {"hello_ms": 1000, "dead_ms": 4000, "spf_ms": 50}
        self.route_tables: dict = {}
        self._pending: list[float] = []
        self.log: list[dict] = []
        self._seq = 0
        self._t0 = 0.0
        self.svc: dict = {}                    # dhcp, dns
        self.web_servers: dict = {}
        self.mail_servers: dict = {}

    # ------------------------------------------------------------------ build
    def add_node(self, node: Node) -> Node:
        self.nodes[node.name] = node
        return node

    def add_link(self, a: str, b: str, segment: str, **kw) -> Link:
        link = Link(f"{a}~{b}", a, b, segment, **kw)
        self.links[link.id] = link
        return link

    def add_subnet(self, seg: str, cidr: str, label: str = "") -> None:
        self.subnets[seg] = ipaddress.ip_network(cidr)
        self.subnet_labels[seg] = label or seg

    def add_acl(self, name, in_seg, src, dst, action, remark="", proto=None, dport=None, router="R1") -> None:
        self.acls.append({"name": name, "in_seg": in_seg, "src": ipaddress.ip_network(src),
                          "dst": ipaddress.ip_network(dst), "action": action,
                          "remark": remark, "proto": proto, "dport": dport,
                          "router": router, "enabled": True})

    def nat_translate(self, dst_ip: str, dport: Optional[int]) -> Optional[str]:
        if not hasattr(self, "nat_port_forwards") or dport is None:
            return None
        return self.nat_port_forwards.get((dst_ip, dport))

    def build_routing(self) -> None:
        self.route_tables = self.compute_routes(ignore_state=(self.routing_mode == "static"))

    def segment_of_ip(self, ip: str) -> Optional[str]:
        for n in self.nodes.values():
            if n.ip == ip and n.segment:
                return n.segment
            for seg, itf in n.ifaces.items():
                if str(itf.ip) == ip:
                    return seg
        try:
            a = ipaddress.ip_address(ip)
            for seg, net in self.subnets.items():
                if a in net:
                    return seg
        except ValueError:
            pass
        return None

    def owner_of_ip(self, ip: str) -> Optional[str]:
        for n in self.nodes.values():
            if n.ip == ip:
                return n.name
            for itf in n.ifaces.values():
                if str(itf.ip) == ip:
                    return n.name
        return None

    def router_with_ip(self, ip: str) -> Optional[str]:
        for n in self.nodes.values():
            if n.kind == "router" and any(str(i.ip) == ip for i in n.ifaces.values()):
                return n.name
        return None

    def primary_ip(self, name: str) -> Optional[str]:
        n = self.nodes[name]
        if n.ip:
            return n.ip
        for itf in n.ifaces.values():
            return str(itf.ip)
        return None

    def relay_router(self, seg: str) -> Optional[str]:
        for n in self.nodes.values():
            if n.kind == "router" and seg in n.helpers:
                return n.name
        return None

    def link_between(self, a: str, b: str, seg: str) -> Optional[Link]:
        for l in self.links.values():
            if l.segment == seg and {l.a, l.b} == {a, b}:
                return l
        return None

    # --------------------------------------------------------------------- L2
    def l2_path(self, seg: str, a: str, b: str):
        """Lowest-delay path over *up* links of one segment. Returns (nodes, links) or None."""
        if not (self.nodes[a].up and self.nodes[b].up):
            return None
        if a == b:
            return [a], []
        adj: dict[str, list] = {}
        for l in self.links.values():
            if l.segment != seg or not l.up:
                continue
            if not (self.nodes[l.a].up and self.nodes[l.b].up):
                continue
            adj.setdefault(l.a, []).append(l)
            adj.setdefault(l.b, []).append(l)
        dist = {a: 0.0}
        prev: dict = {}
        pq = [(0.0, a)]
        while pq:
            d, u = heapq.heappop(pq)
            if u == b:
                break
            if d > dist.get(u, 1e18):
                continue
            for l in adj.get(u, []):
                v = l.other(u)
                nd = d + l.delay_ms
                if nd < dist.get(v, 1e18):
                    dist[v] = nd
                    prev[v] = (u, l)
                    heapq.heappush(pq, (nd, v))
        if b not in prev:
            return None
        nodes, links, cur = [b], [], b
        while cur != a:
            u, l = prev[cur]
            links.append(l)
            nodes.append(u)
            cur = u
        nodes.reverse()
        links.reverse()
        return nodes, links

    # --------------------------------------------------------------------- L3
    def compute_routes(self, ignore_state: bool = False) -> dict:
        """Shortest-path (SPF) routing tables: router -> {dest_segment: (out_segment, next_router)}."""
        routers = [n for n in self.nodes.values()
                   if n.kind == "router" and (ignore_state or n.up)]

        def link_ok(l: Link) -> bool:
            return ignore_state or (l.up and self.nodes[l.a].up and self.nodes[l.b].up)

        adj = {r.name: [] for r in routers}
        for l in self.links.values():
            if l.a in adj and l.b in adj and link_ok(l):
                adj[l.a].append((l.b, l.cost, l.segment))
                adj[l.b].append((l.a, l.cost, l.segment))
        attached = {r.name: set() for r in routers}
        for l in self.links.values():
            if not (ignore_state or l.up):
                continue
            for end in (l.a, l.b):
                if end in attached and l.segment in self.nodes[end].ifaces:
                    attached[end].add(l.segment)
        if "R1" in attached and self.nodes["R1"].up and "R1~R3" in self.nodes["R1"].ifaces:
            attached["R1"].add("R1~R3")
        tables = {}
        for r in routers:
            dist = {r.name: 0}
            first: dict = {r.name: None}
            pq = [(0, r.name)]
            while pq:
                d, u = heapq.heappop(pq)
                if d > dist[u]:
                    continue
                for v, c, seg in sorted(adj[u]):
                    nd = d + c
                    if nd < dist.get(v, 1e9):
                        dist[v] = nd
                        first[v] = first[u] if first[u] else (seg, v)
                        heapq.heappush(pq, (nd, v))
            table = {}
            for seg in self.subnets:
                best = None
                for r2, segs in attached.items():
                    if seg in segs and r2 in dist:
                        key = (dist[r2], r2)
                        if best is None or key < best[0]:
                            best = (key, r2)
                if best is None:
                    continue
                table[seg] = (None, None) if best[1] == r.name else first[best[1]]
            tables[r.name] = table
        return tables

    def check_acl(self, cur_router: str, in_seg: str, src_ip: str, dst_ip: str,
                  proto: Optional[str] = None, dport: Optional[int] = None):
        s, d = ipaddress.ip_address(src_ip), ipaddress.ip_address(dst_ip)
        for a in self.acls:
            if not a["enabled"] or a["in_seg"] != in_seg:
                continue
            if a.get("router") and a["router"] != cur_router:
                continue
            if s not in a["src"] or d not in a["dst"]:
                continue
            if a.get("proto") and proto and a["proto"].lower() != proto.lower():
                continue
            if a.get("dport") is not None:
                if dport is None or a["dport"] != dport:
                    continue
            if a.get("proto") and not proto:
                continue
            if a["action"] == "permit":
                return None
            if a["action"] == "deny":
                return a
        return None

    def path_delay(self, nodes, links, size=64) -> float:
        d = sum(l.delay_ms + size * 8 / (l.bw_mbps * 1000.0) for l in links)
        d += sum(PROC_MS.get(self.nodes[n].kind, 0.05) for n in nodes)
        return d

    def deliver(self, src: str, dst_ip: str, *, src_ip: Optional[str] = None,
                acl: bool = True, size: int = 64, proto: str = "ip", dport: Optional[int] = None) -> Delivery:
        """Walk one packet hop by hop from `src` to `dst_ip` using the *current* routing tables."""
        s = self.nodes[src]
        nodes = [src]
        lobjs: list[Link] = []
        hops: list = []
        nat_record = None

        def fail(reason, blocked=None):
            return Delivery(False, reason, list(nodes), [l.id for l in lobjs], 0.0, hops, blocked)

        def extend(seg, a, b):
            p = self.l2_path(seg, a, b)
            if p is None:
                return False
            nodes.extend(p[0][1:])
            lobjs.extend(p[1])
            return True

        def done():
            keep = 1.0
            for l in lobjs:
                keep *= (1 - l.loss)
            deliv = Delivery(True, "", list(nodes), [l.id for l in lobjs],
                            self.path_delay(nodes, lobjs, size), hops, None, 1 - keep,
                            min([l.bw_mbps for l in lobjs], default=1000.0))
            if nat_record:
                deliv.nat = nat_record
            deliv.effective_dst = dst_ip
            return deliv

        if not s.up:
            return fail(f"{src} is powered off")

        # Private addresses are not routable from the Internet
        try:
            d_addr = ipaddress.ip_address(dst_ip)
            if src == "EXT-PC" and d_addr in ipaddress.ip_network("10.0.0.0/8"):
                return fail("no route / private address")
        except ValueError:
            pass

        dst_seg = self.segment_of_ip(dst_ip)
        if dst_seg is None:
            return fail("Destination net unreachable (no matching network)")
        owner = self.owner_of_ip(dst_ip)

        if s.kind == "router":
            cur, seg_in, sip = src, None, src_ip or self.primary_ip(src)
        else:
            sip = src_ip or s.ip
            if not sip:
                return fail("source has no IP address")
            if dst_seg == s.segment:
                if owner is None:
                    return fail("Destination host unreachable (ARP failed)")
                if not extend(s.segment, src, owner):
                    return fail("Destination host unreachable (no layer-2 path)")
                return done()
            if not s.gw:
                return fail("no default gateway configured")
            gw = self.router_with_ip(s.gw)
            if gw is None or self.segment_of_ip(s.gw) != s.segment:
                return fail("default gateway unreachable (ARP failed)")
            if not extend(s.segment, src, gw):
                return fail("default gateway unreachable (no layer-2 path)")
            cur, seg_in = gw, s.segment

        for _ in range(16):
            r = self.nodes[cur]
            if not r.up:
                return fail(f"{cur} is powered off")
            if seg_in:
                hops.append((cur, str(r.ifaces[seg_in].ip)))
                if seg_in == "INET" and src == "EXT-PC":
                    try:
                        if ipaddress.ip_address(dst_ip) in ipaddress.ip_network("10.0.0.0/8"):
                            return fail("no route / private address")
                    except ValueError:
                        pass
                if acl:
                    rule = self.check_acl(cur, seg_in, sip, dst_ip, proto=proto, dport=dport)
                    if rule:
                        return fail(f"Destination administratively prohibited ({rule['name']} on {cur})",
                                    rule["name"])
            else:
                hops.append((cur, None))

            # Static NAT / port forwarding on R1 from WAN side
            if cur == "R1" and seg_in in ("R1~R3", "R1~R2") and hasattr(self, "nat_port_forwards"):
                trans = self.nat_port_forwards.get((dst_ip, dport))
                if trans:
                    nat_record = {"orig_dst": f"{dst_ip}:{dport}", "new_dst": f"{trans}:{dport}"}
                    dst_ip = trans
                    dst_seg = self.segment_of_ip(dst_ip)
                    owner = self.owner_of_ip(dst_ip)

            if dst_seg in r.ifaces:
                if owner is None:
                    return fail("Destination host unreachable (ARP failed)")
                if owner != cur and not extend(dst_seg, cur, owner):
                    return fail("Destination host unreachable (last-hop link or switch is down)")
                return done()
            entry = self.route_tables.get(cur, {}).get(dst_seg)
            if not entry or entry[1] is None:
                return fail(f"No route to {dst_ip} on {cur}")
            out_seg, nxt = entry
            l = self.link_between(cur, nxt, out_seg)
            if l is None or not l.up or not self.nodes[nxt].up:
                return fail(f"Packet dropped at {cur}: next hop {nxt} is unreachable (stale route)")
            nodes.append(nxt)
            lobjs.append(l)
            cur, seg_in = nxt, out_seg
        return fail("TTL expired in transit (routing loop)")

    def round_trip(self, src: str, dst_ip: str, size: int = 64, acl: bool = True,
                   src_ip: Optional[str] = None, proto: str = "ip", dport: Optional[int] = None) -> RoundTrip:
        fwd = self.deliver(src, dst_ip, size=size, acl=acl, src_ip=src_ip, proto=proto, dport=dport)
        if not fwd.ok:
            return RoundTrip(False, fwd.reason, 0.0, fwd.nodes, fwd.links, fwd.hops, fwd.blocked_by)
        effective_dst = getattr(fwd, "effective_dst", dst_ip)
        owner = self.owner_of_ip(effective_dst)
        sip = src_ip or self.primary_ip(src)
        rev = self.deliver(owner, sip, size=size, acl=False, proto=proto)
        if not rev.ok:
            return RoundTrip(False, "no return path: " + rev.reason, 0.0, fwd.nodes, fwd.links, fwd.hops)
        keep = (1 - fwd.loss_p) * (1 - rev.loss_p)
        if self.rng.random() > keep:
            return RoundTrip(False, "request timed out (packet lost)", 0.0, fwd.nodes, fwd.links,
                             fwd.hops, None, 1 - keep, min(fwd.bottleneck_mbps, rev.bottleneck_mbps))
        rtt = fwd.one_way_ms + rev.one_way_ms
        rtt += self.rng.uniform(0, 0.12 * rtt) + abs(self.rng.gauss(0, 0.03))
        rt = RoundTrip(True, "", rtt, fwd.nodes, fwd.links, fwd.hops, None, 1 - keep,
                       min(fwd.bottleneck_mbps, rev.bottleneck_mbps))
        if hasattr(fwd, "nat"):
            rt.nat = fwd.nat
        return rt

    # ------------------------------------------------------- state / routing
    def _schedule(self, went_down: bool) -> None:
        if self.routing_mode != "ospf":
            return
        o = self.ospf
        if went_down:                      # neighbour declared dead after the dead interval
            detect = self.rng.uniform(o["dead_ms"] - o["hello_ms"], o["dead_ms"])
        else:                              # adjacency needs ~2 hellos to come up
            detect = 2 * o["hello_ms"]
        self._pending.append(self.clock + detect + o["spf_ms"] + 5.0)

    def set_link(self, link_id: str, up: bool) -> None:
        l = self.links[link_id]
        if l.up != up:
            l.up = up
            self._schedule(not up)

    def set_node(self, name: str, up: bool) -> None:
        n = self.nodes[name]
        if n.up != up:
            n.up = up
            if n.kind in ("router", "switch"):
                self._schedule(not up)

    def set_routing_mode(self, mode: str) -> None:
        self.routing_mode = mode
        self._pending = []
        self.route_tables = self.compute_routes(ignore_state=(mode == "static"))

    def advance(self, ms: float) -> None:
        self.clock += ms
        if self._pending and min(self._pending) <= self.clock:
            self._pending = [d for d in self._pending if d > self.clock]
            self.route_tables = self.compute_routes()

    # -------------------------------------------------------------- packet log
    def record(self, src_ip, dst_ip, proto, info, nodes=None, length=64, ok=True,
               meta=None, src=None, dst=None) -> dict:
        self._seq += 1
        rec = {"no": self._seq, "t": round(self.clock - self._t0, 3), "src": src_ip, "dst": dst_ip,
               "src_name": src, "dst_name": dst, "proto": proto, "length": length, "info": info,
               "path": list(nodes or []), "ok": ok, "meta": meta or {}}
        self.log.append(rec)
        if len(self.log) > 3000:
            self.log = self.log[-3000:]
        return rec

    def clear_log(self) -> None:
        self.log = []
        self._seq = 0
        self._t0 = self.clock
