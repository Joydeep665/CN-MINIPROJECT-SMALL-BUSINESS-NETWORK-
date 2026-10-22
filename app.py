"""Flask API + dashboard for the SmallBiz network simulation.

Run:  python app.py      then open http://127.0.0.1:5000
"""
from __future__ import annotations

import threading
import traceback

from flask import Flask, Response, jsonify, request

from netsim import boot_all, build_smallbiz
from netsim import perf, testsuite
from netsim.services import (DOMAIN, dhcp_request, dns_query, fetch_mail, flush_mail_queue, http_get,
                             send_mail)
from netsim.tools import ping, traceroute

app = Flask(__name__, static_folder="static", static_url_path="")
LOCK = threading.RLock()
STATE = {"net": None}


def fresh(mode="ospf"):
    net = build_smallbiz()
    boot_all(net)
    net.clear_log()
    if mode != "ospf":
        net.set_routing_mode(mode)
    STATE["net"] = net


fresh()


def net():
    return STATE["net"]


def api(fn):
    def wrapper(*a, **kw):
        with LOCK:
            try:
                return jsonify(fn(*a, **kw))
            except KeyError as e:
                return jsonify({"error": f"unknown item {e}"}), 404
            except Exception as e:      # surface errors in the UI instead of a blank 500
                traceback.print_exc()
                return jsonify({"error": str(e)}), 500
    wrapper.__name__ = fn.__name__
    return wrapper


def snapshot():
    n = net()
    nodes = []
    for x in n.nodes.values():
        nodes.append({"name": x.name, "kind": x.kind, "x": x.x, "y": x.y, "segment": x.segment, "up": x.up,
                      "ip": x.ip, "mask": x.mask, "gw": x.gw, "dns": x.dns, "apipa": x.apipa,
                      "role": x.role, "mac": x.mac,
                      "ifaces": [{"segment": s, "ip": str(i)} for s, i in x.ifaces.items()],
                      "helpers": x.helpers})
    links = [{"id": l.id, "a": l.a, "b": l.b, "segment": l.segment, "up": l.up, "delay_ms": l.delay_ms,
              "bw_mbps": l.bw_mbps, "loss": l.loss, "cost": l.cost} for l in n.links.values()]
    subnets = []
    for seg, net_ in n.subnets.items():
        hosts = net_.num_addresses - 2 if net_.prefixlen < 31 else net_.num_addresses
        first = str(net_.network_address + 1)
        last = str(net_.broadcast_address - 1)
        subnets.append({"segment": seg, "label": n.subnet_labels[seg], "cidr": str(net_),
                        "mask": str(net_.netmask), "hosts": hosts, "range": f"{first} - {last}",
                        "broadcast": str(net_.broadcast_address)})
    routes = {}
    for r, table in n.route_tables.items():
        rows = []
        for seg, (out_seg, nxt) in table.items():
            rows.append({"dest": str(n.subnets[seg]), "label": n.subnet_labels[seg],
                         "via": "directly connected" if nxt is None else
                         f"{nxt} ({str(n.nodes[nxt].ifaces[out_seg].ip)})"})
        routes[r] = rows
    dhcp, dns = n.svc["dhcp"], n.svc["dns"]
    return {
        "nodes": nodes, "links": links, "subnets": subnets, "routes": routes,
        "acls": [{"name": a["name"], "in_seg": a["in_seg"], "src": str(a["src"]), "dst": str(a["dst"]),
                  "action": a["action"], "remark": a["remark"]} for a in n.acls],
        "routing_mode": n.routing_mode, "clock_ms": round(n.clock, 1),
        "converging": bool(n._pending),
        "ospf": n.ospf,
        "dhcp": {"leases": [{"mac": m, **l} for m, l in dhcp.leases.items()], "stats": dhcp.stats},
        "dns": {"stats": dns.stats, "cache": [{"name": k[0], "type": k[1]} for k in dns.cache],
                "zone": [r for recs in dns.zone.values() for r in recs]},
        "mail": {node: {"queue": len(ms.queue), "domain": ms.domain,
                        "mailboxes": {u: len(b) for u, b in ms.mailboxes.items()}}
                 for node, ms in n.mail_servers.items()},
        "pcs": [x.name for x in n.nodes.values() if x.kind == "pc"],
        "domain": DOMAIN,
    }


def packet_rows(since=0):
    rows = []
    for r in net().log:
        if r["no"] <= since:
            continue
        meta = {k: v for k, v in r["meta"].items() if k != "payload"}
        if r["meta"].get("payload"):
            meta["payload"] = r["meta"]["payload"][:600]
        rows.append({**{k: r[k] for k in ("no", "t", "src", "dst", "src_name", "dst_name", "proto",
                                           "length", "info", "path", "ok")}, "meta": meta})
    return rows


@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.get("/api/state")
@api
def state():
    return snapshot()


@app.post("/api/reset")
@api
def reset():
    fresh((request.json or {}).get("mode", "ospf"))
    return snapshot()


@app.post("/api/link")
@api
def link():
    d = request.json
    net().set_link(d["id"], bool(d["up"]))
    return snapshot()


@app.post("/api/node")
@api
def node():
    d = request.json
    net().set_node(d["name"], bool(d["up"]))
    return snapshot()


@app.post("/api/routing")
@api
def routing():
    net().set_routing_mode(request.json["mode"])
    return snapshot()


@app.post("/api/advance")
@api
def advance():
    net().advance(float(request.json.get("ms", 1000)))
    return snapshot()


@app.post("/api/dhcp")
@api
def dhcp():
    return dhcp_request(net(), request.json["host"], renew=True)


@app.post("/api/dns")
@api
def dns():
    d = request.json
    return dns_query(net(), d["host"], d["name"], d.get("type", "A"))


@app.post("/api/ping")
@api
def do_ping():
    d = request.json
    return ping(net(), d["host"], d["target"], int(d.get("count", 4)))


@app.post("/api/traceroute")
@api
def do_trace():
    d = request.json
    return traceroute(net(), d["host"], d["target"])


@app.post("/api/http")
@api
def do_http():
    d = request.json
    return http_get(net(), d["host"], d["url"])


@app.post("/api/mail/send")
@api
def mail_send():
    d = request.json
    return send_mail(net(), d["host"], d["from"], d["to"], d.get("subject", ""), d.get("body", ""))


@app.post("/api/mail/fetch")
@api
def mail_fetch():
    d = request.json
    return fetch_mail(net(), d["host"], d["user"], d["password"])


@app.post("/api/mail/flush")
@api
def mail_flush():
    return {"results": flush_mail_queue(net(), "MAIL-SRV")}


@app.get("/api/packets")
@api
def packets():
    return {"packets": packet_rows(int(request.args.get("since", 0)))}


@app.post("/api/packets/clear")
@api
def packets_clear():
    net().clear_log()
    return {"ok": True}


@app.get("/api/pcap")
def pcap():
    with LOCK:
        try:
            from netsim.export_pcap import build_pcap
            data = build_pcap(net().log)
        except ImportError:
            return Response("scapy is not installed (pip install scapy)", status=501)
    return Response(data, mimetype="application/vnd.tcpdump.pcap",
                    headers={"Content-Disposition": "attachment; filename=smallbiz_sim.pcap"})


@app.post("/api/tests/run")
@api
def run_tests():
    res = testsuite.run_all()
    return {"results": res, "passed": sum(r["passed"] for r in res), "total": len(res)}


@app.post("/api/perf/run")
@api
def run_perf():
    return perf.run_performance()


@app.post("/api/ext/check")
@api
def ext_check():
    n = net()
    checks = []

    # 1) Browse http://www.smallbiz.local
    w = http_get(n, "EXT-PC", "http://www.smallbiz.local/")
    checks.append({
        "id": 1,
        "test": "Browse http://www.smallbiz.local",
        "target": "http://www.smallbiz.local",
        "ok": bool(w["ok"] and w.get("status") == 200),
        "result": f"200 OK via port forward 80 -> 10.10.1.100 ({len(w.get('body', ''))} bytes in {w['ms']:.1f} ms)" if w["ok"] else w.get("reason", "failed"),
        "why": "via port forward 80 -> 10.10.1.100",
        "path": w.get("path", [])
    })

    # 2) Resolve www.smallbiz.local and MX
    d_a = dns_query(n, "EXT-PC", "www.smallbiz.local", "A")
    d_mx = dns_query(n, "EXT-PC", "smallbiz.local", "MX")
    a_val = d_a["answers"][0]["value"] if d_a.get("answers") else None
    mx_val = d_mx["answers"][0]["value"] if d_mx.get("answers") else None
    d_ok = bool(a_val == "198.51.100.2" and mx_val == "mail.smallbiz.local")
    checks.append({
        "id": 2,
        "test": "Resolve www.smallbiz.local and MX",
        "target": "www.smallbiz.local, smallbiz.local (MX)",
        "ok": d_ok,
        "result": f"A -> {a_val}, MX -> {mx_val}",
        "why": "public IP / mail.smallbiz.local",
        "path": d_a.get("path", [])
    })

    # 3) Send mail to carol@smallbiz.local
    m = send_mail(n, "EXT-PC", "partner@example.com", "carol@smallbiz.local",
                  "Outside Inquiry", "Checking product pricing and availability.")
    checks.append({
        "id": 3,
        "test": "Send mail to carol@smallbiz.local",
        "target": "carol@smallbiz.local",
        "ok": bool(m["status"] == "delivered"),
        "result": "delivered" if m["status"] == "delivered" else m.get("reason", m["status"]),
        "why": "delivered",
        "path": m.get("path", [])
    })

    # 4) Ping 10.10.1.100 and 10.10.1.70
    p_srv = ping(n, "EXT-PC", "10.10.1.100", 2)
    p_mgt = ping(n, "EXT-PC", "10.10.1.70", 2)
    p_priv_ok = bool((p_srv["received"] == 0 and "private address" in (p_srv["error"] or "")) and
                     (p_mgt["received"] == 0 and "private address" in (p_mgt["error"] or "")))
    checks.append({
        "id": 4,
        "test": "Ping 10.10.1.100 and 10.10.1.70",
        "target": "10.10.1.100, 10.10.1.70",
        "ok": p_priv_ok,
        "result": f"0/2 replies ({p_srv.get('error', 'blocked')})",
        "why": "blocked (private, not routable)",
        "path": p_srv.get("path", [])
    })

    # 5) Ping the public IP 198.51.100.2
    p_pub = ping(n, "EXT-PC", "198.51.100.2", 2)
    p_pub_ok = bool(p_pub["received"] == 0 and "prohibited" in (p_pub["error"] or ""))
    checks.append({
        "id": 5,
        "test": "Ping the public IP 198.51.100.2",
        "target": "198.51.100.2",
        "ok": p_pub_ok,
        "result": f"0/2 replies ({p_pub.get('error', 'blocked')})",
        "why": "blocked by WAN ACL",
        "path": p_pub.get("path", [])
    })

    # 6) Connect to POP3 (port 110) on public IP
    pop = fetch_mail(n, "EXT-PC", "carol", "carol123", pop_host="mail.smallbiz.local")
    checks.append({
        "id": 6,
        "test": "Connect to POP3 (port 110) on public IP",
        "target": "198.51.100.2:110",
        "ok": bool(not pop["ok"]),
        "result": "blocked / connection failed" if not pop["ok"] else "connected",
        "why": "blocked, not published",
        "path": pop.get("path", [])
    })

    # 7) Traceroute to www.smallbiz.local
    tr = traceroute(n, "EXT-PC", "www.smallbiz.local")
    hops_str = " -> ".join([h["node"] for h in tr.get("hops", [])])
    tr_ok = bool(tr.get("hops") and tr["hops"][-1]["node"] == "R1" and not any(h["node"] in ("WEB-SRV", "SW-SRV") for h in tr["hops"]))
    checks.append({
        "id": 7,
        "test": "Traceroute to www.smallbiz.local",
        "target": "www.smallbiz.local (198.51.100.2)",
        "ok": tr_ok,
        "result": f"stops at {hops_str}",
        "why": "stops at R1, internal hops are not shown",
        "path": tr.get("path", [])
    })

    return {"checks": checks, "passed": sum(c["ok"] for c in checks), "total": len(checks)}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
