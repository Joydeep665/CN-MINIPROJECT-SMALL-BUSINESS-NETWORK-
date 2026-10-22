"""Run every test case and (optionally) the performance measurements, and write report-ready files.

    python run_tests.py            # test report  -> results/test_report.md
    python run_tests.py --perf     # also performance -> results/performance.json + .csv
    python run_tests.py --pcap     # also export a demo capture -> results/demo.pcap
"""
import csv
import json
import os
import sys

from netsim import testsuite

os.makedirs("results", exist_ok=True)
res = testsuite.run_all()
lines = ["# Test report", "", f"{sum(r['passed'] for r in res)} of {len(res)} test cases passed.", "",
         "| ID | Type | Test | Expected | Observed | Result |", "|---|---|---|---|---|---|"]
for r in res:
    print(("PASS" if r["passed"] else "FAIL"), r["id"], r["name"])
    lines.append(f"| {r['id']} | {r['category']} | {r['name']} | {r['expected']} | {r['actual']} | "
                 f"{'PASS' if r['passed'] else 'FAIL'} |")
open("results/test_report.md", "w").write("\n".join(lines) + "\n")
print("wrote results/test_report.md")

if "--perf" in sys.argv:
    from netsim.perf import run_performance
    p = run_performance()
    json.dump(p, open("results/performance.json", "w"), indent=2)
    with open("results/performance.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scenario", "min_ms", "avg_ms", "max_ms", "jitter_ms", "loss_pct"])
        for x in p["latency"]:
            w.writerow([x["scenario"], x["min"], x["avg"], x["max"], x["jitter"], x["loss_pct"]])
        w.writerow([])
        w.writerow(["throughput scenario", "bottleneck_mbps", "rtt_ms", "loss_pct", "tcp_mbps"])
        for x in p["throughput"]:
            w.writerow([x["scenario"], x["bottleneck_mbps"], x["rtt_ms"], x["loss_pct"], x["tcp_mbps"]])
        w.writerow([])
        w.writerow(["routing mode", "convergence_ms", "probe_loss_pct"])
        for c in p["convergence"]:
            w.writerow([c["mode"], c["convergence_ms"] if c["convergence_ms"] is not None else "never", c["loss_pct"]])
    print("wrote results/performance.json and results/performance.csv")

if "--pcap" in sys.argv:
    from netsim import build_smallbiz, boot_all
    from netsim.export_pcap import build_pcap
    from netsim.services import dns_query, fetch_mail, http_get, send_mail
    from netsim.tools import ping
    net = build_smallbiz(); boot_all(net)
    ping(net, "EMP-PC1", "www.smallbiz.local", 4)
    dns_query(net, "EMP-PC1", "smallbiz.local", "MX")
    http_get(net, "EMP-PC1", "http://www.smallbiz.local/")
    send_mail(net, "EMP-PC1", "alice@smallbiz.local", "carol@smallbiz.local", "Weekly report", "Figures attached.")
    fetch_mail(net, "MGT-PC1", "carol", "carol123")
    build_pcap(net.log, "results/demo.pcap")
    print("wrote results/demo.pcap")
