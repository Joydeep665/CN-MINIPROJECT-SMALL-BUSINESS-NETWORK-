# SmallBiz network lab

A pure-Python simulation of a small business network with automatic addressing (DHCP with relay),
name resolution (DNS), a web server, email (SMTP and POP3), routing (OSPF-style and static), and an
access list, plus a browser dashboard that draws the topology and shows every packet.

**This is a simulation, not a real network.** No sockets are opened and no real packets are sent.
Delays, loss and routing convergence come from a model with a fixed random seed, so results are
reproducible. Say this plainly in your report and demo; evaluators respect it and it protects you
in the viva.

## Run it

```bash
pip install -r requirements.txt
python app.py                 # then open http://127.0.0.1:5000
python run_tests.py --perf --pcap   # writes results/test_report.md, performance.csv/json, demo.pcap
python -m pytest tests        # same test cases under pytest
```

Python 3.9+. Flask is required; scapy (for the .pcap export) and pytest are optional.

## Network design

| Segment | Network | Usable range | Gateway | Notes |
|---|---|---|---|---|
| Employees | 10.10.1.0/26 | .1 - .62 | 10.10.1.1 | DHCP pool .10 - .62 |
| Management | 10.10.1.64/27 | .65 - .94 | 10.10.1.65 | DHCP pool .70 - .94 |
| Servers | 10.10.1.96/28 | .97 - .110 | 10.10.1.97 | static: DHCP .98, DNS .99, Web .100, Mail .101 |
| R1 - R3 | 198.51.100.0/30 | .1 - .2 | | primary WAN link (R3 = .1, R1 = .2; company public IP 198.51.100.2; cost 10) |
| R1 - R2 | 10.10.2.0/30 | .1 - .2 | | backup path |
| R2 - R3 | 10.10.2.4/30 | .5 - .6 | | backup path (R1-R2-R3 costs 20) |
| Outside / Internet | 203.0.113.0/26 | .1 - .62 | 203.0.113.1 | INET-HOST (.10, public DNS/web/mail), EXT-PC (.50, static external PC) |

The three internal LANs use VLSM out of 10.10.1.0/24. R1 is the edge router and DHCP relay
(`ip helper-address`): DHCP lives in the Servers subnet, so Discover/Request are relayed to it.
R3 is the ISP-facing router connecting the business to the external network.

### Static NAT & Inbound WAN ACL
The company is accessed externally via its single public IP `198.51.100.2` on R1's WAN interface.
R1 implements static NAT (port forwarding):
* `198.51.100.2:80` &rarr; `WEB-SRV 10.10.1.100:80`
* `198.51.100.2:25` &rarr; `MAIL-SRV 10.10.1.101:25`

Return traffic is translated back so the client sees replies from `198.51.100.2`.
R1 enforces an inbound WAN ACL (`ACL-WAN-IN`): only published ports 80 and 25 are permitted.
All other traffic (ICMP ping to public IP, POP3 port 110, DNS port 53, direct access to internal
10.0.0.0/8 networks) is blocked. Private LAN addresses are non-routable from the Internet.

### Split-Horizon DNS
* **Internal DNS (`DNS-SRV` 10.10.1.99):** Resolves `www.smallbiz.local` and `mail.smallbiz.local`
  to internal private addresses `10.10.1.100` and `10.10.1.101`.
* **Public DNS (`INET-HOST` 203.0.113.10):** Resolves `www.smallbiz.local` and `mail.smallbiz.local`
  to the company's public IP `198.51.100.2`, and provides MX record `smallbiz.local` &rarr; `mail.smallbiz.local`.

### Failover via R2 (Stretch Goal)
When the primary R1-R3 link fails, OSPF converges in ~3.7 s to route WAN traffic via R2
(R3 &rarr; R2 &rarr; R1). The public website and inbound mail remain fully accessible from outside
over the backup path.

## What is modelled

| Area | How |
|---|---|
| Layer 2 | Hosts and switches per segment; shortest-delay path over links that are up |
| Layer 3 | Hop-by-hop forwarding using per-router tables; Dijkstra over link costs |
| OSPF mode | After a link change, tables are recomputed only after a dead-timer detection (hello 1 s, dead 4 s) plus SPF delay, so packets are dropped on stale routes until it converges |
| Static mode | Tables are fixed when configured and never adapt |
| NAT / ACL | Static port forwarding (80 & 25) on R1 WAN ingress; stateful ACLs matching segment, protocol, port, and IP network |
| DHCP | Discover, Offer, Request, Ack through the relay; per-segment pools; APIPA fallback (169.254.x.x) after timeouts |
| DNS | Split-horizon: internal `DNS-SRV` and public `INET-HOST` (authoritative A, MX, CNAME, NXDOMAIN), forwarder with TTL cache |
| Web | TCP handshake, HTTP GET and response, 404s, connection refused or timeout |
| Email | SMTP dialogue, POP3 retrieval with login, MX lookup for external domains, retry queue when the Internet is unreachable |
| Throughput | **Modelled**, not measured: min(bottleneck bandwidth, 64 KB window / RTT, Mathis loss limit) x 0.94 |

## Files

```
app.py                  Flask API and dashboard server
netsim/network.py       topology, forwarding, routing, ACL, NAT, packet log
netsim/services.py      DHCP, DNS, web, SMTP/POP3 servers and client functions
netsim/topology.py      builds the SmallBiz network (R1, R2, R3, EXT-PC)
netsim/tools.py         ping, traceroute
netsim/testsuite.py     24 test cases (normal, failure, and external outside-in)
netsim/perf.py          latency, jitter, loss, throughput, DHCP/DNS timing, convergence
netsim/export_pcap.py   writes the packet log to a Wireshark-readable .pcap
static/                 dashboard (index.html, style.css, app.js)
tests/                  pytest wrapper
run_tests.py            writes report-ready files into results/
```

## Dashboard guide

- **Topology:** click a link or device to select it, then fail/restore it or power it off. Dots show packet paths. Outside / Internet zone contains INET-HOST and EXT-PC.
- **Lab tab:** pick a source PC (Internal LAN or External), then run DHCP, ping, traceroute, DNS lookups, web requests and email. The "Break something" switches create failures. In OSPF mode use "+1 s" / "+5 s" to watch routing converge.
- **External view tab:** view the network from outside as EXT-PC (`203.0.113.50`). One-click "Run outside-in check" validates web via NAT, public DNS/MX, inbound email, private address isolation, WAN ACL blocking, POP3 rejection, and boundary-stopping traceroute.
- **Packets tab:** Wireshark-style list with protocol fields for each message, including NAT translation details (`198.51.100.2:port` &rarr; `internal:port`). Click a row to highlight its path.
- **Addressing tab:** subnet table, device addresses, routing tables, ACL, DHCP leases, DNS cache.
- **Tests / Performance tabs:** run the 24 test cases and measurements with one click.

## Wireshark evidence

Click "Download .pcap" (or `python run_tests.py --pcap`) and open the file in Wireshark. It contains real
DHCP, DNS, ICMP, TCP, HTTP, SMTP and POP3 layouts, so the dissectors decode them, but the packets are
**synthesised from the simulation log**, with simulated timestamps and MAC addresses. They are not a live
capture. Describe them that way. If your course requires captures from a real network, use
Mininet or Packet Tracer as well (see the earlier discussion).

## Mapping to the rubric (mini-project, 10 marks)

- **PPT (3):** objectives, topology, addressing table, protocol flows (screenshots of the Packets tab with NAT details), test results (24 cases), performance charts.
- **Report (3):** use `results/test_report.md` and `results/performance.csv`, dashboard screenshots, this README's design tables, references, team contribution table.
- **Demo (4):** 5-minute script: topology with R1-R2-R3 and EXT-PC (30 s), DHCP renew (1 min), DNS then web by name (1 min), email send and POP3 check (1 min), external view check & NAT (1 min), one failure (cut R1-R3 then +5 s to show OSPF failover via R2) (1 min), packet view and `.pcap` (30 s). Every member should be able to run any step.

## Team contribution (fill in)

| Member | Area | Files / work |
|---|---|---|
| | Addressing, routing, ACL, NAT | |
| | DHCP and DNS | |
| | Web and email | |
| | Tests, performance, Wireshark | |
| | Dashboard, report, PPT | |

## Likely viva questions

Why /26, /27, /28? What does DHCP relay do and why is it needed here? What is giaddr? Why does the
mail server need an MX record? What happens to a client if DHCP is down? Why does OSPF recover from a
link failure but static routing does not? What does the ACL do and why is it applied inbound on the
Employees interface? What does the DNS cache save you? How does static NAT/port forwarding enable
external access to internal servers while keeping private IP addresses hidden and protected? Why is
split-horizon DNS necessary when using NAT?

## Limitations (state these)

Single-process simulation; NAT is static port forwarding only (no dynamic PAT/overload for outbound
internal clients); ACLs are stateful by assumption; OSPF is a timing model of detection
plus SPF, not a full protocol implementation (no LSAs or DR election); throughput is modelled; DHCP
renewal and lease expiry are not simulated; no encryption (SMTP/POP3/HTTP are plain text).
