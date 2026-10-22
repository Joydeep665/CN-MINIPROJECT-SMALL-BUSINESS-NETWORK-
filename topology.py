"""Builds the SmallBiz reference network (topology, addressing, services, ACLs)."""
from __future__ import annotations

from .network import Network, Node
from .services import (DNSServer, DHCPServer, MailServer, Pool, WebServer, DOMAIN, dhcp_request)
import ipaddress

SRV_GW = "10.10.1.97"
DNS_IP = "10.10.1.99"
DHCP_IP = "10.10.1.98"
INET_IP = "203.0.113.10"

PCS = ["EMP-PC1", "EMP-PC2", "EMP-PC3", "MGT-PC1", "MGT-PC2"]

SITE_HTML = """<html><head><title>SmallBiz Ltd</title></head>
<body style="font-family:sans-serif;padding:24px">
<h1>SmallBiz Ltd - Intranet</h1>
<p>Welcome to the company web server (www.smallbiz.local).</p>
<ul><li><a href="/about">About us</a></li><li><a href="/staff">Staff directory</a></li></ul>
</body></html>"""

PAGES = {
    "/": SITE_HTML,
    "/about": "<html><body><h1>About SmallBiz</h1><p>A small business with a complete network.</p></body></html>",
    "/staff": "<html><body><h1>Staff</h1><p>alice, bob (employees) - carol, dave (management)</p></body></html>",
}


def _ifc(cidr):
    return ipaddress.ip_interface(cidr)


def build_smallbiz(seed: int = 42) -> Network:
    net = Network(seed)

    # ---- address plan (VLSM out of 10.10.1.0/24, plus two WAN /30s and a documentation "Internet")
    net.add_subnet("EMP", "10.10.1.0/26", "Employees")
    net.add_subnet("MGT", "10.10.1.64/27", "Management")
    net.add_subnet("SRV", "10.10.1.96/28", "Servers")
    net.add_subnet("R1~R3", "198.51.100.0/30", "R1 - R3 link")
    net.add_subnet("R1~R2", "10.10.2.0/30", "R1 - R2 link")
    net.add_subnet("R2~R3", "10.10.2.4/30", "R2 - R3 link")
    net.add_subnet("INET", "203.0.113.0/26", "Outside / Internet")

    # ---- devices (x, y are for the front-end drawing)
    R1 = net.add_node(Node("R1", "router", 480, 190, role="Edge router"))
    R1.ifaces = {"EMP": _ifc("10.10.1.1/26"), "MGT": _ifc("10.10.1.65/27"),
                 "SRV": _ifc("10.10.1.97/28"), "R1~R3": _ifc("198.51.100.2/30"),
                 "R1~R2": _ifc("10.10.2.1/30")}
    R1.helpers = {"EMP": DHCP_IP, "MGT": DHCP_IP}          # ip helper-address (DHCP relay)
    R2 = net.add_node(Node("R2", "router", 300, 70, role="Backup router"))
    R2.ifaces = {"R1~R2": _ifc("10.10.2.2/30"), "R2~R3": _ifc("10.10.2.5/30")}
    R3 = net.add_node(Node("R3", "router", 700, 70, role="ISP-facing router"))
    R3.ifaces = {"R1~R3": _ifc("198.51.100.1/30"), "R2~R3": _ifc("10.10.2.6/30"),
                 "INET": _ifc("203.0.113.1/26")}
    net.add_node(Node("INET-HOST", "internet", 880, 70, segment="INET", ip=INET_IP,
                      mask="255.255.255.192", gw="203.0.113.1", role="Internet web + mail host"))
    net.add_node(Node("EXT-PC", "pc", 880, 160, segment="INET", ip="203.0.113.50",
                      mask="255.255.255.192", gw="203.0.113.1", dns=INET_IP, role="External PC"))

    for name, x, seg in (("SW-EMP", 190, "EMP"), ("SW-MGT", 475, "MGT"), ("SW-SRV", 770, "SRV")):
        net.add_node(Node(name, "switch", x, 330, segment=seg, role="Access switch"))

    for name, x, y in (("EMP-PC1", 80, 480), ("EMP-PC2", 190, 520), ("EMP-PC3", 300, 480)):
        net.add_node(Node(name, "pc", x, y, segment="EMP", role="Employee PC"))
    for name, x, y in (("MGT-PC1", 420, 490), ("MGT-PC2", 530, 490)):
        net.add_node(Node(name, "pc", x, y, segment="MGT", role="Management PC"))
    for name, ip, x, y, role in (("DHCP-SRV", DHCP_IP, 650, 480, "DHCP server"),
                                 ("DNS-SRV", DNS_IP, 730, 520, "DNS server"),
                                 ("WEB-SRV", "10.10.1.100", 810, 520, "Web server"),
                                 ("MAIL-SRV", "10.10.1.101", 890, 480, "Mail server (SMTP/POP3)")):
        net.add_node(Node(name, "server", x, y, segment="SRV", ip=ip, mask="255.255.255.240",
                          gw=SRV_GW, dns=DNS_IP, role=role))

    # ---- links: (a, b, segment, delay ms, bandwidth Mbps, cost)
    L = net.add_link
    L("R1", "R3", "R1~R3", delay_ms=8, bw_mbps=100, cost=10)
    L("R1", "R2", "R1~R2", delay_ms=3, bw_mbps=100, cost=10)
    L("R2", "R3", "R2~R3", delay_ms=8, bw_mbps=100, cost=10)
    L("R3", "INET-HOST", "INET", delay_ms=2, bw_mbps=1000)
    L("R3", "EXT-PC", "INET", delay_ms=2, bw_mbps=1000)
    for sw, seg in (("SW-EMP", "EMP"), ("SW-MGT", "MGT"), ("SW-SRV", "SRV")):
        L("R1", sw, seg, delay_ms=0.2, bw_mbps=1000)
    for pc in PCS[:3]:
        L("SW-EMP", pc, "EMP", delay_ms=0.25, bw_mbps=100)
    for pc in PCS[3:]:
        L("SW-MGT", pc, "MGT", delay_ms=0.25, bw_mbps=100)
    for s in ("DHCP-SRV", "DNS-SRV", "WEB-SRV", "MAIL-SRV"):
        L("SW-SRV", s, "SRV", delay_ms=0.25, bw_mbps=1000)

    # ---- NAT / port forwarding on R1 for WAN ingress
    net.nat_port_forwards = {
        ("198.51.100.2", 80): "10.10.1.100",
        ("198.51.100.2", 25): "10.10.1.101",
    }

    # ---- security: Employees may not reach Management; everything else allowed
    net.add_acl("ACL-EMP-IN", "EMP", "10.10.1.0/26", "10.10.1.64/27", "deny",
                "Employees may not reach the Management subnet")

    # ---- security: WAN inbound ACL on R1 (permit only published services)
    for wan_seg in ("R1~R3", "R1~R2"):
        net.add_acl("ACL-WAN-IN", wan_seg, "0.0.0.0/0", "198.51.100.2/32", "permit",
                    "Permit HTTP (port 80) to published web server", proto="tcp", dport=80)
        net.add_acl("ACL-WAN-IN", wan_seg, "0.0.0.0/0", "198.51.100.2/32", "permit",
                    "Permit SMTP (port 25) to published mail server", proto="tcp", dport=25)
        net.add_acl("ACL-WAN-IN", wan_seg, "0.0.0.0/0", "0.0.0.0/0", "deny",
                    "Deny all other WAN ingress traffic (unpublished ports, ICMP, private IPs)")

    # ---- services
    net.svc["dhcp"] = DHCPServer(net, "DHCP-SRV", [
        Pool("EMP", "10.10.1.1", DNS_IP, "10.10.1.10", "10.10.1.62"),
        Pool("MGT", "10.10.1.65", DNS_IP, "10.10.1.70", "10.10.1.94")])
    dns = DNSServer(net, "DNS-SRV")
    for host, ip in (("dns", DNS_IP), ("dhcp", DHCP_IP), ("www", "10.10.1.100"), ("mail", "10.10.1.101")):
        dns.add(f"{host}.{DOMAIN}", "A", ip)
    dns.add(DOMAIN, "MX", f"mail.{DOMAIN}", pref=10)
    dns.add(f"intranet.{DOMAIN}", "CNAME", f"www.{DOMAIN}")
    dns.upstream_ip = INET_IP
    for name, ip in (("www.example.com", INET_IP), ("mail.example.com", INET_IP),
                     ("news.example.org", "203.0.113.20"), ("cdn.example.net", "203.0.113.21"),
                     ("docs.example.com", "203.0.113.22")):
        dns.add(name, "A", ip, ttl=300, upstream=True)
    dns.add("example.com", "MX", "mail.example.com", ttl=300, pref=10, upstream=True)
    net.svc["dns"] = dns

    # Public DNS on INET-HOST (split-horizon external view)
    dns_pub = DNSServer(net, "INET-HOST", domain=DOMAIN)
    dns_pub.add(f"www.{DOMAIN}", "A", "198.51.100.2")
    dns_pub.add(f"mail.{DOMAIN}", "A", "198.51.100.2")
    dns_pub.add(DOMAIN, "MX", f"mail.{DOMAIN}", pref=10)
    for name, ip in (("www.example.com", INET_IP), ("mail.example.com", INET_IP),
                     ("news.example.org", "203.0.113.20"), ("cdn.example.net", "203.0.113.21"),
                     ("docs.example.com", "203.0.113.22")):
        dns_pub.add(name, "A", ip, ttl=300)
    dns_pub.add("example.com", "MX", "mail.example.com", ttl=300, pref=10)
    net.dns_servers = {"DNS-SRV": dns, "INET-HOST": dns_pub}

    net.web_servers["WEB-SRV"] = WebServer("WEB-SRV", "www." + DOMAIN, PAGES)
    net.web_servers["INET-HOST"] = WebServer("INET-HOST", "www.example.com", {
        "/": "<html><body><h1>example.com</h1><p>Simulated Internet site.</p></body></html>"})
    net.mail_servers["MAIL-SRV"] = MailServer(
        net, "MAIL-SRV", DOMAIN, {u: u + "123" for u in ("alice", "bob", "carol", "dave")})
    net.mail_servers["INET-HOST"] = MailServer(net, "INET-HOST", "example.com",
                                               {"partner": "partner123", "info": "info123"})
    net.build_routing()
    return net


def boot_all(net: Network) -> None:
    """Every PC requests its address via DHCP (what happens when the office switches on)."""
    for pc in PCS:
        dhcp_request(net, pc, renew=False)
