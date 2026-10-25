"""A new VM's own fixed address (the user's request, 25/10). The user writes only the address; the rest — the size of
the network, the gateway, the DNS servers — is the Proxmox host's own, read from the bridge the VM goes on and from
the host's DNS settings, and shown beside the field. For Ubuntu (the setup disc's network-config, the ISO's
autoinstall); Windows later."""

from __future__ import annotations

import ipaddress

from .pve import Pve


def host_network(pve: Pve, node: str) -> dict:
    """What the host's own network says: {"bridges": {name: {"cidr", "gateway"}}, "dns": [...], "search": [...]}.
    Parts it does not give stay empty (a bridge without an address of its own offers no static address)."""
    bridges, gateways = {}, []
    for n in pve.networks(node):
        if n.get("gateway"):
            gateways.append(str(n["gateway"]))
        if n.get("type") in ("bridge", "OVSBridge") and n.get("iface"):
            bridges[n["iface"]] = {"cidr": str(n.get("cidr") or ""), "gateway": str(n.get("gateway") or "")}
    for b in bridges.values():  # the gateway set on another of the host's interfaces, in the bridge's network
        if b["cidr"] and not b["gateway"]:
            net = ipaddress.ip_interface(b["cidr"]).network
            b["gateway"] = next((g for g in gateways if ipaddress.ip_address(g) in net), "")
    dns = pve.node_dns(node)
    return {"bridges": bridges,
            "dns": [str(dns[k]) for k in ("dns1", "dns2", "dns3") if dns.get(k)],
            "search": str(dns.get("search") or "").split()}


def for_bridge(net: dict, bridge: str) -> dict | None:
    """The settings a static address on `bridge` takes from the host, or None where the bridge has no IPv4 network
    of its own (or no gateway in it)."""
    b = (net.get("bridges") or {}).get(bridge) or {}
    try:
        iface = ipaddress.ip_interface(b.get("cidr") or "")
    except ValueError:
        return None
    if iface.version != 4 or not b.get("gateway"):
        return None
    return {"network": iface.network, "host": str(iface.ip), "gateway": b["gateway"],
            "dns": list(net.get("dns") or []) or [b["gateway"]], "search": list(net.get("search") or [])}


def describe(info: dict | None) -> str:
    """What goes with the address, in words, for beside the field."""
    if info is None:
        return "this bridge has no IPv4 network on the host to go by"
    return (f"/{info['network'].prefixlen} · gateway {info['gateway']} · DNS {', '.join(info['dns'])} "
            "(from the Proxmox host)")


def check(address: str, info: dict | None, taken: set[str] | frozenset = frozenset()) -> str:
    """"" when `address` will do as the VM's fixed address, else what is wrong, in words."""
    if info is None:
        return ("The host's bridge has no IPv4 network of its own to go by, so no static IP can be set here "
                "(untick Static IP: the VM then asks the network's DHCP).")
    try:
        ip = ipaddress.IPv4Address(address.strip())
    except ValueError:
        return "The static IP: an address such as 192.168.1.50."
    net = info["network"]
    if ip not in net:
        return f"{ip} is not in the host's network ({net})."
    if ip in (net.network_address, net.broadcast_address):
        return f"{ip} is the network's own {'address' if ip == net.network_address else 'broadcast address'}."
    if str(ip) == info["host"]:
        return f"{ip} is the Proxmox host's own address."
    if str(ip) == info["gateway"]:
        return f"{ip} is the gateway's address."
    if str(ip) in taken:
        return f"{ip} is in use: another guest on this host shows it."
    return ""


def settings(address: str, info: dict) -> dict:
    """The static network a seed or an autoinstall writes (see cloudseed.network_config)."""
    return {"address": f"{ipaddress.IPv4Address(address.strip())}/{info['network'].prefixlen}",
            "gateway": info["gateway"], "dns": list(info["dns"]), "search": list(info["search"])}
