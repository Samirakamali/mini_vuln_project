import ipaddress
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional


# -------------------------
# Safety helpers
# -------------------------
def _is_private_or_loopback_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


def _is_private_network(cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        # allow only private networks (RFC1918) and loopback nets
        return net.is_private or net.is_loopback
    except ValueError:
        return False
    

#---------------------
#NMAP command runner
#---------------------
def _run_nmap(cmd: List[str], timeout_sec: int = 300) -> str:
    """
    Runs nmap and returns stdout. Raises RuntimeError on failure.
    """
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
    if proc.returncode != 0:
        err = (proc.stderr or "").strip()
        raise RuntimeError(f"nmap failed: {err}")
    return proc.stdout


# -------------------------
# Stage A: discovery (ping scan): which hosts are up
# -------------------------
def nmap_discover_hosts(cidr: str) -> str:
    """
    Host discovery on a private/loopback CIDR.
    Returns Nmap XML output (string).
    """
    if not _is_private_network(cidr):
        raise ValueError("Discovery allowed only on private/loopback networks (e.g. 192.168.0.0/24).")

    cmd = [
        "nmap",
        "-sn",          # host discovery only
        "-oX", "-",     # XML to stdout
        cidr,
    ]
    return _run_nmap(cmd, timeout_sec=300)


# read xml from discovery state and return up IPs into the list dictionary

def parse_discovery_xml(xml_text: str) -> List[Dict]:
    """
    Extracts up hosts from discovery XML.
    Returns: [{ip, hostname?}, ...]
    """
    root = ET.fromstring(xml_text)
    out: List[Dict] = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.attrib.get("state") != "up":
            continue

        ip = None
        for addr in host.findall("address"):
            if addr.attrib.get("addrtype") == "ipv4":
                ip = addr.attrib.get("addr")
                break
        if not ip:
            continue

        if not _is_private_or_loopback_ip(ip):
            # extra safety
            continue

        hostname = ""
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.attrib.get("name", "") or ""

        out.append({"ip": ip, "hostname": hostname})

    return out


# -------------------------
# Stage B: TCP port scan on IP address + light service detection
# -------------------------
def nmap_scan_ports(ip: str, ports: str = "1-1024") -> str:
    """
    TCP connect scan + light version detection. Safe for Windows without raw sockets.
    Returns Nmap XML output (string).
    """
    if not _is_private_or_loopback_ip(ip):
        raise ValueError("Scanning allowed only for private/loopback IPs.")

    cmd = [
        "nmap",
        "-sT",                 # TCP connect scan
        "-sV",                 # service detection
        "--version-light",
        "-p", ports,
        "-oX", "-",
        ip,
    ]
    return _run_nmap(cmd, timeout_sec=600)


#return dict from open ports and their servises with version from xml last state

def parse_ports_xml(xml_text: str) -> List[Dict]:
    """
    Extract open ports and service/version info.
    Returns: [{port, protocol, state, service, version}, ...]
    """
    root = ET.fromstring(xml_text)
    results: List[Dict] = []

    for port in root.findall(".//port"): # find all ports <port>
        proto = port.attrib.get("protocol", "tcp") or "tcp"
        portid = int(port.attrib.get("portid", "0"))

        state_el = port.find("state")
        state = (state_el.attrib.get("state") if state_el is not None else "") or ""
        if state != "open":
            continue

        service_name = ""
        version_str = ""

        service_el = port.find("service")
        if service_el is not None:
            service_name = service_el.attrib.get("name", "") or ""
            product = service_el.attrib.get("product", "") or ""
            version = service_el.attrib.get("version", "") or ""
            extra = service_el.attrib.get("extrainfo", "") or ""
            parts = [p for p in [product, version, extra] if p]
            version_str = " ".join(parts)

        results.append(
            {
                "port": portid,
                "protocol": proto.lower(),
                "state": state.lower(),
                "service": service_name,
                "version": version_str,
            }
        )

    return results