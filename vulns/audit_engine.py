'''
This code implements a security hardening audit system that examines the ports and services of an Asset, records detected
security weaknesses as Vulnerabilities, and generates an Alert when the severity of a vulnerability is high or critical.

'''
from __future__ import annotations
from typing import Dict, List, Optional, Tuple
import socket
import ssl
 
import requests
from django.db import transaction

from scans.models import Scan, Asset
from vulns.models import Vulnerability, Alert


# ---------- helpers ----------
# CREATE AN ALARM IN DATSET IF SEVERITY OF VULN IS HIGH OR CRITICAL

def _ensure_alert(vuln: Vulnerability) -> None:
    sev = (vuln.severity or "").upper()
    if sev not in ["HIGH", "CRITICAL"]:
        return
    
    Alert.objects.get_or_create(
        vulnerability=vuln,
        defaults={
            "level": sev,
            "message": f"{vuln.cve_id} detected on scan {vuln.scan_id}",
        },
    )


#RETURN ALL SCANS RELATED TO ASSET THAT THEIR STAT IS OPEN
def _get_open_scans_for_asset(asset: Asset) -> List[Scan]:
    return list(Scan.objects.filter(asset=asset, state="open"))


#FIND A SCAN RELATED TO A ASSET AND TCP PORT
def _find_scan_for_port(scans: List[Scan], port: int) -> Optional[Scan]:
    for s in scans:
        if int(s.port) == int(port) and (s.protocol or "tcp").lower() == "tcp":
            return s
    return None



def _upsert_vuln(scan: Scan, cve_id: str, severity: str, description: str) -> Vulnerability:
    vuln, _ = Vulnerability.objects.get_or_create(
        scan=scan,
        cve_id=cve_id,
        defaults={"severity": severity.upper(), "description": description},
    )
    
    changed = False
    if (vuln.severity or "").upper() != severity.upper():
        vuln.severity = severity.upper()
        changed = True
    if (vuln.description or "") != description:
        vuln.description = description
        changed = True
    if changed:
        vuln.save(update_fields=["severity", "description"])
    return vuln


#sending http/https request  to Ip:port to return sataus code and headers
def _http_probe(ip: str, port: int, use_https: bool, timeout: int = 5) -> Tuple[Optional[int], Dict[str, str]]:
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}
        return r.status_code, headers
    except requests.RequestException:
        return None, {}


def _tls_handshake_info(ip: str, port: int, timeout: int = 5) -> Dict[str, str]:
    info: Dict[str, str] = {}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cipher = ssock.cipher()  # (name, protocol, bits)
                if cipher:
                    info["cipher"] = cipher[0]
                    info["tls_protocol"] = cipher[1]
                    info["secret_bits"] = str(cipher[2])
    except Exception:
        pass
    return info


# ---------- main audit ----------
@transaction.atomic
def run_hardening_audit_for_asset(asset: Asset, clear_old: bool = False) -> Dict[str, int]:

    scans = _get_open_scans_for_asset(asset)

    if clear_old:
        
        Vulnerability.objects.filter(scan__asset=asset, cve_id__startswith="HARDEN-").delete()

    created_or_updated = 0
    alerts_created = 0

    open_ports = {int(s.port) for s in scans}

    # 1) Telnet open -> HIGH
    if 23 in open_ports:
        s = _find_scan_for_port(scans, 23)
        if s:
            vuln = _upsert_vuln(
                s,
                "HARDEN-TELNET-OPEN",
                "HIGH",
                "Telnet is open (plaintext). Disable it or restrict access strongly.",
            )
            _ensure_alert(vuln)
            created_or_updated += 1

    # 2) SMB 445 open -> MEDIUM
    if 445 in open_ports:
        s = _find_scan_for_port(scans, 445)
        if s:
            vuln = _upsert_vuln(
                s,
                "HARDEN-SMB-445-OPEN",
                "MEDIUM",
                "SMB port 445 is open. Patch SMB, disable SMBv1, restrict to trusted hosts.",
            )
            created_or_updated += 1

    # 3) RDP 3389 open -> MEDIUM
    if 3389 in open_ports:
        s = _find_scan_for_port(scans, 3389)
        if s:
            vuln = _upsert_vuln(
                s,
                "HARDEN-RDP-3389-OPEN",
                "MEDIUM",
                "RDP port 3389 is open. Use NLA, MFA/VPN, and restrict access.",
            )
            created_or_updated += 1

    # 4) HTTP without HTTPS -> MEDIUM
    http_ports = [p for p in open_ports if p in (80, 8080, 8000, 8888)]
    https_ports = [p for p in open_ports if p in (443, 8443)]

    if http_ports and not https_ports:
        s = _find_scan_for_port(scans, http_ports[0])
        if s:
            vuln = _upsert_vuln(
                s,
                "HARDEN-HTTP-NO-HTTPS",
                "MEDIUM",
                f"HTTP detected on ports {sorted(http_ports)} but HTTPS not detected. Consider enabling HTTPS and redirecting.",
            )
            created_or_updated += 1

    # 5) Security headers missing (HTTP/HTTPS) -> LOW/MEDIUM
    
    web_ports = sorted(set(http_ports + https_ports))
    for p in web_ports:
        use_https = p in (443, 8443)
        status_code, headers = _http_probe(asset.ip_address, p, use_https=use_https)

        if status_code is None:
            
            s = _find_scan_for_port(scans, p)
            if s:
                vuln = _upsert_vuln(
                    s,
                    f"HARDEN-WEB-PROBE-FAILED-{p}",
                    "LOW",
                    f"Could not fetch / on {'https' if use_https else 'http'}:{p}. The service may block requests.",
                )
                created_or_updated += 1
            continue

        missing = []
        if "x-frame-options" not in headers:
            missing.append("X-Frame-Options")
        if "x-content-type-options" not in headers:
            missing.append("X-Content-Type-Options")
        if "content-security-policy" not in headers:
            missing.append("Content-Security-Policy")
        if use_https and "strict-transport-security" not in headers:
            missing.append("Strict-Transport-Security")

        if missing:
            s = _find_scan_for_port(scans, p)
            if s:
                sev = "MEDIUM" if use_https else "LOW"
                vuln = _upsert_vuln(
                    s,
                    f"HARDEN-MISSING-SECURITY-HEADERS-{p}",
                    sev,
                    f"Missing security headers on {'https' if use_https else 'http'}:{p}: {', '.join(missing)}",
                )
                created_or_updated += 1

    # 6) Weak TLS (simple handshake) -> MEDIUM
    for p in https_ports:
        s = _find_scan_for_port(scans, p)
        if not s:
            continue

        info = _tls_handshake_info(asset.ip_address, p)
        proto = (info.get("tls_protocol") or "").upper()

        if not proto:
            vuln = _upsert_vuln(
                s,
                f"HARDEN-TLS-INFO-UNKNOWN-{p}",
                "LOW",
                f"Could not determine TLS handshake info on port {p}.",
            )
            created_or_updated += 1
            continue

       
        if "TLSV1" in proto and "TLSV1.2" not in proto and "TLSV1.3" not in proto:
            vuln = _upsert_vuln(
                s,
                f"HARDEN-WEAK-TLS-PROTOCOL-{p}",
                "MEDIUM",
                f"Weak TLS protocol negotiated on port {p}: {proto}. Prefer TLS 1.2+.",
            )
            created_or_updated += 1

    
    alerts_created = Alert.objects.filter(vulnerability__scan__asset=asset, vulnerability__cve_id__startswith="HARDEN-").count()

    return {"hardening_vulns_touched": created_or_updated, "hardening_alerts_total": alerts_created}