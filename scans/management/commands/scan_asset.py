from django.core.management.base import BaseCommand, CommandError
from scans.models import Asset, Scan
from scans.nmap_utils import nmap_scan_ports, parse_ports_xml

#python manage.py scan_asset --asset-id 5
class Command(BaseCommand):
    help = "Scan ports on a single Asset and save Scan results."

    def add_arguments(self, parser):
        parser.add_argument("--asset-id", type=int, required=True)
        parser.add_argument("--ports", type=str, default="1-1024")

    def handle(self, *args, **opts):
        asset_id = opts["asset_id"]
        ports = opts["ports"]

        try:
            asset = Asset.objects.get(id=asset_id)
        except Asset.DoesNotExist:
            raise CommandError("Asset not found.")

        xml_out = nmap_scan_ports(asset.ip_address, ports=ports)
        findings = parse_ports_xml(xml_out)

        saved = 0
        for f in findings:
            _, created = Scan.objects.update_or_create(
                asset=asset,
                port=f["port"],
                protocol=f["protocol"],
                defaults={
                    "state": f["state"],
                    "service": f["service"],
                    "version": f["version"],
                }
            )
            saved += 1

        self.stdout.write(self.style.SUCCESS(
            f"Scanned {asset.ip_address}. Open ports saved: {len(findings)}"
        ))