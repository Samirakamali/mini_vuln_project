from django.core.management.base import BaseCommand
from scans.models import Asset, Scan
from scans.nmap_utils import nmap_scan_ports, parse_ports_xml


#python manage.py scan_all --user-id 3 --ports 22,80,443
#python manage.py scan_all --ports 1-1024
#scan all assets, find their open ports using NMAP and save the results in scan table
class Command(BaseCommand):
    help = "Scan all assets (optionally filtered by user) and store open ports."

    def add_arguments(self, parser):
        parser.add_argument("--user-id", type=int, required=False)
        parser.add_argument("--ports", type=str, default="1-1024")

    def handle(self, *args, **opts):
        user_id = opts.get("user_id")
        ports = opts["ports"]

        qs = Asset.objects.all()
        if user_id:
            qs = qs.filter(created_by_id=user_id)

        total_assets = qs.count()
        total_open = 0

        for asset in qs.iterator():
            xml_out = nmap_scan_ports(asset.ip_address, ports=ports)
            findings = parse_ports_xml(xml_out)

            for f in findings:
                Scan.objects.update_or_create(
                    asset=asset,
                    port=f["port"],
                    protocol=f["protocol"],
                    defaults={
                        "state": f["state"],
                        "service": f["service"],
                        "version": f["version"],
                    }
                )
            total_open += len(findings)

            self.stdout.write(f"OK {asset.ip_address}: {len(findings)} open ports")

        self.stdout.write(self.style.SUCCESS(
            f"Done. Assets scanned: {total_assets} | Total open ports saved: {total_open}"
        ))