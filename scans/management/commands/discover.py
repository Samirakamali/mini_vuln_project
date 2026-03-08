from django.core.management.base import BaseCommand, CommandError #base class for comand manage.py 
from django.contrib.auth import get_user_model

from scans.models import Asset
from scans.nmap_utils import nmap_discover_hosts, parse_discovery_xml

User = get_user_model()
#input: python manage.py discover_assets --cidr 192.168.1.0/24 --user-id 3
class Command(BaseCommand):
    help = "Discover live hosts in a private network (CIDR) and save/update Assets."

    def add_arguments(self, parser):
        parser.add_argument("--cidr", type=str, required=True, help="e.g. 192.168.0.0/24")
        parser.add_argument("--user-id", type=int, required=False, help="Attach discovered assets to this user")

    def handle(self, *args, **opts):
        cidr = opts["cidr"]
        user_id = opts.get("user_id")

        user = None
        if user_id:
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                raise CommandError("User not found.")

        xml_out = nmap_discover_hosts(cidr) #find UP hosts with nmap -sn 192.168.1.0/24 and return them in a xml output  {"ip": "192.168.1.1", "hostname": "router"}
        hosts = parse_discovery_xml(xml_out) #convert xml to python.dictionary output

        created = 0
        updated = 0

        for h in hosts:
            defaults = {"hostname": h.get("hostname", "")}
            if user:
                defaults["created_by"] = user

            obj, was_created = Asset.objects.update_or_create(
                
                ip_address=h["ip"],
                defaults=defaults
            )
            if was_created:
                created += 1
            else:
                updated += 1

        self.stdout.write(self.style.SUCCESS(
            f"Discovery done. Up hosts: {len(hosts)} | Created: {created} | Updated: {updated}"
        ))