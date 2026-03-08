from scans.nmap_utils import (nmap_scan_ports, 
                              parse_ports_xml,
                              nmap_discover_hosts,
                              parse_discovery_xml)

from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

import ipaddress

from .models import Asset, Scan
from .serializers import AssetSerializer, ScanSerializer
from vulns.audit_engine import run_hardening_audit_for_asset

def _is_private_network(cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return net.is_private or net.is_loopback
    except ValueError:
        return False


class AssetListCreateAPIView(APIView):
    def get(self, request):
        # assets = Asset.objects.all()
        assets = Asset.objects.filter(created_by=request.user)
        serializer = AssetSerializer(assets, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = AssetSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(created_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AssetDetailAPIView(APIView):
    def get_object(self, pk):
        try:
            return Asset.objects.get(pk=pk)
        except Asset.DoesNotExist:
            return None

    def get(self, request, pk):
        asset = self.get_object(pk)
        if not asset:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = AssetSerializer(asset)
        return Response(serializer.data)

    def put(self, request, pk):
        asset = self.get_object(pk)
        if not asset:
            return Response(status=status.HTTP_404_NOT_FOUND)

        serializer = AssetSerializer(asset, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        asset = self.get_object(pk)
        if not asset:
            return Response(status=status.HTTP_404_NOT_FOUND)

        serializer = AssetSerializer(asset, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        asset = self.get_object(pk)
        if not asset:
            return Response(status=status.HTTP_404_NOT_FOUND)
        asset.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ScanListCreateAPIView(APIView):
    def get(self, request):
        # qs = Scan.objects.all()
        qs = Scan.objects.filter(asset__created_by=request.user)

        asset_id = request.query_params.get("asset") #this command looking for "asset" in url like: /api/scans/?asset=1, if "asset" exist asset_id = "1" else: asset_id = None
        if asset_id:
            qs = qs.filter(asset_id=asset_id)

        serializer = ScanSerializer(qs, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = ScanSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class RunScanAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        # only assts for your user
        try:
            asset = Asset.objects.get(pk=pk, created_by=request.user)
        except Asset.DoesNotExist:
            return Response({"detail": "Asset not found."}, status=404)

        ports = request.data.get("ports", "1-1024")

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

        stats = run_hardening_audit_for_asset(asset, clear_old=False)

        return Response({
        "asset": asset.ip_address,
        "open_ports": findings,
        "hardening": stats,
    })





class DiscoverAPIView(APIView):
    """
    POST /api/discover
    body: { "network": "192.168.0.0/24" }

    Runs: nmap -sn <network>   (XML)
    Saves: Asset(ip_address, hostname, created_by)
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        network = request.data.get("network")
        if not network:
            return Response({"detail": "network is required. e.g. 192.168.0.0/24"}, status=400)

        if not _is_private_network(network):
            return Response({"detail": "Only private/loopback networks are allowed."}, status=400)

        # Run discovery
        xml_out = nmap_discover_hosts(network)
        hosts = parse_discovery_xml(xml_out)

        created = 0
        updated = 0

        for h in hosts:
            obj, was_created = Asset.objects.update_or_create(
                ip_address=h["ip"],
                defaults={
                    "hostname": h.get("hostname", ""),
                    "created_by": request.user,
                }
            )
            if was_created:
                created += 1
            else:
                updated += 1

        return Response({
            "network": network,
            "up_hosts": len(hosts),
            "created": created,
            "updated": updated,
            "hosts": hosts,   
        })