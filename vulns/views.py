# vulns/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .models import Vulnerability, Alert
from .serializers import VulnerabilitySerializer, AlertSerializer

class VulnerabilityListCreateAPIView(APIView):
    def get(self, request):
        qs = Vulnerability.objects.filter(scan__asset__created_by=request.user)
        asset_id = request.query_params.get("asset")
        if asset_id:
            qs = qs.filter(scan__asset_id=asset_id)
        return Response(VulnerabilitySerializer(qs, many=True).data)

    def post(self, request):
        serializer = VulnerabilitySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AlertListAPIView(APIView):
    def get(self, request):
        qs = Alert.objects.filter(vulnerability__scan__asset__created_by=request.user)

        asset_id = request.query_params.get("asset")
        if asset_id:
            qs = qs.filter(vulnerability__scan__asset_id=asset_id)

        return Response(AlertSerializer(qs, many=True).data)


class AutoAlertCreateAPIView(APIView):
    
    def post(self, request):
        vuln_id = request.data.get("vulnerability")
        if not vuln_id:
            return Response({"vulnerability": ["This field is required."]}, status=status.HTTP_400_BAD_REQUEST)

        try:
            vuln = Vulnerability.objects.get(id=vuln_id)
        except Vulnerability.DoesNotExist:
            return Response({"vulnerability": ["Invalid id."]}, status=status.HTTP_400_BAD_REQUEST)

        sev = (vuln.severity or "").upper()
        if sev not in ["HIGH", "CRITICAL"]:
            return Response({"detail": f"No alert created. severity={vuln.severity}"}, status=status.HTTP_200_OK)

        alert = Alert.objects.create(
            vulnerability=vuln,
            level=sev,
            message=f"{vuln.cve_id} detected on scan {vuln.scan_id}"
        )
        return Response(AlertSerializer(alert).data, status=status.HTTP_201_CREATED)