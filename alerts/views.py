from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .models import Alert
from .serializers import AlertSerializer
from vulns.models import Vulnerability


class AlertListAPIView(APIView):
    def get(self, request):
        # qs = Alert.objects.all()
        qs = Alert.objects.filter(vulnerability__scan__asset__created_by=request.user)


        asset_id = request.query_params.get("asset")
        if asset_id:
            qs = qs.filter(vulnerability__scan__asset_id=asset_id)  # Alert -> Vuln -> Scan -> Asset

        serializer = AlertSerializer(qs, many=True)
        return Response(serializer.data)


class AutoAlertCreateAPIView(APIView):
    """
    ورودی: {"vulnerability": 1}
    اگر severity HIGH یا CRITICAL بود، یک Alert می‌سازد.
    """
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
            return Response(
                {"detail": f"No alert created. severity={vuln.severity}"},
                status=status.HTTP_200_OK
            )

        alert = Alert.objects.create(
            vulnerability=vuln,
            level=sev,
            message=f"{vuln.cve_id} detected on scan {vuln.scan_id}"
        )

        return Response(AlertSerializer(alert).data, status=status.HTTP_201_CREATED)
