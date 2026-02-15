from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .models import Vulnerability
from .serializers import VulnerabilitySerializer


class VulnerabilityListCreateAPIView(APIView):
    def get(self, request):
        # qs = Vulnerability.objects.all()
        qs = Vulnerability.objects.filter(scan__asset__created_by=request.user)

        asset_id = request.query_params.get("asset")
        if asset_id:
            qs = qs.filter(scan__asset_id=asset_id)  # join: Vulnerability -> Scan -> Asset

        serializer = VulnerabilitySerializer(qs, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = VulnerabilitySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

