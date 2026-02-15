from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .models import Scan
from .serializers import ScanSerializer


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
