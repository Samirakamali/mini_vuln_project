from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .models import Asset
from .serializers import AssetSerializer


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
