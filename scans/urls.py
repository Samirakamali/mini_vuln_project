from django.urls import path
from .views import (ScanListCreateAPIView,
                     AssetListCreateAPIView,
                       AssetDetailAPIView,
                       RunScanAPIView,
                       DiscoverAPIView)

urlpatterns = [
    path("scans/", ScanListCreateAPIView.as_view()),
    path("assets/", AssetListCreateAPIView.as_view()),
    path("assets/<int:pk>/", AssetDetailAPIView.as_view()),
    path("assets/<int:pk>/run-scan/", RunScanAPIView.as_view()),
    path("discover/", DiscoverAPIView.as_view()),
]


