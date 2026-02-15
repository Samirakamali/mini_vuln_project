from django.urls import path
from .views import ScanListCreateAPIView

urlpatterns = [
    path("scans/", ScanListCreateAPIView.as_view()),
]
