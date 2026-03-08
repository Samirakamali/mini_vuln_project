from django.urls import path
from .views import (
    VulnerabilityListCreateAPIView,
    AlertListAPIView,
    AutoAlertCreateAPIView,
)

urlpatterns = [
    path("vulns/", VulnerabilityListCreateAPIView.as_view()),
    path("alerts/", AlertListAPIView.as_view()),
    path("alerts/auto/", AutoAlertCreateAPIView.as_view()),
]