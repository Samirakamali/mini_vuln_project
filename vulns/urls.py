from django.urls import path
from .views import VulnerabilityListCreateAPIView

urlpatterns = [
    path("vulns/", VulnerabilityListCreateAPIView.as_view()),
]
