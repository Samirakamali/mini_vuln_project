from django.urls import path
from .views import AlertListAPIView, AutoAlertCreateAPIView

urlpatterns = [
    path("alerts/", AlertListAPIView.as_view()),
    path("alerts/auto/", AutoAlertCreateAPIView.as_view()),
]
