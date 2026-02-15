from django.urls import path
from .views import RegisterAPIView, MeAPIView, MyActivityLogsAPIView

urlpatterns = [
    path("register/", RegisterAPIView.as_view()),
    path("me/", MeAPIView.as_view()),
    path("logs/", MyActivityLogsAPIView.as_view()),
]


