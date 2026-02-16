from django.urls import path
from .views import RegisterAPIView, MeAPIView, MyActivityLogsAPIView, ProfileUpdateAPIView, ChangePasswordAPIView

urlpatterns = [
    path("register/", RegisterAPIView.as_view()),
    path("me/", MeAPIView.as_view()),
    path("logs/", MyActivityLogsAPIView.as_view()),
    path("profile/update/", ProfileUpdateAPIView.as_view()),
    path("change-password/", ChangePasswordAPIView.as_view()),
]



