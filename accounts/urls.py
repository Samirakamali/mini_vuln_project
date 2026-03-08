from django.urls import path
from .views import RegisterAPIView, MeAPIView, MyActivityLogsAPIView, ProfileUpdateAPIView, ChangePasswordAPIView, ForgotPasswordRequestAPIView, ForgotPasswordConfirmAPIView, UsersListAPIView, DeleteMyAccountAPIView
from .views import LogoutAPIView

urlpatterns = [

    path("register/", RegisterAPIView.as_view()),
    path("me/", MeAPIView.as_view()),
    path("logs/", MyActivityLogsAPIView.as_view()),
    path("profile/update/", ProfileUpdateAPIView.as_view()),
    path("change-password/", ChangePasswordAPIView.as_view()),
    path("password/forgot/", ForgotPasswordRequestAPIView.as_view()),
    path("password/reset/", ForgotPasswordConfirmAPIView.as_view()),
    path("users/", UsersListAPIView.as_view()),
    path("delete-account/", DeleteMyAccountAPIView.as_view()),
    path("logout/", LogoutAPIView.as_view()),

]





