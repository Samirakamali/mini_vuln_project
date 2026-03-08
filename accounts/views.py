from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser

from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes, force_str
from .utils import get_client_ip, get_user_agent
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.utils import timezone
from django.conf import settings
from .models import ActivityLog
from datetime import timedelta
from .serializers import (
    RegisterSerializer,
    MeSerializer,
    ActivityLogSerializer,
    ProfileUpdateSerializer,
    ForgotPasswordRequestSerializer,
    ForgotPasswordConfirmSerializer,
    DeleteAccountSerializer,
    ChangePasswordSerializer,
)

User = get_user_model() # refrence to class of model: User == accounts.models.CustomUser
token_generator = PasswordResetTokenGenerator()

class UsersListAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        users_data = []

        for user in User.objects.all():
            last_log = user.activity_logs.first() 

           
            is_online = False
            if last_log and last_log.action == "LOGIN":
                if timezone.now() - last_log.created_at < timedelta(minutes=5):
                    is_online = True

            users_data.append({
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "is_active": user.is_active,
                "last_action": last_log.action if last_log else None,
                "last_action_time": last_log.created_at if last_log else None,
                "is_online": is_online,
            })

        ActivityLog.objects.create(
            user=request.user,
            action="USERS_LIST",
            ip=get_client_ip(request),
            user_agent=get_user_agent(request),
        )

        return Response(users_data, status=status.HTTP_200_OK)



class RegisterAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            ActivityLog.objects.create(
                user=user,
                action="REGISTER",
                ip=get_client_ip(request),
                user_agent=get_user_agent(request),
                extra={"via": "register_api"},
            )

            return Response(RegisterSerializer(user).data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class MeAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # print(f"request is: {request}")
        serializer = MeSerializer(request.user)
        # print(f"user is: {request.user}")
        # print(f"serializer is: {serializer}")
        # print(f"serializer.data is: {serializer.data}")
        return Response(serializer.data)


class MyActivityLogsAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = ActivityLog.objects.filter(user=request.user)
        # print(f"queryset: {qs}")
        serializer = ActivityLogSerializer(qs, many=True)
        return Response(serializer.data)


class ProfileUpdateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        serializer = ProfileUpdateSerializer(
            request.user,
            data=request.data,
            partial=True,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        ActivityLog.objects.create(
            user=user,
            action="PROFILE_UPDATE",
            ip=get_client_ip(request),
            user_agent=get_user_agent(request),
            extra={"updated_fields": list(request.data.keys())},
        )

        return Response(serializer.data, status=status.HTTP_200_OK)




class ChangePasswordAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user

        if not user.check_password(serializer.validated_data["old_password"]):
            return Response({"detail": "Old password incorrect."}, status=400)

        user.set_password(serializer.validated_data["new_password"])
        user.save()

        ActivityLog.objects.create(
            user=user,
            action="PASSWORD_CHANGE",
            ip=get_client_ip(request),
            user_agent=get_user_agent(request),
        )

        return Response({"detail": "Password changed successfully."})



class ForgotPasswordRequestAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ForgotPasswordRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]

        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            
            return Response(
                {"detail": "If this email exists, a reset link has been sent."},
                status=200
            )

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)

        reset_link = f"http://127.0.0.1:3000/reset-password?uid={uid}&token={token}"

        send_mail(
            subject="Reset your password",
            message=f"Click this link to reset your password:\n{reset_link}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
        )

        ActivityLog.objects.create(
            user=user,
            action="PASSWORD_RESET_REQUEST",
            ip=get_client_ip(request),
            user_agent=get_user_agent(request),
        )

        return Response(
            
            {"detail": "If this email exists, a reset link has been sent."},
            status=200
        )


class ForgotPasswordConfirmAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = ForgotPasswordConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uid = serializer.validated_data["uid"]
        token = serializer.validated_data["token"]
        new_password = serializer.validated_data["new_password"]

        try:
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)
        except Exception:
            return Response({"detail": "Invalid link."}, status=400)

        if not token_generator.check_token(user, token):
            return Response({"detail": "Invalid or expired token."}, status=400)

        user.set_password(new_password)
        user.save()

        ActivityLog.objects.create(
            user=user,
            action="PASSWORD_RESET_CONFIRM",
            ip=get_client_ip(request),
            user_agent=get_user_agent(request),
        )

        return Response({"detail": "Password has been reset successfully."})
    



class DeleteMyAccountAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        serializer = DeleteAccountSerializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)

        user = request.user
        user_id = user.id
        username = user.username

        
        ActivityLog.objects.create(
            user=user,
            action="ACCOUNT_DELETE",
            ip=get_client_ip(request),
            user_agent=get_user_agent(request),
            extra={"user_id": user_id, "username": username},
        )

        user.delete()

        return Response({"detail": "Account deleted successfully."}, status=status.HTTP_200_OK)


class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            ActivityLog.objects.create(
                user=request.user,
                action="LOGOUT",
                ip=get_client_ip(request),
                user_agent=get_user_agent(request),
            )

            return Response({"detail": "Logged out successfully."})

        except Exception:
            return Response({"detail": "Invalid token."}, status=400)