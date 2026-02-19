from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny

from .models import ActivityLog
from .serializers import RegisterSerializer, ActivityLogSerializer, ProfileUpdateSerializer, ForgotPasswordRequestSerializer, ForgotPasswordConfirmSerializer
from .utils import get_client_ip, get_user_agent


from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model

from rest_framework.permissions import IsAdminUser


User = get_user_model()
token_generator = PasswordResetTokenGenerator()


class UsersListAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]  # فقط ادمین‌ها

    def get(self, request):
        qs = User.objects.all().values(
            "id", "username", "email", "first_name", "last_name", "role", "is_active", "date_joined"
        )

        ActivityLog.objects.create(
            user=request.user,
            action="USERS_LIST",
            ip=get_client_ip(request),
            user_agent=get_user_agent(request),
            extra={"count": qs.count()},
        )

        return Response(list(qs), status=status.HTTP_200_OK)



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
        u = request.user
        return Response({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "first_name": u.first_name,
            "last_name": u.last_name,
        })


class MyActivityLogsAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = ActivityLog.objects.filter(user=request.user)
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


from .serializers import ChangePasswordSerializer

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