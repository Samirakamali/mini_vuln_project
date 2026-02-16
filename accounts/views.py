from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny

from .models import ActivityLog
from .serializers import RegisterSerializer, ActivityLogSerializer, ProfileUpdateSerializer
from .utils import get_client_ip, get_user_agent


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
