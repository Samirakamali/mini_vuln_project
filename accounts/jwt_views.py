from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer

from .models import ActivityLog
from .utils import get_client_ip, get_user_agent


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)

        ActivityLog.objects.create(
            user=self.user,
            action="LOGIN",
            ip=get_client_ip(self.context["request"]),
            user_agent=get_user_agent(self.context["request"]),
            extra={"via": "jwt_token_obtain"},
        )
        return data


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


class MyTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)

        req = self.context["request"]
        user = getattr(req, "user", None)
       
        if user and user.is_authenticated:
            ActivityLog.objects.create(
                user=user,
                action="TOKEN_REFRESH",
                ip=get_client_ip(req),
                user_agent=get_user_agent(req),
                extra={"via": "jwt_refresh"},
            )

        return data


class MyTokenRefreshView(TokenRefreshView):
    serializer_class = MyTokenRefreshSerializer
