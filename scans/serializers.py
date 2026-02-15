from rest_framework import serializers
from .models import Scan
from assets.serializers import AssetSerializer

class ScanSerializer(serializers.ModelSerializer):
    asset_detail = AssetSerializer(source="asset", read_only=True)

    class Meta:
        model = Scan
        fields = "__all__"

    def validate_port(self, value):
        if not (1 <= value <= 65535):
            raise serializers.ValidationError("Port must be between 1 and 65535.")
        return value

    def validate_protocol(self, value):
        v = (value or "").lower() #Case normalization
        if v not in ["tcp", "udp"]:
            raise serializers.ValidationError("protocol must be tcp or udp.")
        return v

    def validate_state(self, value):
        v = (value or "").lower() #Case normalization
        if v not in ["open", "closed", "filtered"]:
            raise serializers.ValidationError("state must be open/closed/filtered.")
        return v
