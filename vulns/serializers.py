from rest_framework import serializers
from .models import Vulnerability
from scans.serializers import ScanSerializer

class VulnerabilitySerializer(serializers.ModelSerializer):
    scan_detail = ScanSerializer(source="scan", read_only=True)

    class Meta:
        model = Vulnerability
        fields = "__all__"

    def validate_severity(self, value):
        v = (value or "").upper()
        if v not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            raise serializers.ValidationError("severity must be LOW/MEDIUM/HIGH/CRITICAL.")
        return v
