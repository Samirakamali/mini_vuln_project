from rest_framework import serializers
from .models import Alert
from vulns.serializers import VulnerabilitySerializer

class AlertSerializer(serializers.ModelSerializer):
    vulnerability_detail = VulnerabilitySerializer(source="vulnerability", read_only=True)

    class Meta:
        model = Alert
        fields = "__all__"
