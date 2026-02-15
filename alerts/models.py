from django.db import models
from vulns.models import Vulnerability

class Alert(models.Model):
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name="alerts")

    level = models.CharField(max_length=10, default="HIGH")  # HIGH/CRITICAL/...
    message = models.CharField(max_length=255)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-id"]

    def __str__(self):
        return f"{self.level}: {self.message}"
