from django.db import models
from scans.models import Scan

class Vulnerability(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="vulns")

    cve_id = models.CharField(max_length=30)  # CVE-2021-1234
    severity = models.CharField(max_length=10, default="MEDIUM")  # LOW/MEDIUM/HIGH/CRITICAL
    description = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-id"]
        unique_together = ("scan", "cve_id")  # uniqe vulnare for each scan

    def __str__(self):
        return f"{self.cve_id} ({self.severity})"


class Alert(models.Model):
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name="alerts")

    level = models.CharField(max_length=10, default="HIGH")  # HIGH/CRITICAL/...
    message = models.CharField(max_length=255)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-id"]

    def __str__(self):
        return f"{self.level}: {self.message}"
    
    