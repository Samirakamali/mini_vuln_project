from django.db import models
from django.conf import settings

class Asset(models.Model):
    ip_address = models.GenericIPAddressField(protocol="both")
    hostname = models.CharField(max_length=255, blank=True)
    owner = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="assets",
        null=True,
        blank=True,
    )

    class Meta:
        ordering = ["-id"]

    def __str__(self):
        return self.hostname or self.ip_address


class Scan(models.Model):
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="scans")

    port = models.PositiveIntegerField()
    protocol = models.CharField(max_length=10, default="tcp")
    state = models.CharField(max_length=20, default="open")
    service = models.CharField(max_length=100, blank=True)
    version = models.CharField(max_length=200, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-id"]
        unique_together = ("asset", "port", "protocol")

    def __str__(self):
        return f"{self.asset} {self.port}/{self.protocol} {self.service}"