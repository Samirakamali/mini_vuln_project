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
