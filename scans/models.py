from django.db import models
from assets.models import Asset

class Scan(models.Model):
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="scans") #each asset could have different asset

    port = models.PositiveIntegerField()
    protocol = models.CharField(max_length=10, default="tcp")   # tcp/udp
    state = models.CharField(max_length=20, default="open")     # open/closed/filtered
    service = models.CharField(max_length=100, blank=True)      # ssh/http/...
    version = models.CharField(max_length=200, blank=True)      

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-id"] #from newest scan to the oldest one
        unique_together = ("asset", "port", "protocol")  # for an uniqe asset only an uniqe port and protocol is valid

    def __str__(self):
        return f"{self.asset} {self.port}/{self.protocol} {self.service}"
