from django.contrib import admin
from .models import Asset, Scan

@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    search_fields = ("hostname", "ip_address", "owner")

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ("id", "asset", "port", "protocol", "state", "service", "version", "created_at")
    list_filter = ("protocol", "state", "created_at")
    search_fields = ("asset__hostname", "asset__ip_address", "service", "version")
    autocomplete_fields = ("asset",)
    ordering = ("-id",)