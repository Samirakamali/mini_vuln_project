from django.contrib import admin
from .models import Scan

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ("id", "asset", "port", "protocol", "state", "service", "version", "created_at")
    list_filter = ("protocol", "state", "created_at")
    search_fields = ("asset__name", "service", "version")  
    autocomplete_fields = ("asset",)  
    ordering = ("-id",)