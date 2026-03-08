from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.contrib.auth import get_user_model
from .models import ActivityLog
User = get_user_model()


@admin.register(User)
class CustomUserAdmin(DjangoUserAdmin):
    list_display = (
        "id",
        "username",
        "email",
        "role",
        "is_active",
        "is_staff",
        "is_superuser",
        "date_joined",
    )

    list_filter = ("role", "is_active", "is_staff")

    search_fields = ("username", "email")

    ordering = ("-date_joined",)

    fieldsets = DjangoUserAdmin.fieldsets + (
        (
            "Extra Info",
            {
                "fields": ("phone", "organization", "role"),
            },
        ),
    )


class ActivityLogInline(admin.TabularInline):
    model = ActivityLog
    extra = 0
    can_delete = False
    readonly_fields = ("action", "ip", "user_agent", "extra", "created_at")
    fields = ("action", "ip", "created_at", "user_agent", "extra")

@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "action", "ip", "created_at")
    list_filter = ("action", "created_at")
    search_fields = ("user__username", "user__email", "ip")
    ordering = ("-id",)
    readonly_fields = ("user", "action", "ip", "user_agent", "extra", "created_at")