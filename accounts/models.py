from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings


class CustomUser(AbstractUser):
    
    phone = models.CharField(max_length=30, blank=True)
    organization = models.CharField(max_length=120, blank=True)

    #the first case is saved in datbase and the secound one is shown in admin pannle
    ROLE_CHOICES = [
        ("USER", "USER"),
        ("ANALYST", "ANALYST"),
        ("ADMIN", "ADMIN"),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="USER")

   
    is_email_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.username


class ActivityLog(models.Model):
    
    ACTION_CHOICES = [
    ("REGISTER", "REGISTER"),
    ("LOGIN", "LOGIN"),
    ("LOGOUT", "LOGOUT"),
    ("TOKEN_REFRESH", "TOKEN_REFRESH"),
    ("PASSWORD_CHANGE", "PASSWORD_CHANGE"),
    ("PROFILE_UPDATE", "PROFILE_UPDATE"),
    ("PASSWORD_RESET_REQUEST", "PASSWORD_RESET_REQUEST"),
    ("PASSWORD_RESET_CONFIRM", "PASSWORD_RESET_CONFIRM"),
]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="activity_logs",
    )
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)

    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True) #Chrome/Firefox/Android/Windows

    extra = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-id"]

    def __str__(self):
        return f"{self.user} {self.action} {self.created_at}"
