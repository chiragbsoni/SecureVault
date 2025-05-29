from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.utils.timezone import now
from django.contrib.auth.models import User
from django.db import models
import pyotp
from django.contrib.auth.models import User
from django.db import models


class Role(models.Model):
    name = models.CharField(max_length=20, unique=True)

    def __str__(self):
        return self.name

class User(AbstractUser):
    role = role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)
    mfa_secret = models.CharField(max_length=64, blank=True, null=True)

    def __str__(self):
        return self.username

class Credential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    website = models.CharField(max_length=100)
    login_username = models.CharField(max_length=100)
    encrypted_password = models.BinaryField()
    iv = models.BinaryField()
    notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.website} ({self.login_username})"

# class ActivityLog(models.Model):
#     user = models.ForeignKey(User, on_delete=models.CASCADE)
#     activity_type = models.CharField(max_length=50)
#     ip_address = models.GenericIPAddressField()
#     user_agent = models.TextField()
#     timezone = models.CharField(max_length=50, null=True, blank=True)
#     timestamp = models.DateTimeField(default=now)

#     def __str__(self):
#         return f"{self.user.username} - {self.activity_type} - {self.timestamp}"

class ActivityLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    activity_type = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField()
    device = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)


class TOTPDevice(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    secret = models.CharField(max_length=32, default=pyotp.random_base32)
    confirmed = models.BooleanField(default=False)

    def get_totp_uri(self):
        return pyotp.totp.TOTP(self.secret).provisioning_uri(name=self.user.username, issuer_name="SecureVault")

    def verify_token(self, token):
        return pyotp.TOTP(self.secret).verify(token)
    

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='userprofile')
    otp_secret = models.CharField(max_length=32, default=pyotp.random_base32)
    is_2fa_enabled = models.BooleanField(default=False)
    otp_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username