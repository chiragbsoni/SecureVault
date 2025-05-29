from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm
from .models import Credential
from django.core.exceptions import ValidationError
import re

# Get the custom user model (vaultcore.User)
User = get_user_model()

# Custom user registration form
class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username', 'password1', 'password2']

# Credential form with encryption-ready password field
class CredentialForm(forms.ModelForm):
    plain_password = forms.CharField(widget=forms.PasswordInput())

    class Meta:
        model = Credential
        fields = ['website', 'login_username', 'plain_password', 'notes']

class StrongPasswordForm(UserCreationForm):
    class Meta:
        model = User
        fields = ("username", "password1", "password2")

    def clean_password2(self):
        password = self.cleaned_data.get("password2")
        if len(password) < 12:
            raise ValidationError("Password must be at least 12 characters long.")
        if not re.search(r"[A-Z]", password):
            raise ValidationError("Password must include at least one uppercase letter.")
        if not re.search(r"[a-z]", password):
            raise ValidationError("Password must include at least one lowercase letter.")
        if not re.search(r"[0-9]", password):
            raise ValidationError("Password must include at least one number.")
        if not re.search(r"[^A-Za-z0-9]", password):
            raise ValidationError("Password must include at least one special character.")
        return password