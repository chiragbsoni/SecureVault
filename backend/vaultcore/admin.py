from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Role, Credential, ActivityLog

class CustomUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        ("SecureVault Custom Fields", {'fields': ('role', 'mfa_secret')}),
    )

    add_fieldsets = UserAdmin.add_fieldsets + (
        ("SecureVault Custom Fields", {'fields': ('role', 'mfa_secret')}),
    )

class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'activity_type', 'ip_address', 'timezone', 'timestamp')

admin.site.register(User, CustomUserAdmin)
admin.site.register(Role)
admin.site.register(Credential)
admin.site.register(ActivityLog)
