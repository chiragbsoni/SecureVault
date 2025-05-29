from vaultcore.models import ActivityLog
from django.utils.timezone import now

def log_activity(request, activity_type):
    ActivityLog.objects.create(
        user=request.user,
        activity_type=activity_type,
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', 'unknown'),
        timezone=request.POST.get('timezone', None)

    )

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')


