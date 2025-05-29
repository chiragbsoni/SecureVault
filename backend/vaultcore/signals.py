from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from .models import ActivityLog
from django.utils.timezone import now
import user_agents

@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    # Get IP
    ip = get_client_ip(request)

    # Get User Agent
    ua_string = request.META.get('HTTP_USER_AGENT', '')
    user_agent = user_agents.parse(ua_string)
    device = f"{user_agent.os.family} {user_agent.browser.family} ({user_agent.device.family})"

    # Create log
    ActivityLog.objects.create(
        user=user,
        activity_type="login",
        ip_address=ip,
        device=device,
        timestamp=now()
    )

def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR", "")
    return ip
