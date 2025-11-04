from datetime import timedelta
from django.utils import timezone
from celery import shared_task
from django.db.models import Count
from ip_tracking.models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ["/admin", "/login", "/api/admin", "/api/login"]

@shared_task
def detect_suspicious_ips():
    """
    Detect IPs with abnormal request behavior or sensitive path access.
    Runs hourly via Celery Beat.
    """
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    # Get request counts per IP within the last hour
    recent_requests = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values("ip_address")
        .annotate(request_count=Count("id"))
    )

    for record in recent_requests:
        ip = record["ip_address"]
        count = record["request_count"]

        # Rule 1: Too many requests per hour
        if count > 100:
            SuspiciousIP.objects.get_or_create(
                ip_address=ip,
                defaults={"reason": f"Exceeded 100 requests in the last hour ({count})"},
            )
            continue

        # Rule 2: Accessing sensitive paths
        sensitive_hits = RequestLog.objects.filter(
            ip_address=ip,
            path__in=SENSITIVE_PATHS,
            timestamp__gte=one_hour_ago
        ).count()

        if sensitive_hits > 0:
            SuspiciousIP.objects.get_or_create(
                ip_address=ip,
                defaults={"reason": f"Accessed sensitive paths ({sensitive_hits} times)"},
            )
