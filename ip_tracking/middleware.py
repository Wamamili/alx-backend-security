from datetime import datetime, timedelta
from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
import urllib.request
import json
from .models import RequestLog, BlockedIP

class IPLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log IP, path, timestamp, and geolocation data.
    Blocks IPs found in BlockedIP model.
    """

    def get_client_ip(self, request):
        """Extract real client IP even behind proxies."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def get_geolocation(self, ip):
        """Fetch and cache IP geolocation for 24 hours using a public IP lookup."""
        cache_key = f"geo_{ip}"
        geo_data = cache.get(cache_key)
        if geo_data:
            return geo_data

        # Fallback to a simple public IP geolocation service (no third-party package required)
        try:
            if not ip:
                raise ValueError("No IP provided")

            url = f"http://ip-api.com/json/{ip}?fields=status,country,city"
            with urllib.request.urlopen(url, timeout=5) as resp:
                body = resp.read()
            data = json.loads(body.decode("utf-8"))

            if data.get("status") == "success":
                country = data.get("country") or "Unknown"
                city = data.get("city") or "Unknown"
            else:
                country = "Unknown"
                city = "Unknown"

            geo_data = {"country": country, "city": city}
            cache.set(cache_key, geo_data, timeout=86400)  # 24 hours
            return geo_data
        except Exception:
            # In case of failure, cache minimal data
            geo_data = {"country": "Unknown", "city": "Unknown"}
            cache.set(cache_key, geo_data, timeout=86400)
            return geo_data

    def process_request(self, request):
        """Block blacklisted IPs, then log allowed requests with geolocation."""
        ip = self.get_client_ip(request)

        # Block blacklisted IPs
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Access denied: Your IP address has been blocked.")

        # Get location info
        geo_info = self.get_geolocation(ip)
        country = geo_info["country"]
        city = geo_info["city"]

        # Log allowed request
        RequestLog.objects.create(
            ip_address=ip,
            path=request.path,
            timestamp=datetime.now(),
            country=country,
            city=city
        )
