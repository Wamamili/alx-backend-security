from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from django.views import View


@method_decorator(csrf_exempt, name='dispatch')
class LoginView(View):
    """
    Example sensitive view protected by rate limiting.
    """

    # Apply rate limiting separately for authenticated vs anonymous users
    @method_decorator(ratelimit(key='ip', rate='10/m', method='POST', block=True))
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True))
    def post(self, request):
        """
        Handles a login attempt (simulated for this task).
        """
        user = request.user
        if user.is_authenticated:
            message = "Authenticated login request received."
        else:
            message = "Anonymous login attempt."
        return JsonResponse({"message": message})
