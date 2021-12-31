# @Author   : xiansong wu
# @Time     : 2021/12/29 17:12
# @Function :

from django.contrib.sessions.backends.cache import SessionStore
from django.http import HttpResponse


def salt_token_tool(func):
    """
    If the custom authentication header is supplied, put it in the cookie dict
    so the rest of the session-based auth works as intended
    """
    def wrapper(*args, **kwargs):
        request = args[1]
        x_auth = request.headers.get("X-Auth-Token", None)
        # X-Auth-Token header trumps session cookie
        if x_auth:
            request.COOKIES["sessionid"] = x_auth
            request.session = SessionStore(session_key=x_auth)
        return func(*args, **kwargs)
    return wrapper


def salt_auth_tool(func):
    """
    Redirect all unauthenticated requests to the login page
    """
    # Redirect to the login page if the session hasn't been authed
    def wrapper(*args, **kwargs):
        request = args[1]
        if "token" not in request.session.keys():  # pylint: disable=W8601
            return HttpResponse(status=401)

        # Session is authenticated; inform caches
        response = func(*args, **kwargs)
        response.headers["Cache-Control"] = "private"
        return response
    return wrapper
