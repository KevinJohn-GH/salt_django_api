from django.shortcuts import render

# Create your views here.


import os
import logging
import json

import salt.config
import salt.netapi
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

logfile = '/var/log/salt/rest_cherrypy'
loglevel = 'debug'
import salt.log.setup
salt.log.setup.setup_logfile_logger(logfile, loglevel)
logger = logging.getLogger(__name__)


from django.http import HttpResponse
from django.views import View

class MyView(View):
    def get(self, request, *args, **kwargs):
        request.session["foo"] = "hello"
        request.session["bar"] = "world"
        var = request.session["foo"]
        return HttpResponse(var)

    def post(self, request, *args, **kwargs):
        return HttpResponse(content="hello world", status=200)


    __opts__ = salt.config.client_config(
        os.environ.get("SALT_MASTER_CONFIG", "/etc/salt/master")
    )

def salt_token_tool(request):
    """
    If the custom authentication header is supplied, put it in the cookie dict
    so the rest of the session-based auth works as intended
    """
    x_auth = request.headers.get("X-Auth-Token", None)

    # X-Auth-Token header trumps session cookie
    if x_auth:
        request.cookie["session_id"] = x_auth

def salt_auth_tool(request):
    """
    Redirect all unauthenticated requests to the login page
    """
    # Redirect to the login page if the session hasn't been authed
    if "token" not in cherrypy.session:  # pylint: disable=W8601
        raise cherrypy.HTTPError(401)

    # Session is authenticated; inform caches
    cherrypy.response.headers["Cache-Control"] = "private"


class LowDataAdapter(View):
    """
    The primary entry point to Salt's REST API

    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.opts = salt.config.client_config(
            os.environ.get("SALT_MASTER_CONFIG", "/etc/salt/master")
        )
        self.api = salt.netapi.NetapiClient(self.opts)

    def exec_lowstate(self, request, client=None, token=None):
        """
        Pull a Low State data structure from request and execute the low-data
        chunks through Salt. The low-data chunks will be updated to include the
        authorization token for the current session.
        """

        # 兼容expr_form参数
        # if 'expr_form' in cherrypy.request.lowstate[0]:
        #     cherrypy.request.lowstate[0]['tgt_type'] = cherrypy.request.lowstate[0].pop('expr_form')

        lowstate = request.body

        # Release the session lock before executing any potentially
        # long-running Salt commands. This allows different threads to execute
        # Salt commands concurrently without blocking.
        # if cherrypy.request.config.get("tools.sessions.on", False):
        #     cherrypy.session.release_lock()

        # if the lowstate loaded isn't a list, lets notify the client
        if not isinstance(lowstate, list):
            return HttpResponse("Lowstates must be a list", status=400)

        # Make any requested additions or modifications to each lowstate, then
        # execute each one and yield the result.
        for chunk in lowstate:
            if token:
                chunk["token"] = token

            if "token" in chunk:
                # Make sure that auth token is hex
                try:
                    int(chunk["token"], 16)
                except (TypeError, ValueError):
                    return HttpResponse("Invalid token", status=401)

            if "token" in chunk:
                # Make sure that auth token is hex
                try:
                    int(chunk["token"], 16)
                except (TypeError, ValueError):
                    return HttpResponse("Invalid token", status=401)

            if client:
                chunk["client"] = client

            # Make any 'arg' params a list if not already.
            # This is largely to fix a deficiency in the urlencoded format.
            if "arg" in chunk and not isinstance(chunk["arg"], list):
                chunk["arg"] = [chunk["arg"]]

            ret = self.api.run(chunk)

            # Sometimes Salt gives us a return and sometimes an iterator
            if isinstance(ret, Iterator):
                yield from ret
            else:
                yield ret

    def get(self, request):
        """
        An explanation of the API with links of where to go next

        .. http:get:: /

            :reqheader Accept: |req_accept|

            :status 200: |200|
            :status 401: |401|
            :status 406: |406|

        **Example request:**

        .. code-block:: bash

            curl -i localhost:8000

        .. code-block:: text

            GET / HTTP/1.1
            Host: localhost:8000
            Accept: application/json

        **Example response:**

        .. code-block:: text

            HTTP/1.1 200 OK
            Content-Type: application/json
        """
        ret = {
            "return": "Welcome",
            "clients": salt.netapi.CLIENTS,
        }
        request[cookie["session_id"] = 123
        return HttpResponse(json.dumps(ret), content_type="application/json")

    def post(self, request, **kwargs):
        """
        Send one or more Salt commands in the request body

        .. http:post:: /

            :reqheader X-Auth-Token: |req_token|
            :reqheader Accept: |req_accept|
            :reqheader Content-Type: |req_ct|

            :resheader Content-Type: |res_ct|

            :status 200: |200|
            :status 400: |400|
            :status 401: |401|
            :status 406: |406|

            :term:`lowstate` data describing Salt commands must be sent in the
            request body.

        **Example request:**

        .. code-block:: bash

            curl -sSik https://localhost:8000 \\
                -b ~/cookies.txt \\
                -H "Accept: application/x-yaml" \\
                -H "Content-type: application/json" \\
                -d '[{"client": "local", "tgt": "*", "fun": "test.ping"}]'

        .. code-block:: text

            POST / HTTP/1.1
            Host: localhost:8000
            Accept: application/x-yaml
            X-Auth-Token: d40d1e1e
            Content-Type: application/json

            [{"client": "local", "tgt": "*", "fun": "test.ping"}]

        **Example response:**

        .. code-block:: text

            HTTP/1.1 200 OK
            Content-Length: 200
            Allow: GET, HEAD, POST
            Content-Type: application/x-yaml

            return:
            - ms-0: true
              ms-1: true
              ms-2: true
              ms-3: true
              ms-4: true
        """

        ret = {"return": list(self.exec_lowstate(request=request))}
        ret = {}
        return HttpResponse(json.dumps(ret), content_type="application/json")
