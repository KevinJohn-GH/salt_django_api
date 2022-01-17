from collections import Iterator

from django.shortcuts import render

# Create your views here.


import os
import logging
import json

import salt.config
import salt.netapi
import auth
# import tokens

logfile = '/var/log/salt/rest_cherrypy'
loglevel = 'debug'
import salt.log.setup
salt.log.setup.setup_logfile_logger(logfile, loglevel)
logger = logging.getLogger(__name__)


from django.http import HttpResponse
from django.views import View
import api.tools
import management.settings as settings



__opt__ = salt.config.client_config(os.environ.get("SALT_MASTER_CONFIG", "/etc/salt/master"))

def salt_api_acl_tool(username, request):
    """
    .. versionadded:: 2016.3.0

    Verifies user requests against the API whitelist. (User/IP pair)
    in order to provide whitelisting for the API similar to the
    master, but over the API.

    .. code-block:: yaml

        rest_cherrypy:
            api_acl:
                users:
                    '*':
                        - 1.1.1.1
                        - 1.1.1.2
                    foo:
                        - 8.8.4.4
                    bar:
                        - '*'

    :param username: Username to check against the API.
    :type username: str
    :param request: Cherrypy request to check against the API.
    :type request: cherrypy.request
    """
    failure_str = "[api_acl] Authentication failed for " "user {0} from IP {1}"
    success_str = "[api_acl] Authentication successful for user {0} from IP {1}"
    pass_str = "[api_acl] Authentication not checked for " "user {0} from IP {1}"

    acl = None
    # Salt Configuration
    salt_config = settings.SALT_OPT
    if salt_config:
        # Cherrypy Config.
        cherrypy_conf = salt_config.get("rest_cherrypy", None)
        if cherrypy_conf:
            # ACL Config.
            acl = cherrypy_conf.get("api_acl", None)

    ip = request.META['REMOTE_ADDR']
    if acl:
        users = acl.get("users", {})
        if users:
            if username in users:
                if ip in users[username] or "*" in users[username]:
                    logger.info(success_str.format(username, ip))
                    return True
                else:
                    logger.info(failure_str.format(username, ip))
                    return False
            elif username not in users and "*" in users:
                if ip in users["*"] or "*" in users["*"]:
                    logger.info(success_str.format(username, ip))
                    return True
                else:
                    logger.info(failure_str.format(username, ip))
                    return False
            else:
                logger.info(failure_str.format(username, ip))
                return False
    else:
        logger.info(pass_str.format(username, ip))
        return True


class LowDataAdapter(View):
    """
    The primary entry point to Salt's REST API

    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.opts = settings.SALT_OPT
        self.api = salt.netapi.NetapiClient(self.opts)

    def exec_lowstate(self, request, client=None, token=None):
        """
        Pull a Low State data structure from request and execute the low-data
        chunks through Salt. The low-data chunks will be updated to include the
        authorization token for the current session.
        """
        token = request.session.get("token")
        # 兼容expr_form参数
        # if 'expr_form' in cherrypy.request.lowstate[0]:
        #     cherrypy.request.lowstate[0]['tgt_type'] = cherrypy.request.lowstate[0].pop('expr_form')

        lowstate = json.loads(request.body)

        # Release the session lock before executing any potentially
        # long-running Salt commands. This allows different threads to execute
        # Salt commands concurrently without blocking.
        # if cherrypy.request.config.get("tools.sessions.on", False):
        #     cherrypy.session.release_lock()

        # if the lowstate loaded isn't a list, lets notify the client
        if not isinstance(lowstate, list):
            lowstate = [lowstate]

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

    @api.tools.salt_token_tool
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
        request.session["foo"] = request.session.session_key
        ret = {
            "return": "Welcome",
            "clients": salt.netapi.CLIENTS,
            "hello": "world",
            "session": request.session.session_key,
            "foo": request.session["foo"]

        }
        return HttpResponse(json.dumps(ret), content_type="application/json")

    @api.tools.salt_token_tool
    @api.tools.salt_auth_tool
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
        response = HttpResponse(content=json.dumps(ret), content_type=request.headers["Accept"])
        return response


class Login(LowDataAdapter):
    """
    Log in to receive a session token

    :ref:`Authentication information <rest_cherrypy-auth>`.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.auth = auth.LoadAuth(self.opts)
        # self.auth = salt.auth.Resolver(self.opts)


    def get(self, request):
        """
        Present the login interface

        .. http:get:: /login

            An explanation of how to log in.

            :status 200: |200|
            :status 401: |401|
            :status 406: |406|

        **Example request:**

        .. code-block:: bash

            curl -i localhost:8000/login

        .. code-block:: text

            GET /login HTTP/1.1
            Host: localhost:8000
            Accept: text/html

        **Example response:**

        .. code-block:: text

            HTTP/1.1 200 OK
            Content-Type: text/html
        """
        response = HttpResponse()
        response.headers["WWW-Authenticate"] = "Session"
        response.content = json.dumps({
            "status": response.status_code,
            "return": "Please log in",
        })
        return response

    def post(self, request, **kwargs):
        """
        :ref:`Authenticate  <rest_cherrypy-auth>` against Salt's eauth system

        .. http:post:: /login

            :reqheader X-Auth-Token: |req_token|
            :reqheader Accept: |req_accept|
            :reqheader Content-Type: |req_ct|

            :form eauth: the eauth backend configured for the user
            :form username: username
            :form password: password

            :status 200: |200|
            :status 401: |401|
            :status 406: |406|

        **Example request:**

        .. code-block:: bash

            curl -si localhost:8000/login \\
                -c ~/cookies.txt \\
                -H "Accept: application/json" \\
                -H "Content-type: application/json" \\
                -d '{
                    "username": "saltuser",
                    "password": "saltuser",
                    "eauth": "auto"
                }'

        .. code-block:: text

            POST / HTTP/1.1
            Host: localhost:8000
            Content-Length: 42
            Content-Type: application/json
            Accept: application/json

            {"username": "saltuser", "password": "saltuser", "eauth": "auto"}


        **Example response:**

        .. code-block:: text

            HTTP/1.1 200 OK
            Content-Type: application/json
            Content-Length: 206
            X-Auth-Token: 6d1b722e
            Set-Cookie: session_id=6d1b722e; expires=Sat, 17 Nov 2012 03:23:52 GMT; Path=/

            {"return": {
                "token": "6d1b722e",
                "start": 1363805943.776223,
                "expire": 1363849143.776224,
                "user": "saltuser",
                "eauth": "pam",
                "perms": [
                    "grains.*",
                    "status.*",
                    "sys.*",
                    "test.*"
                ]
            }}
        """
        if not self.api._is_master_running():
            raise salt.exceptions.SaltDaemonNotRunning("Salt Master is not available.")

        # the urlencoded_processor will wrap this in a list
        if isinstance(json.loads(request.body), list):
            creds = json.loads(request.body)[0]
        else:
            creds = json.loads(request.body)

        username = creds.get("username", None)
        # Validate against the whitelist.
        if not salt_api_acl_tool(username, request):
            return HttpResponse(status=401)

        # Mint token.
        token = self.auth.mk_token(creds)
        if "token" not in token:
            return HttpResponse(
                "Could not authenticate using provided credentials", status=401
            )

        response = HttpResponse()
        response.headers["X-Auth-Token"] = request.session.session_key
        # TODO: response type
        response.headers["Content-Type"] = "application/json"
        request.session["token"] = token["token"]
        request.session["timeout"] = (token["expire"] - token["start"]) / 60

        # Grab eauth config for the current backend for the current user
        try:
            eauth = self.opts.get("external_auth", {}).get(token["eauth"], {})

            if token["eauth"] == "django" and "^model" in eauth:
                perms = token["auth_list"]
            else:
                # Get sum of '*' perms, user-specific perms, and group-specific perms
                perms = eauth.get(token["name"], [])
                perms.extend(eauth.get("*", []))

                if "groups" in token and token["groups"]:
                    user_groups = set(token["groups"])
                    eauth_groups = {
                        i.rstrip("%") for i in eauth.keys() if i.endswith("%")
                    }

                    for group in user_groups & eauth_groups:
                        perms.extend(eauth["{}%".format(group)])

            if not perms:
                logger.debug("Eauth permission list not found.")
        except Exception:  # pylint: disable=broad-except
            logger.debug(
                "Configuration for external_auth malformed for "
                "eauth '{}', and user '{}'.".format(
                    token.get("eauth"), token.get("name")
                ),
                exc_info=True,
            )
            perms = None

        response.content = json.dumps( {
            "return": [
                {
                    "token": request.session.session_key,
                    "expire": token["expire"],
                    "start": token["start"],
                    "user": token["name"],
                    "eauth": token["eauth"],
                    "perms": perms or {},
                }
            ]
        })
        return response