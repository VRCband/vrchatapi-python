# coding: utf-8

"""
REST client layer for vrchatapi-python, with cookie persistence support.
"""

import re
import json
import ssl
import urllib3
from urllib.parse import urlencode
from urllib.request import Request
from http.cookiejar import CookieJar
from http.cookies import SimpleCookie
from requests.cookies import create_cookie

import six

from .exceptions import (
    ApiException,
    ApiValueError,
    UnauthorizedException,
    ForbiddenException,
    NotFoundException,
    ServiceException,
)

# Response wrapper to normalize urllib3 responses
class RESTResponse(object):
    def __init__(self, response):
        self.status = response.status
        self.data = response.data
        self.headers = response.headers
        self.reason = getattr(response, "reason", None)


class RESTClientObject(object):
    def __init__(self, configuration, pools_size=4, maxsize=None):
        # Determine SSL requirement
        if configuration.verify_ssl:
            cert_reqs = ssl.CERT_REQUIRED
        else:
            cert_reqs = ssl.CERT_NONE

        # Initialize cookie storage
        self.cookie_jar = CookieJar()

        # PoolManager arguments
        addition_pool_args = {}
        if configuration.assert_hostname is not None:
            addition_pool_args["assert_hostname"] = configuration.assert_hostname
        if configuration.retries is not None:
            addition_pool_args["retries"] = configuration.retries
        if configuration.socket_options is not None:
            addition_pool_args["socket_options"] = configuration.socket_options

        # Determine maxsize
        if maxsize is None:
            maxsize = configuration.connection_pool_maxsize or 4

        # Create the pool manager (with or without proxy)
        if configuration.proxy:
            self.pool_manager = urllib3.ProxyManager(
                num_pools=pools_size,
                maxsize=maxsize,
                cert_reqs=cert_reqs,
                ca_certs=configuration.ssl_ca_cert,
                cert_file=configuration.cert_file,
                key_file=configuration.key_file,
                proxy_url=configuration.proxy,
                proxy_headers=configuration.proxy_headers,
                **addition_pool_args
            )
        else:
            self.pool_manager = urllib3.PoolManager(
                num_pools=pools_size,
                maxsize=maxsize,
                cert_reqs=cert_reqs,
                ca_certs=configuration.ssl_ca_cert,
                cert_file=configuration.cert_file,
                key_file=configuration.key_file,
                **addition_pool_args
            )

    def request(
        self,
        method,
        url,
        query_params=None,
        headers=None,
        body=None,
        post_params=None,
        _preload_content=True,
        _request_timeout=None,
    ):
        """Perform HTTP request, inject and extract cookies automatically."""
        method = method.upper()
        assert method in ["GET", "HEAD", "DELETE", "POST", "PUT", "PATCH", "OPTIONS"]

        if post_params and body:
            raise ApiValueError(
                "body parameter cannot be used with post_params parameter."
            )

        post_params = post_params or {}
        headers = headers or {}

        # Inject cookies into the outgoing request
        mock_req = Request(url=url, method=method, headers=headers)
        self.cookie_jar.add_cookie_header(mock_req)
        if "Cookie" in mock_req.unredirected_hdrs:
            headers["Cookie"] = mock_req.unredirected_hdrs["Cookie"]

        # Build timeout object
        timeout = None
        if _request_timeout is not None:
            if isinstance(_request_timeout, six.integer_types + (float,)):
                timeout = urllib3.Timeout(total=_request_timeout)
            elif isinstance(_request_timeout, tuple) and len(_request_timeout) == 2:
                timeout = urllib3.Timeout(
                    connect=_request_timeout[0], read=_request_timeout[1]
                )

        # Ensure a default Content-Type
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"

        try:
            # Write GET/POST/PUT/PATCH/DELETE logic
            if method in ["POST", "PUT", "PATCH", "OPTIONS", "DELETE"]:
                if query_params:
                    url += "?" + urlencode(query_params)

                if re.search("json", headers["Content-Type"], re.IGNORECASE):
                    payload = json.dumps(body) if body is not None else None
                    resp = self.pool_manager.request(
                        method,
                        url,
                        body=payload,
                        preload_content=_preload_content,
                        timeout=timeout,
                        headers=headers,
                    )
                elif headers["Content-Type"] == "application/x-www-form-urlencoded":
                    resp = self.pool_manager.request(
                        method,
                        url,
                        fields=post_params,
                        encode_multipart=False,
                        preload_content=_preload_content,
                        timeout=timeout,
                        headers=headers,
                    )
                elif headers["Content-Type"] == "multipart/form-data":
                    del headers["Content-Type"]
                    resp = self.pool_manager.request(
                        method,
                        url,
                        fields=post_params,
                        encode_multipart=True,
                        preload_content=_preload_content,
                        timeout=timeout,
                        headers=headers,
                    )
                elif isinstance(body, (str, bytes)):
                    resp = self.pool_manager.request(
                        method,
                        url,
                        body=body,
                        preload_content=_preload_content,
                        timeout=timeout,
                        headers=headers,
                    )
                else:
                    msg = (
                        "Cannot prepare a request message for provided "
                        "arguments. Please check that your arguments match "
                        "declared content type."
                    )
                    raise ApiException(status=0, reason=msg)
            else:
                resp = self.pool_manager.request(
                    method,
                    url,
                    fields=query_params,
                    preload_content=_preload_content,
                    timeout=timeout,
                    headers=headers,
                )
        except urllib3.exceptions.SSLError as e:
            raise ApiException(status=0, reason=f"{type(e).__name__}\n{e}")

        # Extract Set-Cookie headers
        if hasattr(resp, "headers") and "set-cookie" in resp.headers:
            cookie = SimpleCookie()
            cookie.load(resp.headers["set-cookie"])
            for key, morsel in cookie.items():
                self.cookie_jar.set_cookie(
                    create_cookie(name=key, value=morsel.value)
                )

        # Wrap response if requested
        if _preload_content:
            resp = RESTResponse(resp)

        # Error handling
        if not 200 <= resp.status <= 299:
            if resp.status == 401:
                raise UnauthorizedException(http_resp=resp)
            if resp.status == 403:
                raise ForbiddenException(http_resp=resp)
            if resp.status == 404:
                raise NotFoundException(http_resp=resp)
            if 500 <= resp.status <= 599:
                raise ServiceException(http_resp=resp)
            raise ApiException(http_resp=resp)

        # 2FA enforcement detection
        if re.match(b'{"\\w{21}":\\["totp","otp"]}', resp.data):
            resp.reason = "2 Factor Authentication verification is required"
            raise UnauthorizedException(http_resp=resp)
        elif re.match(b'{"\\w{21}":\\["emailOtp"]}', resp.data):
            resp.reason = "Email 2 Factor Authentication verification is required"
            raise UnauthorizedException(http_resp=resp)

        return resp

    def get_cookie(self, name):
        """Return the value of a cookie by name."""
        for c in self.cookie_jar:
            if c.name == name:
                return c.value
        return None

    def get_all_cookies(self):
        """Return a dict of all stored cookies."""
        return {c.name: c.value for c in self.cookie_jar}

    def GET(self, url, headers=None, query_params=None, _preload_content=True,
            _request_timeout=None):
        return self.request("GET", url,
                            headers=headers,
                            _preload_content=_preload_content,
                            _request_timeout=_request_timeout,
                            query_params=query_params)

    def HEAD(self, url, headers=None, query_params=None, _preload_content=True,
             _request_timeout=None):
        return self.request("HEAD", url,
                            headers=headers,
                            _preload_content=_preload_content,
                            _request_timeout=_request_timeout,
                            query_params=query_params)

    def OPTIONS(self, url, headers=None, query_params=None, post_params=None,
                body=None, _preload_content=True, _request_timeout=None):
        return self.request("OPTIONS", url,
                            headers=headers,
                            query_params=query_params,
                            post_params=post_params,
                            _preload_content=_preload_content,
                            _request_timeout=_request_timeout,
                            body=body)

    def DELETE(self, url, headers=None, query_params=None, body=None,
               _preload_content=True, _request_timeout=None):
        return self.request("DELETE", url,
                            headers=headers,
                            query_params=query_params,
                            _preload_content=_preload_content,
                            _request_timeout=_request_timeout,
                            body=body)

    def POST(self, url, headers=None, query_params=None, post_params=None,
             body=None, _preload_content=True, _request_timeout=None):
        return self.request("POST", url,
                            headers=headers,
                            query_params=query_params,
                            post_params=post_params,
                            _preload_content=_preload_content,
                            _request_timeout=_request_timeout,
                            body=body)

    def PUT(self, url, headers=None, query_params=None, post_params=None,
            body=None, _preload_content=True, _request_timeout=None):
        return self.request("PUT", url,
                            headers=headers,
                            query_params=query_params,
                            post_params=post_params,
                            _preload_content=_preload_content,
                            _request_timeout=_request_timeout,
                            body=body)

    def PATCH(self, url, headers=None, query_params=None, post_params=None,
              body=None, _preload_content=True, _request_timeout=None):
        return self.request("PATCH", url,
                            headers=headers,
                            query_params=query_params,
                            post_params=post_params,
                            _preload_content=_preload_content,
                            _request_timeout=_request_timeout,
                            body=body)
