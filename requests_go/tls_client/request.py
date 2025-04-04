from json import dumps, loads

from .client import request, freeMemory
from .response import build_response
from ..tls_config import TLSConfig
from .exceptions import TLSClientExeption

class Session:
    def __init__(self, tls_config: TLSConfig = None):
        super(Session, self).__init__()
        self.tls_config = tls_config

    def request(self, method, url, params=None, data=None, headers=None, headers_order=None, cookies=None, timeout=None, allow_redirects=True,
                proxies=None, verify=None, json=None, body=None, ja3=None, pseudo_header_order=None, tls_extensions=None, http2_settings=None, force_http1=False):
        if self.tls_config.get("Ja3", None):
            ja3 = self.tls_config["Ja3"]
        if self.tls_config.get("PseudoHeaderOrder", None):
            pseudo_header_order = self.tls_config["PseudoHeaderOrder"]
        if self.tls_config.get("TLSExtensions", None):
            tls_extensions = self.tls_config["TLSExtensions"]
        if self.tls_config.get("HTTP2Settings", None):
            http2_settings = self.tls_config["HTTP2Settings"]
        if self.tls_config.get("HeadersOrder", None):
            headers_order = self.tls_config["HeadersOrder"]
        if self.tls_config.get("ForceHTTP1", None):
            force_http1 = self.tls_config["ForceHTTP1"]
        if not method and not url and ja3:
            raise Exception("method and url and ja3 must exist")
        request_params = {
            "Method": method,
            "Url": url,
            "Ja3": ja3,
        }
        if params:
            request_params["Params"] = params
        if headers:
            request_params["Headers"] = headers
        if headers_order:
            request_params["HeadersOrder"] = headers_order
        if cookies:
            request_params["Cookies"] = cookies
        if timeout:
            request_params["Timeout"] = timeout
        if allow_redirects:
            request_params["AllowRedirects"] = allow_redirects
        if proxies:
            if type(proxies) == dict:
                if proxies.get("https", ""):
                    request_params["Proxies"] = proxies["https"]
                elif proxies.get("http", ""):
                    request_params["Proxies"] = proxies["http"]
                else:
                    raise TLSClientExeption('Proxies必须为{"http": "代理IP", "https": "代理IP"}')
            else:
                request_params["Proxies"] = proxies
        # if verify:
        #     request_params["Verify"] = verify
        if body:
            if type(body) == str:
                request_params["Body"] = body
            elif type(body) == bytes:
                request_params["Body"] = body.decode()
            else:
                raise TLSClientExeption("Body data is not a string or bytes class.")
        elif data:
            request_params["Data"] = data
        elif json:
            request_params["Json"] = json
        if force_http1:
            request_params["ForceHTTP1"] = force_http1
        if pseudo_header_order:
            request_params["PseudoHeaderOrder"] = pseudo_header_order
        if tls_extensions:
            request_params["TLSExtensions"] = dumps(tls_extensions, separators=(",", ":"))
        if http2_settings:
            request_params["HTTP2Settings"] = dumps(http2_settings, separators=(",", ":"))
        rs = request(dumps(request_params).encode("utf-8")).decode("utf-8")
        try:
            res = loads(rs)
            if res.get("err", ""):
                raise TLSClientExeption(res["err"])
            freeMemory(res["id"].encode("utf-8"))
            return build_response(res)
        except Exception as e:
            raise TLSClientExeption("requests_go error:", rs)
