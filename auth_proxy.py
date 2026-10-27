"""OpenHost auth proxy sidecar for Calibre-Web.

Sits between the OpenHost router and Calibre-Web. When the router stamps
`X-OpenHost-Is-Owner: true` on the inbound request (meaning the visitor
holds a valid owner session), this proxy adds `X-Openhost-User: admin`
so Calibre-Web's reverse-proxy header login treats the visitor as the
`admin` user — no username/password form ever appears for the owner.

Network layout inside the container:
  0.0.0.0:8080   <- this auth-proxy sidecar (the openhost.toml-declared port)
  *:8083         <- Calibre-Web's wsgi server (the LSIO image's default,
                    which we leave alone so its s6 readiness probe still
                    fires correctly)

The OpenHost router only routes traffic to port 8080 (per openhost.toml),
so external clients cannot reach Calibre-Web's 8083 directly.

Calibre-Web is configured (in init-openhost-calibre-web) with
`config_allow_reverse_proxy_header_login = 1` and
`config_reverse_proxy_login_header_name = X-Openhost-User`, so a valid
stamped header authenticates the visitor as Calibre-Web's `admin` user.
The `admin` user is the one upstream creates by default on first boot;
init-openhost-calibre-web randomises its password so the upstream
default of admin/admin123 stops being a usable credential, and stashes
the new random password in /config/admin-password.txt as a recovery
escape hatch.

Visitors who are not the owner (e.g. invited users with their own
Calibre-Web-local password accounts) get the request passed through with
NO X-Openhost-User header. Calibre-Web then falls back to its normal
session/password auth flow at `/login`. The two paths coexist without
conflict — Calibre-Web only consults the reverse-proxy header when its
own session is empty (see cps/usermanagement.py:load_user_from_reverse_proxy_header).

Security model
==============

The OpenHost router is the sole authority for `X-OpenHost-*` headers.
Before forwarding any request to an app container, the router strips all
client-supplied `X-OpenHost-*` headers and then re-adds
`X-OpenHost-Is-Owner: true` only if the visitor's session cookie verified
successfully. This means:

  * A non-owner visitor cannot spoof the header — the router removes it
    before the request reaches us.
  * We can trust the header unconditionally, even on public paths.

We still strip `X-Openhost-User` from inbound requests as defence in
depth, so only this sidecar's stamped header is honoured. Calibre-Web
binds *:8083 inside the container (its LSIO default — we leave it
untouched so the LSIO `nc -z localhost 8083` readiness probe still
fires), but the OpenHost router only routes traffic to the
openhost.toml-declared port 8080 (this sidecar). External clients
therefore cannot reach Calibre-Web's 8083 directly: the sidecar is on
the only externally-reachable port.

We also rewrite the `Host` header from `X-Forwarded-Host`. Calibre-Web
uses Flask, which by default trusts request.host for URL generation
(setting cookies, redirecting, building OPDS URLs, etc). The OpenHost
router strips the original `Host` and puts the value the client used in
`X-Forwarded-Host`; without rewriting we'd hand Calibre-Web a Host of
127.0.0.1:8084, which would then leak into Set-Cookie domain attributes
and absolute redirects.
"""

from __future__ import annotations

import http.client
import logging
import os
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

OWNER_HEADER_NAME = "X-OpenHost-Is-Owner"
AUTH_HEADER_NAME = "X-Openhost-User"
# Headers that must not be forwarded hop-by-hop (RFC 7230 §6.1) plus a
# few extras where we control the forwarding meaning.
HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        # Host is dropped from the inbound request (it points at the
        # proxy, not the client's view of the URL); _proxy() then
        # explicitly forwards a Host header based on X-Forwarded-Host
        # so Calibre-Web's URL generation sees the right origin.
        "Host",
    )
)

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


class AuthProxyHandler(BaseHTTPRequestHandler):
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 8083

    # Route request logs through our logger so they're interleaved with
    # the module's own log lines, and suppress logs for Calibre-Web's
    # /login when the OpenHost router probes it (HEAD requests with no
    # cookies) so the ~1/second liveness traffic doesn't drown out
    # interesting log lines. We deliberately log GET /login from real
    # users — it's the username/password form, and access patterns
    # there are useful to see.
    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        path = getattr(self, "path", "")
        command = getattr(self, "command", "")
        if path.startswith("/login") and command == "HEAD":
            return
        log.info("%s - " + format, self.address_string(), *args)

    def do_GET(self) -> None:  # noqa: N802
        self._proxy()

    def do_HEAD(self) -> None:  # noqa: N802
        self._proxy()

    def do_POST(self) -> None:  # noqa: N802
        self._proxy()

    def do_PUT(self) -> None:  # noqa: N802
        self._proxy()

    def do_DELETE(self) -> None:  # noqa: N802
        self._proxy()

    def do_PATCH(self) -> None:  # noqa: N802
        self._proxy()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._proxy()

    # Cap on request- and response-body memory so a crafted or
    # buggy client cannot drive the proxy OOM by sending
    # `Content-Length: 2147483647`. 256 MiB is generous enough to
    # cover Calibre-Web's typical use cases (uploading ebooks,
    # serving cover images, downloading converted formats); the
    # largest legitimate single payload is a multi-format ebook
    # download which can hit ~100 MiB for a graphic novel.
    #
    # Calibre-Web does not expose any single-request endpoint that
    # would legitimately exceed this cap. If you need to upload a
    # larger book, do so via the file system / volume mount, not
    # the web upload form.
    MAX_BODY_BYTES = 256 * 1024 * 1024

    # Read timeout on the client socket. A slow-loris client dripping body
    # bytes over minutes would otherwise tie up a server thread indefinitely,
    # leading to thread exhaustion under concurrency.
    CLIENT_READ_TIMEOUT_SECONDS = 60

    def _safe_send_error(self, code: int, message: str) -> None:
        """Send an HTTP error, silently swallowing OSError.

        If the client has already disconnected, send_error will fail with
        BrokenPipeError (an OSError subclass). We don't want that to bubble
        up as an unhandled exception — the request is already over.
        """
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    def _proxy(self) -> None:
        # Apply a read timeout to the incoming socket so a slow client can't
        # hold a thread forever while sending the request body.
        try:
            self.connection.settimeout(self.CLIENT_READ_TIMEOUT_SECONDS)
        except OSError:
            # Very unlikely (socket already closed); nothing to recover.
            pass

        # Check owner status BEFORE stripping headers. The router
        # guarantees this header is authentic: it strips all
        # client-supplied X-OpenHost-* headers and only re-adds
        # X-OpenHost-Is-Owner: true after verifying the owner's session
        # cookie, so we can trust it unconditionally even on public paths.
        is_owner = self.headers.get(OWNER_HEADER_NAME, "").strip().lower() == "true"

        # Strip (a) the auth + owner headers (never forward client-supplied
        # or router-internal auth headers to Calibre-Web), (b) hop-by-hop
        # headers (Connection, Transfer-Encoding, etc.), and (c)
        # Content-Length — we rebuild the body into a buffered request
        # below and set a fresh Content-Length from the actual bytes we
        # send. Forwarding the client's Content-Length or Transfer-Encoding
        # would confuse the upstream when the two disagree.
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS
            | {
                AUTH_HEADER_NAME.lower(),
                OWNER_HEADER_NAME.lower(),
                "content-length",
            },
        )

        # Rewrite Host from X-Forwarded-Host. The OpenHost router strips
        # the original Host header and puts the value the client actually
        # used into X-Forwarded-Host. Calibre-Web's URL generation
        # (cookies, redirects, OPDS catalogue absolute URLs) reads
        # request.host; without this rewrite Calibre-Web would emit
        # links to 127.0.0.1:8084 instead of the public hostname.
        #
        # Some inbound requests (e.g. the OpenHost router's own liveness
        # probe to /robots.txt) won't have X-Forwarded-Host set. We fall
        # back to letting http.client set its default Host (which points
        # at the loopback target) so the upstream still gets a valid
        # Host field — RFC 7230 §5.4 requires one and Flask raises
        # otherwise.
        forwarded_host = self.headers.get("X-Forwarded-Host")
        explicit_host_set = False
        if forwarded_host:
            cleaned_headers.append(("Host", forwarded_host))
            explicit_host_set = True

        if is_owner:
            # `admin` is the Calibre-Web username we map the OpenHost
            # owner to. It is the username Calibre-Web creates by
            # default on first boot; init-openhost-calibre-web
            # randomises its password so the upstream default
            # admin/admin123 is no longer a usable credential.
            cleaned_headers.append((AUTH_HEADER_NAME, "admin"))

        # Reject chunked (and any other non-identity) transfer encoding
        # outright. We buffer the body into a new Content-Length request;
        # forwarding the raw chunked bytes as a plain body would corrupt
        # the upstream's parse, and implementing dechunking here duplicates
        # what the fronting OpenHost router (httpx-based) already does
        # before it reaches us. 501 is the correct status code: the
        # semantic issue is "we do not implement this transfer-coding", not
        # "please add Content-Length and try again" (which 411 would imply
        # and which would send a client into a retry loop).
        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower().strip()
        if transfer_encoding and transfer_encoding != "identity":
            self._safe_send_error(501, "Transfer-Encoding not supported")
            return

        body: bytes | None = None
        content_length_header = self.headers.get("Content-Length")
        if content_length_header:
            try:
                length = int(content_length_header)
            except ValueError:
                self._safe_send_error(400, "invalid Content-Length")
                return
            if length < 0:
                self._safe_send_error(400, "negative Content-Length")
                return
            if length > self.MAX_BODY_BYTES:
                # Reject before allocating. Without this cap a hostile
                # client could advertise a multi-GiB body and exhaust
                # container RAM.
                self._safe_send_error(413, "request body too large")
                return
            if length > 0:
                try:
                    body = self.rfile.read(length)
                except (OSError, TimeoutError) as exc:
                    # Client dropped the connection or the socket timeout
                    # we set at the top of _proxy() fired. Return 400 so
                    # the client sees a clean response instead of a raw
                    # traceback in the server log.
                    log.info("client read error: %s", exc)
                    self._safe_send_error(400, "request body read failed")
                    return
                if len(body) != length:
                    # Short read: the client closed the socket before
                    # sending the full body they promised. We must not
                    # silently forward a truncated body with a shorter
                    # Content-Length header — Calibre-Web would accept
                    # the truncated request as if it were complete.
                    log.info(
                        "short read: expected %d bytes, got %d",
                        length,
                        len(body),
                    )
                    self._safe_send_error(400, "incomplete request body")
                    return
            else:
                body = b""
        elif self.command in ("POST", "PUT", "PATCH", "DELETE"):
            # Body method with no Content-Length and no Transfer-Encoding.
            # The HTTP spec says this means "no body" for a request (unlike a
            # response, which can use connection-close framing). Forward an
            # empty body rather than blocking waiting for EOF, which would
            # otherwise let a slow client tie up a handler thread until the
            # 60s socket timeout fires.
            body = b""

        # The outer try/finally guarantees the upstream socket is always
        # released, even if conn.request() or getresponse() raises. We use
        # putrequest/putheader rather than conn.request() so that duplicate
        # header names (e.g. multiple Set-Cookie on the request direction or
        # chained X-Forwarded-For entries) are each preserved — conn.request()
        # takes a dict and would silently collapse duplicates to the last
        # value.
        conn = http.client.HTTPConnection(
            self.upstream_host, self.upstream_port, timeout=60
        )
        try:
            try:
                # When we successfully rewrote Host from
                # X-Forwarded-Host, suppress http.client's automatic
                # Host header so our explicit one wins. When we don't
                # have an X-Forwarded-Host (e.g. router liveness
                # probes), let http.client set its default Host
                # (`127.0.0.1:8083`) so the upstream request still
                # has a valid Host field — RFC 7230 §5.4 requires
                # one and Flask raises otherwise.
                # `skip_accept_encoding` avoids http.client adding
                # `Accept-Encoding: identity` if the client omitted
                # the header.
                conn.putrequest(
                    self.command,
                    self.path,
                    skip_host=explicit_host_set,
                    skip_accept_encoding=True,
                )
                for key, value in cleaned_headers:
                    conn.putheader(key, value)
                if body is not None:
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(message_body=body)
                upstream = conn.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            # Read the upstream body into memory, capped at the same
            # limit we enforce on request bodies. A compromised or
            # misbehaving Calibre-Web streaming an oversized response
            # could otherwise exhaust container RAM. `read(MAX_BODY_BYTES + 1)`
            # lets us distinguish "cap reached, probably more available"
            # from "legitimate body just under the cap".
            try:
                payload = upstream.read(self.MAX_BODY_BYTES + 1)
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream read error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                try:
                    upstream.close()
                except Exception as close_exc:  # noqa: BLE001 - best effort
                    log.debug("upstream.close() after read error raised: %s", close_exc)
                return
            try:
                upstream.close()
            except Exception as exc:  # noqa: BLE001 - best effort only
                log.debug("upstream.close() raised (ignored): %s", exc)
            if len(payload) > self.MAX_BODY_BYTES:
                log.warning(
                    "upstream response exceeded %d bytes; returning 502",
                    self.MAX_BODY_BYTES,
                )
                self._safe_send_error(502, "upstream response too large")
                return

            # Forward upstream's status + headers. We leave upstream's
            # Content-Length intact because for HEAD it's the only way the
            # client learns the size a real GET would return; for everything
            # else it matches len(payload) anyway since we just read the
            # whole body. The whole block writes to the client socket, so a
            # disconnect here surfaces as OSError; swallow it the same way
            # we do for the body write below.
            #
            # `upstream.reason` can legitimately be None (RFC 9110 §6.2
            # allows a bare status line with no reason phrase); fall back
            # to an empty string so send_response doesn't emit
            # "HTTP/1.1 200 None".
            reason = upstream.reason or ""
            try:
                self.send_response(upstream.status, reason)
                for key, value in upstream.getheaders():
                    if key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    self.send_header(key, value)
                self.end_headers()
                # HEAD responses MUST NOT include a message body (RFC 9110
                # §9.3.2). http.client already returns an empty payload for
                # HEAD but suppress the write unconditionally for clarity.
                if self.command != "HEAD":
                    self.wfile.write(payload)
            except OSError as exc:
                # BrokenPipeError, ConnectionResetError, TimeoutError, and
                # ECONNABORTED are all signals that the client went away.
                # Nothing we can do except log at debug and avoid crashing
                # the handler thread.
                log.debug("client disconnected mid-response: %s", exc)
        finally:
            conn.close()


class IPv4ThreadingServer(ThreadingHTTPServer):
    # OpenHost's router talks to the container over Docker's bridge network
    # on IPv4, so we explicitly bind IPv4 and don't advertise dual-stack
    # capability. allow_reuse_address lets us come back up quickly after a
    # crash, daemon_threads ensures request threads don't keep the process
    # alive on shutdown.
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def _port_from_env(name: str, default: int) -> int:
    """Read a port from an env var, with a clear error on non-integer input."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer: {exc}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}={raw!r} is out of range (1-65535)")
    return port


def main() -> int:
    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 8080)
        upstream_port = _port_from_env("CALIBRE_WEB_UPSTREAM_PORT", 8083)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    AuthProxyHandler.upstream_port = upstream_port

    # Wait for Calibre-Web to bind its upstream port before we start
    # accepting traffic. The s6 dependency on svc-calibre-web ensures
    # svc-calibre-web has reached its `up` state (s6-notifyoncheck has
    # confirmed `nc -z localhost 8083` succeeds), so by this point
    # Calibre-Web should already be listening — but we re-check here as
    # belt-and-braces. If we accept a request before Calibre-Web is up
    # we'd return a spurious 502 to the OpenHost router's first liveness
    # probe, which has cascaded into "app failed to start" reports in
    # the past.
    upstream_ready_deadline = time.monotonic() + 60
    while time.monotonic() < upstream_ready_deadline:
        try:
            with socket.create_connection(("127.0.0.1", upstream_port), timeout=1):
                break
        except OSError:
            time.sleep(0.5)
    else:
        # If we time out waiting we still start the server — Calibre-Web
        # might just be slow on first boot — but log loudly so it shows
        # up in the container logs.
        log.warning(
            "upstream 127.0.0.1:%d still not listening after 60s; "
            "starting anyway and hoping it shows up",
            upstream_port,
        )

    try:
        server = IPv4ThreadingServer(("0.0.0.0", listen_port), AuthProxyHandler)
    except OSError as exc:
        # Typically "address already in use" if something else is already
        # bound. Fail with a clear message instead of a raw traceback so
        # the operator can see what's wrong in the container logs.
        log.error(
            "failed to bind auth-proxy listener on 0.0.0.0:%d: %s",
            listen_port,
            exc,
        )
        return 1
    log.info(
        "listening on 0.0.0.0:%d -> 127.0.0.1:%d",
        listen_port,
        upstream_port,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
