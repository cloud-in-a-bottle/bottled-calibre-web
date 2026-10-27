import re
import time
from urllib.parse import urlparse

import requests
from openhost_test_harness import OpenhostStack

HTML = {"Accept": "text/html"}
CSRF_TOKEN = re.compile(r'name="csrf_token" value="([^"]+)"')


def _get_when_up(session: requests.Session, url: str, stack: OpenhostStack) -> requests.Response:
    # The app is marked running once /login answers; the first boot's init can still be settling.
    deadline = time.monotonic() + 120
    while True:
        try:
            response = session.get(url, headers=HTML, timeout=30)
            if response.status_code < 500:
                return response
        except requests.ConnectionError:
            pass
        if time.monotonic() > deadline:
            raise AssertionError(f"{url} never came up\n\n{stack.app_logs()[-5000:]}")
        time.sleep(2)


def test_owner_is_signed_in_as_admin(stack: OpenhostStack) -> None:
    # auth_proxy.py stamps X-Openhost-User: admin on owner requests and our init enables Calibre-Web's
    # reverse-proxy header login for it, so the owner lands in the library as admin with no login form.
    response = _get_when_up(stack.owner_session, f"{stack.url}/", stack)
    path = urlparse(response.url).path
    # Our init also creates an empty library and points Calibre-Web at it; without it the admin is sent to the
    # database setup page instead of the library.
    assert path == "/", f"owner ended up at {response.url} ({response.status_code}): {response.text[:500]}"
    assert response.status_code == 200
    user = re.search(r'id="top_user".*?<span class="hidden-sm">([^<]*)</span>', response.text, re.S)
    assert user and user.group(1) == "admin", f"not signed in as admin: {response.text[:2000]}"
    # Uploads are enabled out of the box (config_uploading = 1).
    assert 'id="form-upload"' in response.text, "no upload button on the library page"

    admin = stack.owner_session.get(f"{stack.url}/admin/view", headers=HTML, timeout=30)
    assert admin.status_code == 200 and urlparse(admin.url).path == "/admin/view", admin.url


def test_anonymous_gets_login_form(stack: OpenhostStack) -> None:
    # The whole app is public (public_paths = ["/"]) so invited readers can use Calibre-Web's own login; anonymous
    # visitors must get that form, not the library, even if they send the headers that grant owner access.
    anonymous = requests.Session()
    spoofed = {**HTML, "X-Openhost-User": "admin", "X-OpenHost-Is-Owner": "true"}
    _get_when_up(anonymous, f"{stack.url}/login", stack)
    response = anonymous.get(f"{stack.url}/", headers=spoofed, timeout=30)
    assert urlparse(response.url).path == "/login", f"anonymous got {response.url}: {response.text[:500]}"
    assert 'name="password"' in response.text

    # The upstream default admin/admin123 is replaced with a random password on first boot.
    token = CSRF_TOKEN.search(response.text)
    assert token, f"no csrf token on login form: {response.text[:1000]}"
    anonymous.post(
        f"{stack.url}/login",
        data={"username": "admin", "password": "admin123", "csrf_token": token.group(1), "next": "/"},
        headers=HTML,
        timeout=30,
    )
    after = anonymous.get(f"{stack.url}/admin/view", headers=HTML, timeout=30)
    assert urlparse(after.url).path == "/login", f"admin/admin123 still logs in: {after.url}"


def test_config_and_library_in_app_data(stack: OpenhostStack) -> None:
    # Calibre-Web's settings/users db and the library live in the app data dir rather than LSIO's /config volume,
    # which is recreated empty on every redeploy.
    _get_when_up(stack.owner_session, f"{stack.url}/", stack)
    for rel in ("config/app.db", "books/metadata.db"):
        assert (stack.data_dir / rel).is_file(), f"{rel} missing from app data\n\n{stack.app_logs()[-3000:]}"
