# bottled-calibre-web

[Calibre-Web](https://github.com/janeczku/calibre-web) packaged for Cloud in a Bottle.
Calibre-Web is a Flask web app that serves an existing Calibre ebook library
over the web with a clean reading UI, OPDS feed, sync support, and
admin/user management.

## Features

- **Owner SSO via Cloud in a Bottle.** Owners are auto-logged-in as the Calibre-Web
  `admin` user via the bundled auth-proxy sidecar. The proxy trusts the
  `X-OpenHost-Is-Owner: true` header the Cloud in a Bottle router stamps on requests
  from an authenticated zone owner (the router strips any client-supplied
  `X-OpenHost-*` headers first, so it cannot be spoofed) and stamps
  `X-Openhost-User: admin` on the upstream request.
- **Username/password fallback for invited readers.** Calibre-Web's normal
  login form at `/login` still works, so you can mint shared accounts for
  family members or co-owners who don't have a Cloud in a Bottle identity. The
  default `admin` password is randomised at first boot — see
  `admin-password.txt` below for recovery.
- **Empty library on first boot.** A blank Calibre library is seeded at
  `/books/metadata.db` so Calibre-Web skips its setup wizard and lands you
  on the (empty) book list immediately. Drop EPUBs and PDFs in via the
  web UI's upload button or by writing them to the persistent volume.
- **Uploads enabled out of the box.** Calibre-Web's "Enable Uploads"
  setting (`config_uploading`) is turned on during init, so the owner can
  add books through the web UI's upload button without first flipping the
  toggle in the admin settings.
- **Persistent state.** Both `app.db` (settings, users, downloads) and
  the Calibre library files live under `OPENHOST_APP_DATA_DIR` and
  survive container rebuilds.

## Persistent layout

Cloud in a Bottle bind-mounts the app's data directory at `/data/app_data/calibre-web`
inside the container. The LSIO image normally writes everything to
`/config`, but `/config` is a `VOLUME` in the upstream Dockerfile —
which Podman would back with an anonymous volume that disappears on
container recreate. To keep state across redeploys, we override the
LSIO `init-calibre-web-config` and `svc-calibre-web` run scripts so
Calibre-Web reads/writes the persistent path directly:

```
/data/app_data/calibre-web/
  config/
    app.db                  Calibre-Web settings + users (SQLite)
    admin-password.txt      Generated random admin password (recovery)
    .openhost-initialised   Sentinel; presence means first-boot done
    client_secrets.json     Stub for Google Drive integration (LSIO)
    .key                    Calibre-Web's encryption key (LSIO)
  books/
    metadata.db             Calibre library catalogue (SQLite)
    <Author>/<Title>/...    Book files added through the web UI
```

The container's own `/config` directory is a tmpfs nobody writes to;
ignore it.

To populate the library by hand, copy a complete Calibre directory tree
into `/data/app_data/calibre-web/books/` (preserving `metadata.db` and
all author/title subdirectories) and reload the app from the Cloud in a Bottle
admin UI.

## Login

- **Owner.** Browse to the app URL while signed in to Cloud in a Bottle as the
  zone owner. The auth-proxy will recognise the router's owner header and
  log you in as `admin` automatically.
- **Other users.** Visit `/login` and enter the username/password of an
  account you've created via the admin UI ("Users" -> "Create New
  User").
- **Recovery.** The randomised admin password is stored in
  `<host>/data/app_data/calibre-web/config/admin-password.txt` (mode 0600,
  owned by the LSIO `abc` user, which defaults to UID 911). If the
  auth-proxy ever gets wedged and you can't log in via SSO, this is
  your escape hatch — read the file from the host (the Cloud in a Bottle shell,
  `cat $OPENHOST_APP_DATA_DIR/config/admin-password.txt`) and use the
  password at `/login`.

## Manifest

| key | value | rationale |
|---|---|---|
| `port` | 8080 | The auth-proxy sidecar's listen port. Calibre-Web itself runs on `127.0.0.1:8083` inside the container. |
| `health_check` | `/robots.txt` | Cheapest 200-OK route Calibre-Web serves to anonymous traffic. |
| `public_paths` | `["/"]` | Calibre-Web mediates auth itself, so the entire app needs to be reachable. |
| `app_data` | `true` | Library files + settings db. |
| `memory_mb` | 768 | Calibre-Web + ImageMagick (cover thumbnails) + Python. |
| `cpu_millicores` | 500 | Spikes during cover thumbnail generation. |

`cloudinabottle.toml` sets `prebuilt_image`, so Cloud in a Bottle pulls our signed prebuilt image (built by CI from each release tag) instead of building the Dockerfile. To fork and modify this app, comment out `prebuilt_image` so your instance builds from source.

## Caveats

- **Library starts empty.** If you have an existing Calibre library on
  another machine, you'll need to copy `metadata.db` and the book
  subdirectories into `/data/app_data/calibre-web/books/` yourself
  (e.g. via scp + the Cloud in a Bottle host shell, or by mounting the volume
  on the host).
- **Ebook conversion is not enabled.** The LSIO image supports a Calibre
  Docker mod (`linuxserver/mods:universal-calibre`) that adds the Calibre
  conversion binaries. We don't pull it in by default — it more than
  doubles the image size. If you need format conversion (EPUB -> MOBI,
  etc.), add `DOCKER_MODS=linuxserver/mods:universal-calibre` to the
  container's environment by editing `Dockerfile` and rebuilding.
- **No OAuth providers.** Calibre-Web's built-in Google/GitHub OAuth
  login is supported by the upstream image but not pre-configured. If
  you need those, configure them through the admin UI; secrets persist
  in `app.db`.
- **Reverse-proxy auto-registration is OFF.** Unlike Forgejo, Calibre-Web
  does not auto-create users for unknown reverse-proxy headers
  (see `cps/usermanagement.py:load_user_from_reverse_proxy_header`).
  The owner is mapped to the pre-existing `admin` account; non-owners
  cannot use SSO and must use a Calibre-Web-local password.

## Reference

- Upstream Docker image: <https://hub.docker.com/r/linuxserver/calibre-web>
- Calibre-Web source: <https://github.com/janeczku/calibre-web>
- Empty-library schema (vendored at `calibre_metadata_sqlite.sql`):
  <https://github.com/kovidgoyal/calibre/blob/master/resources/metadata_sqlite.sql>
