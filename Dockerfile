# Pinned LSIO Calibre-Web image. Tag includes both the upstream Calibre-Web
# release (0.6.27) and LSIO's build number (-ls406), so we get reproducible
# rebuilds rather than chasing `latest`. Bump deliberately when needed.
# The digest (multi-arch index) is what is enforced; keep the tag beside it.
FROM lscr.io/linuxserver/calibre-web:0.6.27-ls406@sha256:b206b791d77b731203fb47b5733d055c8d4ebd7c9fa59a4569a5d6a2b3ebda54

# OpenHost bind-mounts the app's persistent data dir at
# /data/app_data/calibre-web inside the container. The LSIO base image
# expects all of Calibre-Web's writable state at /config (declared as
# `VOLUME /config`, which makes the path unwritable during `podman
# build` and forces an anonymous Podman volume on every container
# recreate — exactly what we don't want for a long-lived stateful app).
#
# We can't delete /config in a RUN step because the VOLUME declaration
# overlays it with a tmpfs during the build. We can't remove the
# VOLUME directive from a child image either. The trick: override the
# LSIO init scripts at runtime so Calibre-Web reads/writes
# /data/app_data/calibre-web/config (and /data/app_data/calibre-web/books
# for the library) directly, bypassing /config entirely. The LSIO
# /config tmpfs continues to exist but is never used; everything that
# matters lives under the persistent bind-mount.
#
# This also nicely sidesteps the "/books doesn't exist in the LSIO
# image" issue — we never need that path; the persistent path is
# what calibre-web actually writes to.
#
# See:
#   - root/etc/s6-overlay/s6-rc.d/init-calibre-web-config/run
#     (overrides LSIO's init to use the persistent path)
#   - root/etc/s6-overlay/s6-rc.d/svc-calibre-web/run
#     (overrides LSIO's service start to set CALIBRE_DBPATH there)

# The auth-proxy sidecar is implemented entirely with the Python standard
# library (http.server + http.client), so there are no third-party
# dependencies to install. python3 is already present in the LSIO base
# image (it ships the /lsiopy venv that calibre-web itself runs from, plus
# a system python3), and sqlite3 is present too (LSIO uses it in
# init-calibre-web-config to seed kepubify paths).

# Auth-proxy sidecar. Listens on 0.0.0.0:8080 (the openhost.toml-declared
# port) and forwards to Calibre-Web on 127.0.0.1:8083 with an
# X-Openhost-User: admin header stamped when the OpenHost router marks the
# request as coming from the zone owner (X-OpenHost-Is-Owner: true). See
# auth_proxy.py for the full rationale.
COPY auth_proxy.py /app/auth_proxy.py

# An empty Calibre library schema, taken verbatim from upstream Calibre's
# resources/metadata_sqlite.sql. We materialise an empty metadata.db at
# /books on first boot so calibre-web's "DB Location is not Valid" check
# passes and the library configuration step in the wizard is unnecessary.
COPY calibre_metadata_sqlite.sql /app/calibre_metadata_sqlite.sql

# OpenHost-specific s6 services:
#
#   init-openhost-calibre-web (oneshot)
#       Runs after init-calibre-web-config (which seeds /config/app.db).
#       Creates the empty Calibre library, patches app.db to point at it
#       and to enable reverse-proxy header login, and randomises the
#       admin password on first boot.
#
#   svc-auth-proxy (longrun)
#       Starts after svc-calibre-web is ready. Runs auth_proxy.py on
#       0.0.0.0:8080.
#
# The `root/` tree mirrors LSIO's convention so we can drop in service
# definitions without overlay scripting. Each service has a `type` file,
# a `run` script, and `dependencies.d/<dep>` markers; the
# `user/contents.d/<service>` empty files enable each service in the
# generated s6 bundle.
COPY root/ /

# Ensure all run scripts are executable. COPY preserves bits, but
# CI/git-on-Windows checkouts can strip them, so we re-assert
# explicitly. Every script we ship — both our own services and our
# overrides of LSIO's — needs +x so s6 can exec them.
RUN chmod +x \
        /etc/s6-overlay/s6-rc.d/init-openhost-calibre-web/run \
        /etc/s6-overlay/s6-rc.d/svc-auth-proxy/run \
        /etc/s6-overlay/s6-rc.d/init-calibre-web-config/run \
        /etc/s6-overlay/s6-rc.d/svc-calibre-web/run

# The base image already declares EXPOSE 8083, but we listen externally
# on 8080 (the auth-proxy port). Add 8080 to the exposed-port metadata
# so `docker inspect` lines up with reality.
EXPOSE 8080
