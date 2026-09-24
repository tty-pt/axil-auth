## 1.1.0

- **Renamed `libndc-auth` → `axil-auth`**: the module now integrates with the axil HTTP/server library and its xy hooks (`axil-xy.h`); headers and build targets renamed accordingly.
- **Proper axil XY integration**: hooks forwarded through `on_axil_*` (command/connect/disconnect/tick/parse) so session and ownership logic runs inside axil's request lifecycle. Session hooks ride the xy bus (`get_cookie`, `get_session_user`, `on_auth_confirm_ok`/`on_auth_confirm_error`) and callers dispatch through it.
- **Configurable sessions**: `auth_config` — cookie name (default `QSESSION`), cookie attributes (`Path=/; SameSite=Lax; HttpOnly`), `max_sessions`, and `session_ttl` (default 24h, 0 = no expiry).
- **Group management**: `auth_create_group`, `auth_get_gid`/`auth_get_grpname`, `auth_user_in_group`, `auth_group_add_member`/`auth_group_del_member`/`auth_group_get_members` over POSIX `/etc/group`.
- **Audit hardening**: auth audit fixes and improvements across the session token / registration / login paths.
- Retained feature set: user registration and login with bcrypt password hashing, session tokens via cookie, ownership tracking (chown when root, owner-file when not), configurable via environment (`AXIL_AUTH_GID`, `AXIL_AUTH_GROUP`, `AXIL_AUTH_COOKIE`), plus the `/auth/login`, `/auth/register`, `/auth/api/session`, `/auth/logout`, and `/auth/confirm` endpoints.
- `libqmap` → `libcorm` rename.