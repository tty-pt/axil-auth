## 1.2.0

- **The default shell is `/bin/false`, and that is the enforcement point for
  terminal access — not a convenience default.** Every passwd row this module
  writes now carries `AUTH_DEFAULT_SHELL` (`/bin/false`): downstream code
  (axil-tty) grants a login shell only when the authenticated identity's passwd
  entry names a real shell, so `/bin/sh` here would hand every registered
  account a shell on the server. Do not "fix" this to a login shell. Covered by
  `test.sh` §14 (the registered account's passwd row must name a no-op shell).
- **Registration refuses a name that passwd already owns** — `auth_username_taken()`.
  A name is taken when it is registered here, present in the passwd file this
  module owns, or resolvable by the C library; all three are consulted because
  `load_passwd()` deliberately does not seed the user map from passwd (it only
  patches the uid of names already loaded from shadow), so a passwd-only entry
  was absent from the user map while still being a real account — registering
  over it handed the caller's session that account's uid and shell. `test.sh`
  §15 appends a passwd-only name and asserts registration is refused, and the
  fixture is removed on every exit path so a failed run leaves no account
  behind.
- **`auth_password_matches(username, password)` is exported as an XY hook**, so
  a non-HTTP login surface (a MUCK-style `connect` command) authenticates
  through the same code path instead of asserting an identity. It fails closed
  and the failures are deliberately indistinguishable — unknown user, wrong
  password, unconfirmed account and a no-op stored hash all return 0, so
  callers cannot be used to enumerate accounts; a `*`/`!` stored hash makes
  `crypt()` fail, which is what keeps a locked system account from
  authenticating at all. It returns **non-zero** on success on purpose: the xy
  bus zero-fills a hook result when no module implements it, so a "0 means
  valid" predicate would authenticate every caller the moment axil-auth is
  absent.
- **Login failures answer one uniform message.** The login handler now reports
  unknown user, wrong password and unconfirmed account identically (the
  "not confirmed" case is folded in deliberately) so the form is not an
  account oracle.

## [1.1.0]

- **Renamed `libndc-auth` → `axil-auth`**: the module now integrates with the axil HTTP/server library and its xy hooks (`axil-xy.h`); headers and build targets renamed accordingly.
- **Proper axil XY integration**: hooks forwarded through `on_axil_*` (command/connect/disconnect/tick/parse) so session and ownership logic runs inside axil's request lifecycle. Session hooks ride the xy bus (`get_cookie`, `get_session_user`, `on_auth_confirm_ok`/`on_auth_confirm_error`) and callers dispatch through it.
- **Configurable sessions**: `auth_config` — cookie name (default `QSESSION`), cookie attributes (`Path=/; SameSite=Lax; HttpOnly`), `max_sessions`, and `session_ttl` (default 24h, 0 = no expiry).
- **Group management**: `auth_create_group`, `auth_get_gid`/`auth_get_grpname`, `auth_user_in_group`, `auth_group_add_member`/`auth_group_del_member`/`auth_group_get_members` over POSIX `/etc/group`.
- **Audit hardening**: auth audit fixes and improvements across the session token / registration / login paths.
- Retained feature set: user registration and login with bcrypt password hashing, session tokens via cookie, ownership tracking (chown when root, owner-file when not), configurable via environment (`AXIL_AUTH_GID`, `AXIL_AUTH_GROUP`, `AXIL_AUTH_COOKIE`), plus the `/auth/login`, `/auth/register`, `/auth/api/session`, `/auth/logout`, and `/auth/confirm` endpoints.
- `libqmap` → `libcorm` rename.