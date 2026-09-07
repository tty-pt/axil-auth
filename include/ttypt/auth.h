#ifndef AXIL_AUTH_H
#define AXIL_AUTH_H

#include <ttypt/xy-mod.h>
#include <stddef.h>

/* ---------------------------------------------------------------------------
 * auth_config — write fields before calling auth_init().
 * All fields have sensible defaults; only override what you need.
 * ------------------------------------------------------------------------- */

struct auth_config {
	const char *cookie_name;   /* default: "QSESSION"                        */
	const char *cookie_attrs;  /* default: "; Path=/; SameSite=Lax; HttpOnly" */
	const char *etc_dir;       /* default: "./etc"                            */
	const char *users_dir;     /* default: "./users"                          */
	const char *home_dir;      /* default: "./home"                           */
	const char *route_prefix;  /* default: "/auth"                            */
	int         www_gid;       /* default: 67                                 */
	unsigned    max_sessions;  /* default: 0xFF                               */
	unsigned    max_users;     /* default: 0xFFFF                             */
	unsigned    session_ttl;   /* default: 86400 (24h); 0 = no expiry        */
};

extern struct auth_config auth_config;

/* Call after writing any auth_config fields.
 * Opens maps, creates directories, loads users, registers HTTP routes. */
void auth_init(void);

/* Look up the uid for a registered username. Returns -1 if not found. */
int auth_get_uid(const char *username);

/* Look up the username for a registered uid. Returns 0 on success, -1 if not found. */
int auth_get_username(int uid, char *out, size_t len);

/* Group management and POSIX /etc/group operations */
int auth_create_group(const char *grp_name);
int auth_get_gid(const char *grp_name);
int auth_get_grpname(int gid, char *out, size_t len);
int auth_user_in_group(const char *username, const char *grp_name);
int auth_group_add_member(const char *grp_name, const char *username);
int auth_group_del_member(const char *grp_name, const char *username);
int auth_group_get_members(const char *grp_name, char *out, size_t len);

/* ---------------------------------------------------------------------------
 * Session hooks — callers dispatch through the xy bus.
 * The implementation TU (AUTH_IMPL) skips these DECL expansions and uses
 * XY_IMPL directly to avoid redefinition.
 * ------------------------------------------------------------------------- */

#ifndef AUTH_IMPL
XY_DECL(int, get_cookie,
	const char *, cookie, char *, token, size_t, len);

XY_DECL(const char *, get_session_user, const char *, token);

XY_DECL(const char *, get_request_user, int, fd);

XY_DECL(int, require_login, int, fd, const char *, username);
#endif /* !AUTH_IMPL */

/* ---------------------------------------------------------------------------
 * Outcome hooks — callers dispatch through the xy bus.  libaxil-auth provides
 * plain-response defaults and falls back to them when no module listens.
 * A site can render its own responses (e.g. an HTML login form) by being the
 * sole listener for a hook: define AUTH_OUTCOME_IMPL before including this
 * header and use XY_IMPL for the hooks it implements, matching these
 * signatures.  The implementation never relies on symbol interposition, so
 * module load order does not matter.
 * ------------------------------------------------------------------------- */

#ifndef AUTH_OUTCOME_IMPL
XY_DECL(int, on_auth_login_ok,
	int, fd, const char *, username, const char *, redirect);

XY_DECL(int, on_auth_login_error,
	int, fd, int, status, const char *, msg, const char *, redirect);

XY_DECL(int, on_auth_register_ok,
	int, fd, const char *, username, const char *, redirect);

XY_DECL(int, on_auth_register_error,
	int, fd, int, status, const char *, msg, const char *, redirect);

XY_DECL(int, on_auth_logout,
	int, fd, const char *, redirect);

XY_DECL(int, on_auth_confirm_ok,
	int, fd, const char *, username);

XY_DECL(int, on_auth_confirm_error,
	int, fd, int, status, const char *, msg);
#endif /* !AUTH_OUTCOME_IMPL */

#endif /* AXIL_AUTH_H */
