#ifndef NDC_AUTH_H
#define NDC_AUTH_H

#include <ttypt/ndx-mod.h>
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
};

extern struct auth_config auth_config;

/* Call after writing any auth_config fields.
 * Opens maps, creates directories, loads users, registers HTTP routes. */
void auth_init(void);

/* Look up the uid for a registered username. Returns -1 if not found. */
int auth_get_uid(const char *username);

/* ---------------------------------------------------------------------------
 * Session hooks — callers dispatch through the ndx bus.
 * The implementation TU (AUTH_IMPL) skips these DECL expansions and uses
 * NDX_LISTENER directly to avoid redefinition.
 * ------------------------------------------------------------------------- */

#ifndef AUTH_IMPL
NDX_HOOK_DECL(int, get_cookie,
	const char *, cookie, char *, token, size_t, len);

NDX_HOOK_DECL(const char *, get_session_user, const char *, token);

NDX_HOOK_DECL(const char *, get_request_user, int, fd);

NDX_HOOK_DECL(int, require_login, int, fd, const char *, username);
#endif /* !AUTH_IMPL */

/* ---------------------------------------------------------------------------
 * Outcome hooks — plain weak symbols in libndc-auth.so; site overrides by
 * providing a strong definition with the same signature.
 * ------------------------------------------------------------------------- */
int on_auth_login_ok(int fd, const char *username, const char *redirect);
int on_auth_login_error(int fd, int status, const char *msg, const char *redirect);
int on_auth_register_ok(int fd, const char *username, const char *redirect);
int on_auth_register_error(int fd, int status, const char *msg, const char *redirect);
int on_auth_logout(int fd, const char *redirect);
int on_auth_confirm_ok(int fd, const char *username);
int on_auth_confirm_error(int fd, int status, const char *msg);

#endif /* NDC_AUTH_H */
