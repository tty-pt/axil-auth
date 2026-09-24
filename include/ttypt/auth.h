#ifndef AXIL_AUTH_H
#define AXIL_AUTH_H

/**
 * @file auth.h
 * @brief Sessions, registration and ownership for axil.
 *
 * Mounts cookie-session handling and POSIX user/group maps on an axil
 * server; callers dispatch through the xy bus. Configurable via the
 * auth_config struct below.
 */

#include <ttypt/xy-mod.h>
#include <stddef.h>

/* ---------------------------------------------------------------------------
 * auth_config — write fields before calling auth_init().
 * All fields have sensible defaults; only override what you need.
 * ------------------------------------------------------------------------- */

/**
 * @brief Runtime configuration of the axil-auth module.
 */
struct auth_config {
	/** Session cookie name. Default: "QSESSION". */
	const char *cookie_name;
	/** Cookie attribute string. Default: "; Path=/; SameSite=Lax; HttpOnly". */
	const char *cookie_attrs;
	/** Base directory for config maps. Default: "./etc". */
	const char *etc_dir;
	/** Users directory. Default: "./users". */
	const char *users_dir;
	/** Home directory base. Default: "./home". */
	const char *home_dir;
	/** HTTP route prefix. Default: "/auth". */
	const char *route_prefix;
	/** Web-serving GID for shared files. Default: 67. */
	int         www_gid;
	/** Maximum concurrent sessions. Default: 0xFF. */
	unsigned    max_sessions;
	/** Maximum registered users. Default: 0xFFFF. */
	unsigned    max_users;
	/** Session TTL in seconds. Default: 86400 (24h); 0 = no expiry. */
	unsigned    session_ttl;
};

/** @brief Global auth configuration; write fields before auth_init(). */
extern struct auth_config auth_config;

/**
 * @brief Initialize the auth module.
 *
 * Call after writing any auth_config fields. Opens maps, creates
 * directories, loads users, and registers HTTP routes.
 */
void auth_init(void);

/**
 * @brief Look up the uid for a registered username.
 * @param[in] username Username to resolve.
 * @return Uid, or -1 when not found.
 */
int auth_get_uid(const char *username);

/**
 * @brief Look up the username for a registered uid.
 * @param[in]  uid User id.
 * @param[out] out Destination buffer.
 * @param[in]  len Capacity of out.
 * @return 0 on success, -1 when not found.
 */
int auth_get_username(int uid, char *out, size_t len);

/* Group management and POSIX /etc/group operations */
/**
 * @brief Create a group.
 * @param[in] grp_name Group name.
 * @return 0 on success, -1 on failure.
 */
int auth_create_group(const char *grp_name);

/**
 * @brief Look up the gid for a group name.
 * @param[in] grp_name Group name.
 * @return Gid, or -1 when not found.
 */
int auth_get_gid(const char *grp_name);

/**
 * @brief Look up the group name for a gid.
 * @param[in]  gid Group id.
 * @param[out] out Destination buffer.
 * @param[in]  len Capacity of out.
 * @return 0 on success, -1 when not found.
 */
int auth_get_grpname(int gid, char *out, size_t len);

/**
 * @brief Whether a user belongs to a group.
 * @param[in] username Username.
 * @param[in] grp_name Group name.
 * @return Non-zero when the user is a member.
 */
int auth_user_in_group(const char *username, const char *grp_name);

/**
 * @brief Add a user to a group.
 * @param[in] grp_name Group name.
 * @param[in] username Username.
 * @return 0 on success, -1 on failure.
 */
int auth_group_add_member(const char *grp_name, const char *username);

/**
 * @brief Remove a user from a group.
 * @param[in] grp_name Group name.
 * @param[in] username Username.
 * @return 0 on success, -1 on failure.
 */
int auth_group_del_member(const char *grp_name, const char *username);

/**
 * @brief List group members as a comma-separated string.
 * @param[in]  grp_name Group name.
 * @param[out] out      Destination buffer.
 * @param[in]  len      Capacity of out.
 * @return 0 on success, -1 on failure.
 */
int auth_group_get_members(const char *grp_name, char *out, size_t len);

/* ---------------------------------------------------------------------------
 * Session hooks — callers dispatch through the xy bus.
 * The implementation TU (AUTH_IMPL) skips these DECL expansions and uses
 * XY_IMPL directly to avoid redefinition.
 * ------------------------------------------------------------------------- */

#ifndef AUTH_IMPL
/** @brief Extract and validate a session token from a raw cookie value. */
XY_DECL(int, get_cookie,
	const char *, cookie, char *, token, size_t, len);

/** @brief Resolve the username owning a session token. */
XY_DECL(const char *, get_session_user, const char *, token);

/** @brief Resolve the username of the session on a client fd. */
XY_DECL(const char *, get_request_user, int, fd);

/** @brief Require a login, emitting the login challenge when absent. */
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
/** @brief Emit the login-success response for a client fd. */
XY_DECL(int, on_auth_login_ok,
	int, fd, const char *, username, const char *, redirect);

/** @brief Emit the login-error response for a client fd. */
XY_DECL(int, on_auth_login_error,
	int, fd, int, status, const char *, msg, const char *, redirect);

/** @brief Emit the registration-success response for a client fd. */
XY_DECL(int, on_auth_register_ok,
	int, fd, const char *, username, const char *, redirect);

/** @brief Emit the registration-error response for a client fd. */
XY_DECL(int, on_auth_register_error,
	int, fd, int, status, const char *, msg, const char *, redirect);

/** @brief Emit the logout response for a client fd. */
XY_DECL(int, on_auth_logout,
	int, fd, const char *, redirect);

/** @brief Emit the confirmation-success response for a client fd. */
XY_DECL(int, on_auth_confirm_ok,
	int, fd, const char *, username);

/** @brief Emit the confirmation-error response for a client fd. */
XY_DECL(int, on_auth_confirm_error,
	int, fd, int, status, const char *, msg);
#endif /* !AUTH_OUTCOME_IMPL */

#endif /* AXIL_AUTH_H */
