#ifndef AXIL_AUTH_H
#define AXIL_AUTH_H

/**
 * @file auth.h
 * @brief Sessions, registration, ownership, and POSIX user/group operations for axil.
 *
 * Caller-facing XY hook declarations.
 * Implementers must NOT include this header. Direct configuration lives in
 * auth-config.h and internal outcome dispatches live in auth-outcome.h.
 */

#include <ttypt/xy-mod.h>
#include <stddef.h>

/* ---------------------------------------------------------------------------
 * Session hooks — callers dispatch through the xy bus.
 * ------------------------------------------------------------------------- */

/** @brief Extract and validate a session token from a raw cookie value. */
XY_DECL(int, get_cookie,
	const char *, cookie, char *, token, size_t, len);

/** @brief Resolve the username owning a session token. */
XY_DECL(const char *, get_session_user, const char *, token);

/** @brief Resolve the username of the session on a client fd. */
XY_DECL(const char *, get_request_user, int, fd);

/**
 * @brief Check a username/password pair against the stored credential.
 *
 * Non-zero on success, 0 on failure or absent module.
 */
XY_DECL(int, auth_password_matches,
	const char *, username,
	const char *, password);

/** @brief Require a login, emitting the login challenge when absent. */
XY_DECL(int, require_login, int, fd, const char *, username);

/* ---------------------------------------------------------------------------
 * Management and POSIX user/group hooks — callers dispatch through xy bus.
 * ------------------------------------------------------------------------- */

XY_DECL(int, auth_get_uid, const char *, username);

XY_DECL(int, auth_get_username, int, uid, char *, out, size_t, len);

XY_DECL(int, auth_username_taken, const char *, username);

XY_DECL(int, auth_create_group, const char *, grp_name);

XY_DECL(int, auth_get_gid, const char *, grp_name);

XY_DECL(int, auth_get_grpname, int, gid, char *, out, size_t, len);

XY_DECL(int, auth_user_in_group, const char *, username, const char *, grp_name);

XY_DECL(int, auth_group_add_member, const char *, grp_name, const char *, username);

XY_DECL(int, auth_group_del_member, const char *, grp_name, const char *, username);

XY_DECL(int, auth_group_get_members, const char *, grp_name, char *, out, size_t, len);

XY_DECL(int, auth_www_gid, void);

#endif /* AXIL_AUTH_H */
