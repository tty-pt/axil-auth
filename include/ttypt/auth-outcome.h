#ifndef AXIL_AUTH_OUTCOME_H
#define AXIL_AUTH_OUTCOME_H

/**
 * @file auth-outcome.h
 * @brief XY outcome hooks dispatched by libaxil-auth.
 *
 * Included only by src/libaxil-auth.c (the sole caller).
 * Sites/modules that handle auth outcomes implement these via XY_IMPL
 * and do NOT include this header.
 */

#include <ttypt/xy-mod.h>

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

#endif /* AXIL_AUTH_OUTCOME_H */
