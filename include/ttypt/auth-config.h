#ifndef AXIL_AUTH_CONFIG_H
#define AXIL_AUTH_CONFIG_H

/**
 * @file auth-config.h
 * @brief Direct configuration and standalone prototypes for axil-auth.
 *
 * Used by libaxil-auth internally and standalone unit tests.
 * Never included by site modules or XY bus callers.
 */

#include <stddef.h>

struct auth_config {
	const char *cookie_name;
	const char *cookie_attrs;
	const char *etc_dir;
	const char *users_dir;
	const char *home_dir;
	const char *route_prefix;
	int         www_gid;
	unsigned    max_sessions;
	unsigned    max_users;
	unsigned    session_ttl;
};

extern struct auth_config auth_config;

void auth_init(void);
int auth_username_taken(const char *username);

#endif /* AXIL_AUTH_CONFIG_H */
