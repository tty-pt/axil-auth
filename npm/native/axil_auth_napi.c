#include <node_api.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ttypt/auth-config.h>

/* Direct C exports from libaxil-auth */
extern int get_cookie(const char *cookie, char *token, size_t len);
extern const char *get_session_user(const char *token);
extern int auth_password_matches(const char *username, const char *password);
extern int auth_www_gid(void);

static char s_cookie_name[64];
static char s_cookie_attrs[256];
static char s_etc_dir[256];
static char s_users_dir[256];
static char s_home_dir[256];
static char s_route_prefix[128];

static bool extract_utf8_buf(napi_env env, napi_value val, char *buf, size_t cap) {
	if (!buf || cap == 0)
		return false;
	size_t len = 0;
	if (napi_get_value_string_utf8(env, val, buf, cap, &len) != napi_ok)
		return false;
	buf[cap - 1] = '\0';
	return true;
}

/* hasNativeModule() -> boolean (anchors DT_NEEDED for libaxil-auth) */
static napi_value AuthHasNativeModule(napi_env env, napi_callback_info info) {
	(void)info;
	int gid = auth_www_gid();
	napi_value res;
	napi_get_boolean(env, gid >= 0, &res);
	return res;
}

/* getConfig() -> object */
static napi_value AuthGetConfig(napi_env env, napi_callback_info info) {
	(void)info;
	napi_value obj, val;
	napi_create_object(env, &obj);

	napi_create_string_utf8(env, auth_config.cookie_name ? auth_config.cookie_name : "", NAPI_AUTO_LENGTH, &val);
	napi_set_named_property(env, obj, "cookieName", val);

	napi_create_string_utf8(env, auth_config.cookie_attrs ? auth_config.cookie_attrs : "", NAPI_AUTO_LENGTH, &val);
	napi_set_named_property(env, obj, "cookieAttrs", val);

	napi_create_string_utf8(env, auth_config.etc_dir ? auth_config.etc_dir : "", NAPI_AUTO_LENGTH, &val);
	napi_set_named_property(env, obj, "etcDir", val);

	napi_create_string_utf8(env, auth_config.users_dir ? auth_config.users_dir : "", NAPI_AUTO_LENGTH, &val);
	napi_set_named_property(env, obj, "usersDir", val);

	napi_create_string_utf8(env, auth_config.home_dir ? auth_config.home_dir : "", NAPI_AUTO_LENGTH, &val);
	napi_set_named_property(env, obj, "homeDir", val);

	napi_create_string_utf8(env, auth_config.route_prefix ? auth_config.route_prefix : "", NAPI_AUTO_LENGTH, &val);
	napi_set_named_property(env, obj, "routePrefix", val);

	napi_create_int32(env, auth_config.www_gid, &val);
	napi_set_named_property(env, obj, "wwwGid", val);

	napi_create_uint32(env, auth_config.max_sessions, &val);
	napi_set_named_property(env, obj, "maxSessions", val);

	napi_create_uint32(env, auth_config.max_users, &val);
	napi_set_named_property(env, obj, "maxUsers", val);

	napi_create_uint32(env, auth_config.session_ttl, &val);
	napi_set_named_property(env, obj, "sessionTtl", val);

	return obj;
}

/* configure(options) -> boolean */
static napi_value AuthConfigure(napi_env env, napi_callback_info info) {
	size_t argc = 1;
	napi_value args[1];
	napi_get_cb_info(env, info, &argc, args, NULL, NULL);
	if (argc < 1) {
		napi_value res;
		napi_get_boolean(env, false, &res);
		return res;
	}

	napi_value v;
	bool has = false;

	if (napi_has_named_property(env, args[0], "cookieName", &has) == napi_ok && has) {
		napi_get_named_property(env, args[0], "cookieName", &v);
		if (extract_utf8_buf(env, v, s_cookie_name, sizeof(s_cookie_name)))
			auth_config.cookie_name = s_cookie_name;
	}
	if (napi_has_named_property(env, args[0], "cookieAttrs", &has) == napi_ok && has) {
		napi_get_named_property(env, args[0], "cookieAttrs", &v);
		if (extract_utf8_buf(env, v, s_cookie_attrs, sizeof(s_cookie_attrs)))
			auth_config.cookie_attrs = s_cookie_attrs;
	}
	if (napi_has_named_property(env, args[0], "etcDir", &has) == napi_ok && has) {
		napi_get_named_property(env, args[0], "etcDir", &v);
		if (extract_utf8_buf(env, v, s_etc_dir, sizeof(s_etc_dir)))
			auth_config.etc_dir = s_etc_dir;
	}
	if (napi_has_named_property(env, args[0], "usersDir", &has) == napi_ok && has) {
		napi_get_named_property(env, args[0], "usersDir", &v);
		if (extract_utf8_buf(env, v, s_users_dir, sizeof(s_users_dir)))
			auth_config.users_dir = s_users_dir;
	}
	if (napi_has_named_property(env, args[0], "homeDir", &has) == napi_ok && has) {
		napi_get_named_property(env, args[0], "homeDir", &v);
		if (extract_utf8_buf(env, v, s_home_dir, sizeof(s_home_dir)))
			auth_config.home_dir = s_home_dir;
	}
	if (napi_has_named_property(env, args[0], "routePrefix", &has) == napi_ok && has) {
		napi_get_named_property(env, args[0], "routePrefix", &v);
		if (extract_utf8_buf(env, v, s_route_prefix, sizeof(s_route_prefix)))
			auth_config.route_prefix = s_route_prefix;
	}
	if (napi_has_named_property(env, args[0], "wwwGid", &has) == napi_ok && has) {
		int32_t gid = 0;
		napi_get_named_property(env, args[0], "wwwGid", &v);
		if (napi_get_value_int32(env, v, &gid) == napi_ok)
			auth_config.www_gid = (int)gid;
	}
	if (napi_has_named_property(env, args[0], "maxSessions", &has) == napi_ok && has) {
		uint32_t max_s = 0;
		napi_get_named_property(env, args[0], "maxSessions", &v);
		if (napi_get_value_uint32(env, v, &max_s) == napi_ok)
			auth_config.max_sessions = (unsigned)max_s;
	}
	if (napi_has_named_property(env, args[0], "maxUsers", &has) == napi_ok && has) {
		uint32_t max_u = 0;
		napi_get_named_property(env, args[0], "maxUsers", &v);
		if (napi_get_value_uint32(env, v, &max_u) == napi_ok)
			auth_config.max_users = (unsigned)max_u;
	}
	if (napi_has_named_property(env, args[0], "sessionTtl", &has) == napi_ok && has) {
		uint32_t ttl = 0;
		napi_get_named_property(env, args[0], "sessionTtl", &v);
		if (napi_get_value_uint32(env, v, &ttl) == napi_ok)
			auth_config.session_ttl = (unsigned)ttl;
	}

	napi_value res;
	napi_get_boolean(env, true, &res);
	return res;
}

/* init() -> boolean */
static napi_value AuthInit(napi_env env, napi_callback_info info) {
	(void)info;
	auth_init();
	napi_value res;
	napi_get_boolean(env, true, &res);
	return res;
}

/* extractCookie(cookieHeader) -> string | null */
static napi_value AuthExtractCookie(napi_env env, napi_callback_info info) {
	size_t argc = 1;
	napi_value args[1];
	napi_get_cb_info(env, info, &argc, args, NULL, NULL);
	if (argc < 1) {
		napi_value null_val;
		napi_get_null(env, &null_val);
		return null_val;
	}

	char cookie[1024] = {0};
	if (!extract_utf8_buf(env, args[0], cookie, sizeof(cookie))) {
		napi_value null_val;
		napi_get_null(env, &null_val);
		return null_val;
	}

	char token[256] = {0};
	if (get_cookie(cookie, token, sizeof(token)) != 0 || !token[0]) {
		napi_value null_val;
		napi_get_null(env, &null_val);
		return null_val;
	}

	napi_value res;
	napi_create_string_utf8(env, token, NAPI_AUTO_LENGTH, &res);
	return res;
}

/* getSessionUser(token) -> string | null */
static napi_value AuthGetSessionUser(napi_env env, napi_callback_info info) {
	size_t argc = 1;
	napi_value args[1];
	napi_get_cb_info(env, info, &argc, args, NULL, NULL);
	if (argc < 1) {
		napi_value null_val;
		napi_get_null(env, &null_val);
		return null_val;
	}

	char token[256] = {0};
	if (!extract_utf8_buf(env, args[0], token, sizeof(token)) || !token[0]) {
		napi_value null_val;
		napi_get_null(env, &null_val);
		return null_val;
	}

	const char *user = get_session_user(token);
	if (!user || !user[0]) {
		napi_value null_val;
		napi_get_null(env, &null_val);
		return null_val;
	}

	napi_value res;
	napi_create_string_utf8(env, user, NAPI_AUTO_LENGTH, &res);
	return res;
}

/* verifyPassword(username, password) -> boolean */
static napi_value AuthVerifyPassword(napi_env env, napi_callback_info info) {
	size_t argc = 2;
	napi_value args[2];
	napi_get_cb_info(env, info, &argc, args, NULL, NULL);
	if (argc < 2) {
		napi_value res;
		napi_get_boolean(env, false, &res);
		return res;
	}

	char username[128] = {0};
	char password[256] = {0};
	if (!extract_utf8_buf(env, args[0], username, sizeof(username)) ||
	    !extract_utf8_buf(env, args[1], password, sizeof(password))) {
		napi_value res;
		napi_get_boolean(env, false, &res);
		return res;
	}

	int ok = auth_password_matches(username, password);
	napi_value res;
	napi_get_boolean(env, ok != 0, &res);
	return res;
}

/* usernameTaken(username) -> boolean */
static napi_value AuthUsernameTaken(napi_env env, napi_callback_info info) {
	size_t argc = 1;
	napi_value args[1];
	napi_get_cb_info(env, info, &argc, args, NULL, NULL);
	if (argc < 1) {
		napi_value res;
		napi_get_boolean(env, false, &res);
		return res;
	}

	char username[128] = {0};
	if (!extract_utf8_buf(env, args[0], username, sizeof(username)) || !username[0]) {
		napi_value res;
		napi_get_boolean(env, false, &res);
		return res;
	}

	int taken = auth_username_taken(username);
	napi_value res;
	napi_get_boolean(env, taken != 0, &res);
	return res;
}

static napi_value Init(napi_env env, napi_value exports) {
	napi_property_descriptor props[] = {
		{ "hasNativeModule", NULL, AuthHasNativeModule, NULL, NULL, NULL, napi_default, NULL },
		{ "getConfig", NULL, AuthGetConfig, NULL, NULL, NULL, napi_default, NULL },
		{ "configure", NULL, AuthConfigure, NULL, NULL, NULL, napi_default, NULL },
		{ "init", NULL, AuthInit, NULL, NULL, NULL, napi_default, NULL },
		{ "extractCookie", NULL, AuthExtractCookie, NULL, NULL, NULL, napi_default, NULL },
		{ "getSessionUser", NULL, AuthGetSessionUser, NULL, NULL, NULL, napi_default, NULL },
		{ "verifyPassword", NULL, AuthVerifyPassword, NULL, NULL, NULL, napi_default, NULL },
		{ "usernameTaken", NULL, AuthUsernameTaken, NULL, NULL, NULL, napi_default, NULL },
	};
	napi_define_properties(env, exports, sizeof(props) / sizeof(props[0]), props);
	return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
