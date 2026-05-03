#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1

#include <ttypt/ndx-mod.h>
#include <ttypt/ndc.h>
#include <ttypt/qmap.h>
#include <ttypt/ndc-ndx.h>

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>

#ifndef __OpenBSD__
#include <crypt.h>
#endif

#define AUTH_IMPL
#include "./../include/ttypt/auth.h"
#undef AUTH_IMPL

/* ------------------------------------------------------------------ */
/* Config — defaults; site writes fields before calling auth_init()   */
/* ------------------------------------------------------------------ */

struct auth_config auth_config = {
	.cookie_name  = "QSESSION",
	.cookie_attrs = "; Path=/; SameSite=Lax; HttpOnly",
	.etc_dir      = "./etc",
	.users_dir    = "./users",
	.home_dir     = "./home",
	.route_prefix = "/auth",
	.www_gid      = 67,
	.max_sessions = 0xFF,
	.max_users    = 0xFFFF,
};

/* ------------------------------------------------------------------ */
/* Internal state                                                      */
/* ------------------------------------------------------------------ */

static unsigned users_map;
static unsigned sessions_map;

struct user {
	char active;
	int  uid;
	char hash[64];
};

/* Outcome hook defaults
 * (weak — site overrides by redefining)
 */
WEAK int
on_auth_login_ok(int fd, const char *username, const char *redirect)
{
	(void)username;
	return ndc_redirect(fd, (redirect && *redirect) ? redirect : "/");
}

WEAK int
on_auth_login_error(int fd, int status, const char *msg, const char *redirect)
{
	(void)redirect;
	return ndc_respond_plain(fd, status, msg);
}

WEAK int
on_auth_register_ok(int fd, const char *username, const char *redirect)
{
	(void)username;
	return ndc_redirect(fd, (redirect && *redirect) ? redirect : "/");
}

WEAK int
on_auth_register_error(int fd, int status, const char *msg, const char *redirect)
{
	(void)redirect;
	return ndc_respond_plain(fd, status, msg);
}

WEAK int
on_auth_logout(int fd, const char *redirect)
{
	return ndc_redirect(fd, (redirect && *redirect) ? redirect : "/");
}

WEAK int
on_auth_confirm_ok(int fd, const char *username)
{
	(void)username;
	return ndc_redirect(fd, "/");
}

WEAK int
on_auth_confirm_error(int fd, int status, const char *msg)
{
	return ndc_respond_plain(fd, status, msg);
}

/* Helpers */

static int
skip_confirm_required(void)
{
	const char *env = getenv("AUTH_SKIP_CONFIRM");
	if (!env || !*env)
		return 0;
	return strcmp(env, "0")     != 0
	    && strcmp(env, "false") != 0
	    && strcmp(env, "FALSE") != 0
	    && strcmp(env, "no")    != 0
	    && strcmp(env, "NO")    != 0;
}

static const char *
redirect_target(const char *path)
{
	return (path && *path) ? path : "/";
}

static void
strip_trailing_nl(char *s)
{
	size_t l = strlen(s);
	while (l > 0 && (s[l-1] == '\n' || s[l-1] == '\r'))
		s[--l] = '\0';
}

/* Path helpers */

static void
shadow_path(char *buf, size_t len)
{
#ifdef __OpenBSD__
	snprintf(buf, len, "%s/master.passwd", auth_config.etc_dir);
#else
	snprintf(buf, len, "%s/shadow", auth_config.etc_dir);
#endif
}

static void
passwd_path(char *buf, size_t len)
{
	snprintf(buf, len, "%s/passwd", auth_config.etc_dir);
}

/* UID allocation */

static int
next_uid(void)
{
	char path[512];
	passwd_path(path, sizeof(path));
	FILE *f = fopen(path, "r");
	int max_uid = 999;
	if (!f)
		return 1000;
	char line[512];
	while (fgets(line, sizeof(line), f)) {
		char *p = line;
		int field = 0;
		while (*p && field < 2) {
			if (*p == ':') field++;
			p++;
		}
		if (field == 2) {
			int uid = (int)strtol(p, NULL, 10);
			if (uid > max_uid)
				max_uid = uid;
		}
	}
	fclose(f);
	return max_uid + 1;
}

/* Session helpers */

NDX_LISTENER(const char *, get_session_user, const char *, token)
{
	if (!token || !*token)
		return NULL;
	return qmap_get(sessions_map, token);
}

NDX_LISTENER(int, get_cookie,
	const char *, cookie, char *, token, size_t, len)
{
	const char *p;
	size_t nlen;

	token[0] = '\0';

	if (!cookie || !*cookie)
		return -1;

	nlen = strlen(auth_config.cookie_name);
	p = cookie;

	while (*p) {
		while (*p == ' ' || *p == '\t') p++;

		if (strncmp(p, auth_config.cookie_name, nlen) == 0
		    && p[nlen] == '=') {
			p += nlen + 1;
			/* cookies are separated by "; " */
			const char *end = p;
			while (*end && *end != ';') end++;
			/* trim trailing whitespace */
			while (end > p && end[-1] == ' ') end--;
			size_t tlen = (size_t)(end - p);
			if (tlen >= len) tlen = len - 1;
			strncpy(token, p, tlen);
			token[tlen] = '\0';
			return 0;
		}

		/* advance past this cookie */
		while (*p && *p != ';') p++;
		if (*p == ';') p++;
	}

	return -1;
}

NDX_LISTENER(const char *, get_request_user, int, fd)
{
	char cookie[256] = {0};
	char token[128]  = {0};
	ndc_env_get(fd, cookie, "HTTP_COOKIE");
	get_cookie(cookie, token, sizeof(token));
	return get_session_user(token);
}

NDX_LISTENER(int, require_login, int, fd, const char *, username)
{
	if (username && *username)
		return 0;
	return on_auth_login_error(fd, 401, "Login required", "");
}

/* Token generation */

static void
generate_token(char *buf, size_t len)
{
	FILE *f = fopen("/dev/urandom", "r");
	if (!f) {
		perror("ndc-auth: generate_token: /dev/urandom");
		abort();
	}
	for (size_t i = 0; i + 1 < len; ) {
		int c = fgetc(f);
		if (c == EOF) break;
		buf[i++] = "0123456789abcdef"[(c >> 4) & 15];
		buf[i++] = "0123456789abcdef"[c & 15];
	}
	buf[len - 1] = '\0';
	fclose(f);
}

/* Password hashing */

static void
generate_bcrypt_salt(char *buf, size_t len)
{
	static const char b64[] =
		"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
		"0123456789";
	unsigned char rnd[16];
	int cost = 12;
	const char *cost_env = getenv("AUTH_BCRYPT_COST");
	if (cost_env && *cost_env) {
		int v = atoi(cost_env);
		if (v >= 4 && v <= 31) cost = v;
	}

	FILE *f = fopen("/dev/urandom", "r");
	if (f) {
		if (fread(rnd, 1, sizeof(rnd), f) != sizeof(rnd))
			memset(rnd, 0, sizeof(rnd));
		fclose(f);
	} else {
		unsigned long long t = (unsigned long long)time(NULL);
		for (int i = 0; i < 16; i++)
			rnd[i] = (unsigned char)(t >> (i % 8));
	}

	char salt[23];
	unsigned int bbuf = 0;
	int bits_left = 0, out = 0;
	for (int i = 0; i < 16 && out < 22; i++) {
		bbuf = (bbuf << 8) | rnd[i];
		bits_left += 8;
		while (bits_left >= 6 && out < 22) {
			bits_left -= 6;
			salt[out++] = b64[(bbuf >> bits_left) & 0x3f];
		}
	}
	if (out < 22 && bits_left > 0)
		salt[out++] = b64[(bbuf << (6 - bits_left)) & 0x3f];
	salt[22] = '\0';

	snprintf(buf, len, "$2b$%02d$%s", cost, salt);
}

/* Shadow / passwd / group file I/O */

static int
shadow_append(const char *username, const char *hash, int uid)
{
	char path[512];
	shadow_path(path, sizeof(path));
	FILE *f = fopen(path, "a");
	if (!f) return -1;
#ifdef __OpenBSD__
	fprintf(f, "%s:%s:%d:%d::0:0:%s:%s/%s:/bin/sh\n",
		username, hash, uid, auth_config.www_gid,
		username, auth_config.home_dir, username);
#else
	long lastchg = (long)(time(NULL) / 86400);
	fprintf(f, "%s:%s:%ld:0:99999:7:::\n", username, hash, lastchg);
	(void)uid;
#endif
	fclose(f);
	return 0;
}

static int
passwd_append(const char *username, int uid)
{
	char path[512];
	passwd_path(path, sizeof(path));
	FILE *f = fopen(path, "a");
	if (!f) return -1;
#ifdef __OpenBSD__
	fprintf(f, "%s:*:%d:%d::0:0:%s:%s/%s:/bin/sh\n",
		username, uid, auth_config.www_gid,
		username, auth_config.home_dir, username);
#else
	fprintf(f, "%s:x:%d:%d::%s/%s:/bin/sh\n",
		username, uid, auth_config.www_gid,
		auth_config.home_dir, username);
#endif
	fclose(f);
	return 0;
}

static int
group_append(const char *username)
{
	char grp_path[512], tmp_path[520];
	snprintf(grp_path, sizeof(grp_path), "%s/group",     auth_config.etc_dir);
	snprintf(tmp_path, sizeof(tmp_path), "%s/group.tmp",  auth_config.etc_dir);

	FILE *in  = fopen(grp_path, "r");
	FILE *out = fopen(tmp_path, "w");
	if (!out) { if (in) fclose(in); return -1; }

	if (in) {
		char line[4096];
		while (fgets(line, sizeof(line), in)) {
			strip_trailing_nl(line);
			if (strncmp(line, "www:", 4) == 0)
				fprintf(out, "%s,%s\n", line, username);
			else
				fprintf(out, "%s\n", line);
		}
		fclose(in);
	}
	fclose(out);
	rename(tmp_path, grp_path);
	return 0;
}

#ifdef __OpenBSD__
static void
run_pwd_mkdb(void)
{
	char master[512];
	snprintf(master, sizeof(master), "%s/master.passwd", auth_config.etc_dir);
	pid_t pid = fork();
	if (pid == 0) {
		char *argv[] = {
			"pwd_mkdb", "-d", (char *)auth_config.etc_dir,
			master, NULL
		};
		execv("/usr/sbin/pwd_mkdb", argv);
		_exit(1);
	} else if (pid > 0) {
		waitpid(pid, NULL, 0);
	}
}
#endif

static int
shadow_update(const char *username, const char *new_hash)
{
	char path[512], tmp[520];
	shadow_path(path, sizeof(path));
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);

	FILE *in  = fopen(path, "r");
	FILE *out = fopen(tmp, "w");
	if (!out) return -1;

	if (in) {
		char line[512];
		while (fgets(line, sizeof(line), in)) {
			strip_trailing_nl(line);
			char *colon1 = strchr(line, ':');
			if (!colon1) { fprintf(out, "%s\n", line); continue; }
			size_t ulen = (size_t)(colon1 - line);
			if (ulen == strlen(username) &&
			    strncmp(line, username, ulen) == 0) {
				char *colon2 = strchr(colon1 + 1, ':');
				if (colon2)
					fprintf(out, "%s:%s%s\n", username, new_hash, colon2);
				else
					fprintf(out, "%s:%s\n", username, new_hash);
				continue;
			}
			fprintf(out, "%s\n", line);
		}
		fclose(in);
	}
	fclose(out);
	rename(tmp, path);
	return 0;
}

/* Startup: load users from shadow + passwd */

static void
load_shadow(void)
{
	char path[512];
	shadow_path(path, sizeof(path));
	FILE *f = fopen(path, "r");
	if (!f) return;

	char line[512];
	while (fgets(line, sizeof(line), f)) {
		strip_trailing_nl(line);

		char *colon1 = strchr(line, ':');
		if (!colon1) continue;
		*colon1 = '\0';
		const char *uname = line;
		if (!*uname) continue;

		char *hash_start = colon1 + 1;
		char *colon2 = strchr(hash_start, ':');
		size_t hash_len = colon2
			? (size_t)(colon2 - hash_start)
			: strlen(hash_start);
		if (!hash_len) continue;

		struct user u = {0};
		if (hash_len >= sizeof(u.hash))
			hash_len = sizeof(u.hash) - 1;
		memcpy(u.hash, hash_start, hash_len);
		u.hash[hash_len] = '\0';

#ifdef __OpenBSD__
		if (colon2) {
			char *colon3 = strchr(colon2 + 1, ':');
			size_t uid_len = colon3
				? (size_t)(colon3 - (colon2 + 1))
				: strlen(colon2 + 1);
			char uid_str[16] = {0};
			if (uid_len < sizeof(uid_str)) {
				memcpy(uid_str, colon2 + 1, uid_len);
				u.uid = (int)strtol(uid_str, NULL, 10);
			}
		}
#endif

		char rcode_path[1024];
		snprintf(rcode_path, sizeof(rcode_path),
			"%s/%s/rcode", auth_config.users_dir, uname);
		struct stat st;
		u.active = (stat(rcode_path, &st) != 0) ? 1 : 0;

		qmap_put(users_map, uname, &u);
	}
	fclose(f);
}

#ifndef __OpenBSD__
static void
load_passwd(void)
{
	char path[512];
	passwd_path(path, sizeof(path));
	FILE *f = fopen(path, "r");
	if (!f) return;

	char line[512];
	while (fgets(line, sizeof(line), f)) {
		strip_trailing_nl(line);
		char *c1 = strchr(line, ':'); if (!c1) continue;
		*c1 = '\0';
		const char *uname = line;
		char *c2 = strchr(c1 + 1, ':'); if (!c2) continue;
		char *c3 = strchr(c2 + 1, ':');
		size_t uid_len = c3
			? (size_t)(c3 - (c2 + 1))
			: strlen(c2 + 1);
		char uid_str[16] = {0};
		if (!uid_len || uid_len >= sizeof(uid_str)) continue;
		memcpy(uid_str, c2 + 1, uid_len);
		int uid = (int)strtol(uid_str, NULL, 10);
		struct user *u = (struct user *)qmap_get(users_map, uname);
		if (u) u->uid = uid;
	}
	fclose(f);
}
#endif

/* HTTP handlers */

static int
handle_session(int fd, char *body)
{
	(void)body;
	char cookie[256] = {0}, token[128] = {0};
	ndc_env_get(fd, cookie, "HTTP_COOKIE");
	get_cookie(cookie, token, sizeof(token));
	const char *username = qmap_get(sessions_map, token);
	ndc_header_set(fd, "Content-Type", "text/plain");
	ndc_respond(fd, 200, username ? username : "");
	return 1;
}

static int
login_as(int fd, const char *username, const char *target)
{
	char token[128], cookie[256];
	generate_token(token, sizeof(token));
	qmap_put(sessions_map, token, username);
	snprintf(cookie, sizeof(cookie), "%s=%s%s",
		auth_config.cookie_name, token, auth_config.cookie_attrs);
	ndc_header_set(fd, "Set-Cookie", cookie);
	return on_auth_login_ok(fd, username, target);
}

static int
handle_login(int fd, char *body)
{
	char username[64], password[64], redirect_path[256];

	ndc_query_parse(body);
	ndc_query_param("username", username,      sizeof(username));
	ndc_query_param("password", password,      sizeof(password));
	ndc_query_param("ret",      redirect_path, sizeof(redirect_path));

	const char *ret = redirect_target(redirect_path);

	if (!*username || !*password)
		return on_auth_login_error(fd, 400, "Missing username or password", ret);

	struct user *user = (struct user *)qmap_get(users_map, username);
	if (!user)
		return on_auth_login_error(fd, 401, "Invalid credentials", ret);

	char *hash = crypt(password, user->hash);
	if (!hash || strcmp(hash, user->hash) != 0)
		return on_auth_login_error(fd, 401, "Invalid credentials", ret);

	if (!user->active)
		return on_auth_login_error(fd, 401, "Account not confirmed", ret);

	return login_as(fd, username, ret);
}

static int
handle_logout(int fd, char *body)
{
	(void)body;
	char cookie[256] = {0}, token[128] = {0}, clear[256];
	char ret[256] = {0};

	ndc_env_get(fd, cookie, "HTTP_COOKIE");
	get_cookie(cookie, token, sizeof(token));
	if (*token)
		qmap_del(sessions_map, token);

	snprintf(clear, sizeof(clear), "%s=; Path=/; Max-Age=0%s",
		auth_config.cookie_name, auth_config.cookie_attrs);
	ndc_header_set(fd, "Set-Cookie", clear);

	/* allow ?ret= on logout too */
	char query[256] = {0};
	ndc_env_get(fd, query, "QUERY_STRING");
	ndc_query_parse(query);
	ndc_query_param("ret", ret, sizeof(ret));

	return on_auth_logout(fd, redirect_target(ret));
}

static int
valid_username_char(char c)
{
	return (c >= 'a' && c <= 'z')
	    || (c >= 'A' && c <= 'Z')
	    || (c >= '0' && c <= '9')
	    || c == '_' || c == '-';
}

static int
handle_register(int fd, char *body)
{
	char username[64], password[64], password_confirm[64], email[128];
	char salt[64], redirect_path[256] = {0};
	char user_dir[1024], rcode_path[1088], rcode[128];
	const char *target;
	int skip_confirm;
	struct user user = {0};

	ndc_query_parse(body);
	ndc_query_param("username",  username,         sizeof(username));
	ndc_query_param("password",  password,         sizeof(password));
	ndc_query_param("password2", password_confirm, sizeof(password_confirm));
	ndc_query_param("email",     email,            sizeof(email));
	ndc_query_param("ret",       redirect_path,    sizeof(redirect_path));
	target = redirect_target(redirect_path);

	size_t ulen = strlen(username);
	if (ulen < 2 || ulen > 32)
		return on_auth_register_error(fd, 400, "Username must be 2-32 characters", target);
	for (char *p = username; *p; p++)
		if (!valid_username_char(*p))
			return on_auth_register_error(fd, 400, "Invalid username character", target);
	if (strlen(password) < 4)
		return on_auth_register_error(fd, 400, "Password too short", target);
	if (strcmp(password, password_confirm) != 0)
		return on_auth_register_error(fd, 400, "Passwords do not match", target);
	if (qmap_get(users_map, username))
		return on_auth_register_error(fd, 400, "Username already exists", target);

	generate_bcrypt_salt(salt, sizeof(salt));
	char *hash = crypt(password, salt);
	if (!hash)
		return on_auth_register_error(fd, 500, "Password hashing failed", target);

	int uid = next_uid();
	strncpy(user.hash, hash, sizeof(user.hash) - 1);
	user.uid    = uid;
	skip_confirm = skip_confirm_required();
	user.active  = skip_confirm ? 1 : 0;

	qmap_put(users_map, username, &user);

	if (shadow_append(username, user.hash, uid) != 0)
		fprintf(stderr, "ndc-auth: warning: could not write shadow\n");
	if (passwd_append(username, uid) != 0)
		fprintf(stderr, "ndc-auth: warning: could not write passwd\n");
	if (group_append(username) != 0)
		fprintf(stderr, "ndc-auth: warning: could not update group\n");

#ifdef __OpenBSD__
	run_pwd_mkdb();
#endif

	snprintf(user_dir,   sizeof(user_dir),   "%s/%s",       auth_config.users_dir, username);
	snprintf(rcode_path, sizeof(rcode_path), "%s/rcode",    user_dir);

	if (mkdir(user_dir, 0755) && errno != EEXIST)
		fprintf(stderr, "ndc-auth: warning: could not create %s\n", user_dir);

	char home_dir[1024];
	snprintf(home_dir, sizeof(home_dir), "%s/%s", auth_config.home_dir, username);
	if (mkdir(home_dir, 0755) && errno != EEXIST)
		fprintf(stderr, "ndc-auth: warning: could not create %s\n", home_dir);

	if (*email) {
		char email_path[1088];
		snprintf(email_path, sizeof(email_path), "%s/email", user_dir);
		FILE *ef = fopen(email_path, "w");
		if (ef) { fputs(email, ef); fclose(ef); }
	}

	if (skip_confirm) {
		remove(rcode_path);
		return login_as(fd, username, target);
	}

	generate_token(rcode, sizeof(rcode));
	FILE *rf = fopen(rcode_path, "w");
	if (!rf)
		return on_auth_register_error(fd, 500, "Could not create confirmation", target);
	fputs(rcode, rf);
	fclose(rf);
	fprintf(stderr, "ndc-auth: confirm: %s/confirm?u=%s&r=%s\n",
		auth_config.route_prefix, username, rcode);

	return on_auth_register_ok(fd, username, target);
}

static int
handle_confirm(int fd, char *body)
{
	(void)body;
	char query[256] = {0}, username[64] = {0}, code[128] = {0};
	char rcode_path[1024], stored_rcode[128] = {0};
	struct user user, *existing;

	ndc_env_get(fd, query, "QUERY_STRING");
	ndc_query_parse(query);
	ndc_query_param("u", username, sizeof(username));
	ndc_query_param("r", code,     sizeof(code));

	if (!*username || !*code)
		return on_auth_confirm_error(fd, 400, "Missing parameters");

	existing = (struct user *)qmap_get(users_map, username);
	if (!existing || existing->active)
		return on_auth_confirm_error(fd, 400, "Invalid confirmation");

	snprintf(rcode_path, sizeof(rcode_path),
		"%s/%s/rcode", auth_config.users_dir, username);

	FILE *rf = fopen(rcode_path, "r");
	if (!rf)
		return on_auth_confirm_error(fd, 400, "No confirmation pending");
	if (!fgets(stored_rcode, sizeof(stored_rcode), rf)) {
		fclose(rf);
		return on_auth_confirm_error(fd, 400, "Could not read confirmation code");
	}
	fclose(rf);
	strip_trailing_nl(stored_rcode);

	if (strcmp(code, stored_rcode) != 0)
		return on_auth_confirm_error(fd, 400, "Wrong confirmation code");

	memcpy(&user, existing, sizeof(user));
	user.active = 1;
	qmap_put(users_map, username, &user);
	remove(rcode_path);

	if (shadow_update(username, user.hash) != 0)
		fprintf(stderr, "ndc-auth: warning: could not update shadow\n");

	return on_auth_confirm_ok(fd, username);
}

/* auth_init — call after writing auth_config fields */

void
auth_init(void)
{
	char route[512];

	users_map = qmap_open(NULL, "users", QM_STR,
		qmap_reg(sizeof(struct user)),
		auth_config.max_users, 0);
	sessions_map = qmap_open(NULL, "sess", QM_STR, QM_STR,
		auth_config.max_sessions, 0);

	mkdir(auth_config.etc_dir,   0755);
	mkdir(auth_config.users_dir, 0755);
	mkdir(auth_config.home_dir,  0755);

#ifndef __OpenBSD__
	{
		char ns_path[512];
		snprintf(ns_path, sizeof(ns_path), "%s/nsswitch.conf",
			auth_config.etc_dir);
		FILE *ns = fopen(ns_path, "wx");
		if (ns) {
			fputs("passwd:     files\n", ns);
			fputs("shadow:     files\n", ns);
			fputs("group:      files\n", ns);
			fclose(ns);
		}
	}
#endif

	load_shadow();
#ifndef __OpenBSD__
	load_passwd();
#endif

	snprintf(route, sizeof(route), "POST:%s/login",     auth_config.route_prefix);
	ndc_register_handler(route, handle_login);
	snprintf(route, sizeof(route), "POST:%s/register",  auth_config.route_prefix);
	ndc_register_handler(route, handle_register);
	snprintf(route, sizeof(route), "GET:%s/api/session", auth_config.route_prefix);
	ndc_register_handler(route, handle_session);
	snprintf(route, sizeof(route), "%s/logout",         auth_config.route_prefix);
	ndc_register_handler(route, handle_logout);
	snprintf(route, sizeof(route), "%s/confirm",        auth_config.route_prefix);
	ndc_register_handler(route, handle_confirm);
}

/* ndx_install — sets nothing; site configures then calls auth_init() */

int
auth_get_uid(const char *username)
{
	struct user *u = (struct user *)qmap_get(users_map, username);
	return u ? u->uid : -1;
}

void
ndx_install(void)
{
	/* Intentionally empty.
	 * Write auth_config fields as needed, then call auth_init(). */
}
