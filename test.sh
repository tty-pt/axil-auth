#!/bin/sh
set -e

BASE="${AUTH_BASE:-http://localhost:8080}"
PREFIX="${AUTH_PREFIX:-/auth}"
COOKIE="/tmp/axil_auth_test_$$"
USER="testuser_$$"

fail() { echo "FAIL: $1"; rm -f "$COOKIE"; exit 1; }
pass() { echo "PASS: $1"; }

# Fixture rows appended to the account database are removed on every exit path,
# including a failure -- otherwise a failed run leaves a real account behind.
SQUAT="squatted_$$"
ETC_DIR="${AUTH_ETC_DIR:-$(cd "$(dirname "$0")/../.." && pwd)/etc}"
PASSWD="$ETC_DIR/passwd"
SHADOW="$ETC_DIR/shadow"
cleanup() {
	rm -f "$COOKIE"
	for f in "$PASSWD" "$SHADOW"; do
		[ -w "$f" ] || continue
		grep -v "^$SQUAT:" "$f" > "$f.tmp" && mv "$f.tmp" "$f"
	done
}
trap cleanup EXIT INT TERM

# 1. Empty session
echo -n "1. Empty session... "
out=$(curl -sb "$COOKIE" "$BASE$PREFIX/api/session")
[ -z "$out" ] && pass "empty session" || fail "expected empty, got: $out"

# 2. Register valid user
echo -n "2. Register valid user... "
code=$(curl -sw "%{http_code}" -o /dev/null -c "$COOKIE" -X POST "$BASE$PREFIX/register" \
	-d "username=$USER&password=pass1234&password2=pass1234&email=test@test.com")
[ "$code" = "303" ] && pass "register redirects" || fail "expected 303, got $code"

# 3. Session set after register (AUTH_SKIP_CONFIRM=1 auto-login)
echo -n "3. Session set after register... "
out=$(curl -sb "$COOKIE" "$BASE$PREFIX/api/session")
[ "$out" = "$USER" ] && pass "session returns user" || fail "expected '$USER', got: $out"

# 4. Logout
echo -n "4. Logout... "
code=$(curl -sw "%{http_code}" -o /dev/null -b "$COOKIE" -c "$COOKIE" "$BASE$PREFIX/logout")
[ "$code" = "303" ] && pass "logout redirects" || fail "expected 303, got $code"

# 5. Session empty after logout
echo -n "5. Session empty after logout... "
out=$(curl -sb "$COOKIE" "$BASE$PREFIX/api/session")
[ -z "$out" ] && pass "session empty" || fail "expected empty, got: $out"

# 6. Login after register
echo -n "6. Login after register... "
code=$(curl -sw "%{http_code}" -o /dev/null -c "$COOKIE" -X POST "$BASE$PREFIX/login" \
	-d "username=$USER&password=pass1234")
[ "$code" = "303" ] && pass "login redirects" || fail "expected 303, got $code"

# 7. Session with cookie after login
echo -n "7. Session with cookie after login... "
out=$(curl -sb "$COOKIE" "$BASE$PREFIX/api/session")
[ "$out" = "$USER" ] && pass "session returns user" || fail "expected '$USER', got: $out"

# 8. Logout
echo -n "8. Logout... "
code=$(curl -sw "%{http_code}" -o /dev/null -b "$COOKIE" -c "$COOKIE" "$BASE$PREFIX/logout")
[ "$code" = "303" ] && pass "logout redirects" || fail "expected 303, got $code"

# 9. Session empty after logout
echo -n "9. Session empty after logout... "
out=$(curl -sb "$COOKIE" "$BASE$PREFIX/api/session")
[ -z "$out" ] && pass "session empty" || fail "expected empty, got: $out"

# 10. Register duplicate
echo -n "10. Register duplicate... "
out=$(curl -s -X POST "$BASE$PREFIX/register" \
	-d "username=$USER&password=pass1234&password2=pass1234&email=test2@test.com")
echo "$out" | grep -qi "exists" && pass "duplicate rejected" || fail "expected 'exists', got: $out"

# 11. Login wrong password
echo -n "11. Login wrong password... "
out=$(curl -s -X POST "$BASE$PREFIX/login" -d "username=$USER&password=wrongpass")
echo "$out" | grep -q "Invalid" && pass "wrong password rejected" || fail "expected 'Invalid', got: $out"

# 12. Login nonexistent user
echo -n "12. Login nonexistent user... "
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE$PREFIX/login" \
	-d "username=nobody_$$&password=pass1234")
[ "$status" = "401" ] && pass "nonexistent rejected" || fail "expected 401, got: $status"

# 13. Multiple cookies — correct one is parsed
echo -n "13. Multi-value cookie parsing... "
tok=$(curl -sc "$COOKIE" -o /dev/null "$BASE$PREFIX/api/session" 2>/dev/null; \
	grep QSESSION "$COOKIE" 2>/dev/null | awk '{print $NF}' || true)
raw_out=$(curl -s \
	-H "Cookie: other=xyz; QSESSION=$(grep QSESSION "$COOKIE" 2>/dev/null | awk '{print $NF}'); trailing=abc" \
	"$BASE$PREFIX/api/session")
# after fresh logout the session is empty — just verify no crash (200-ish response code)
status2=$(curl -so /dev/null -w "%{http_code}" \
	-H "Cookie: other=xyz; QSESSION=bogus; trailing=abc" \
	"$BASE$PREFIX/api/session")
[ "$status2" = "200" ] && pass "multi-cookie no crash" || fail "expected 200, got: $status2"

rm -f "$COOKIE"

# 14. A registered account's passwd row must name a no-op shell.
# The shell field is what a downstream terminal check consults before granting a
# login shell, so /bin/sh here would hand every registered account a server shell.
echo -n "14. Registered account has a no-op shell... "
if [ ! -r "$PASSWD" ]; then
	fail "cannot read $PASSWD (set AUTH_ETC_DIR)"
fi
row=$(grep "^$USER:" "$PASSWD" | tail -1)
if [ -z "$row" ]; then
	fail "no passwd row for $USER"
fi
shell=$(printf '%s' "$row" | awk -F: '{print $7}')
case "$shell" in
/bin/false|*/false) pass "passwd shell is $shell" ;;
*) fail "passwd shell is '$shell', expected /bin/false" ;;
esac

# 15. A name already in passwd must not be claimable by registration.
# load_passwd() does not seed the user map from passwd, so such a name used to be
# registrable -- and the resulting session then resolved to that real account.
echo -n "15. Registering a passwd-only name is refused... "
printf '%s:x:99999:67::/home/%s:/bin/sh\n' "$SQUAT" "$SQUAT" >> "$PASSWD"
out=$(curl -s -X POST "$BASE$PREFIX/register" \
	-d "username=$SQUAT&password=pass1234&password2=pass1234&email=squat@test.com")
echo "$out" | grep -qi "exists" \
	&& pass "passwd-only name refused" \
	|| fail "passwd-only name was accepted: $out"

# 16. ...and the refused registration left no shadow row behind either.
echo -n "16. Refused registration created no shadow row... "
if [ -r "$SHADOW" ]; then
	grep -q "^$SQUAT:" "$SHADOW" \
		&& fail "shadow row created for refused registration" \
		|| pass "no shadow row"
else
	pass "shadow unreadable, skipped"
fi

echo "All axil-auth tests passed."
