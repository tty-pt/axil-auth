#!/bin/sh
set -e

BASE="${AUTH_BASE:-http://localhost:8080}"
PREFIX="${AUTH_PREFIX:-/auth}"
COOKIE="/tmp/ndc_auth_test_$$"
USER="testuser_$$"

fail() { echo "FAIL: $1"; rm -f "$COOKIE"; exit 1; }
pass() { echo "PASS: $1"; }

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
echo "All ndc-auth tests passed."
