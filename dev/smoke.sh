#!/usr/bin/env bash
# Skald end-to-end smoke test.
#
# Drives the real OIDC authorization-code flow against the dev stack's Keycloak for two
# users in different groups, and asserts both ALLOW and DENY. Deny cases are the point:
# an access-control regression that only breaks denial is invisible to a happy-path test.
#
# Usage: bash dev/smoke.sh          (stack must be up: `make dev`)

set -uo pipefail

BASE="${BASE:-http://localhost:8080}"
PASS=0
FAIL=0

ok()   { echo "  ok   $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$3', got '$2')"; fi; }

# Log in through the browser flow and leave a session cookie in $2.
login() {
  local user="$1" jar="$2" pass="$1"
  rm -f "$jar"

  # 1. Hit the app; ShinyProxy redirects to Keycloak's authorization endpoint.
  local login_page
  login_page=$(curl -sL -c "$jar" -b "$jar" "$BASE/")

  # 2. Extract the login form's action URL (Keycloak embeds a one-time execution token).
  local action
  action=$(printf '%s' "$login_page" \
    | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//; s/"$//' \
    | sed 's/&amp;/\&/g')
  if [ -z "$action" ]; then
    echo "  !! could not find Keycloak login form for $user" >&2
    return 1
  fi

  # 3. Submit credentials; follow the redirect chain back into ShinyProxy.
  curl -sL -c "$jar" -b "$jar" \
    -d "username=$user" -d "password=$pass" -d "credentialId=" \
    "$action" -o /dev/null
}

# Does the authenticated index list this spec?
#
# The body is captured into a variable rather than piped into grep: under `pipefail`,
# `grep -q` exits on the first match, curl takes a SIGPIPE, and the successful match is
# reported as a failed pipeline. That bug makes every "sees" assertion read `no` and
# every "does NOT see" assertion pass for the wrong reason.
lists_spec() {
  local jar="$1" spec="$2" body
  body=$(curl -s -b "$jar" -c "$jar" "$BASE/")
  case "$body" in
    *"data-app-id=\"$spec\""*) echo yes ;;
    *)                          echo no  ;;
  esac
}

# Guard: confirm we are actually looking at the authenticated index and not a login page,
# so a broken session cannot masquerade as "the app is correctly hidden".
assert_logged_in() {
  local jar="$1" who="$2" body
  body=$(curl -s -b "$jar" -c "$jar" "$BASE/")
  case "$body" in
    *"data-app-id="*) ok "$who has an authenticated session" ;;
    *) bad "$who is NOT logged in — later results are meaningless" ;;
  esac
}

# What status does this user get opening the spec directly?
opens_spec() {
  local jar="$1" spec="$2"
  curl -s -o /dev/null -w '%{http_code}' -b "$jar" -c "$jar" "$BASE/app/$spec"
}

echo "== unauthenticated =="
code=$(curl -s -o /dev/null -w '%{http_code}' -L "$BASE/app/hello")
# Anonymous users are bounced to Keycloak, which answers 200 with a login page.
body=$(curl -sL "$BASE/app/hello" | grep -ci 'kc-form\|Sign in\|password' || true)
if [ "$body" -gt 0 ]; then ok "anonymous is sent to the IdP login page"
else bad "anonymous was NOT sent to a login page (status $code)"; fi

echo "== alice (publishers, platform-admins) =="
ALICE=$(mktemp); login alice "$ALICE" || exit 1
assert_logged_in "$ALICE" alice
check "alice sees 'hello'"            "$(lists_spec "$ALICE" hello)"            yes
check "alice sees 'publishers-only'"  "$(lists_spec "$ALICE" publishers-only)"  yes
check "alice may open 'publishers-only'" "$(opens_spec "$ALICE" publishers-only)" 200
check "alice reaches /admin"          "$(curl -s -o /dev/null -w '%{http_code}' -b "$ALICE" "$BASE/admin")" 200

echo "== bob (viewers) =="
BOB=$(mktemp); login bob "$BOB" || exit 1
assert_logged_in "$BOB" bob
check "bob sees 'hello'"              "$(lists_spec "$BOB" hello)"              yes
check "bob does NOT see 'publishers-only'" "$(lists_spec "$BOB" publishers-only)" no
check "bob is denied 'publishers-only'"    "$(opens_spec "$BOB" publishers-only)" 403
check "bob is denied /admin"          "$(curl -s -o /dev/null -w '%{http_code}' -b "$BOB" "$BASE/admin")" 403

echo "== container start (proves the Docker backend + internal networking) =="
# Nothing above this point starts a container, so a wrong
# proxy.docker.internal-networking / default-container-network would pass every check
# and only surface much later. Start a real app and fetch a page through the proxy.
#
# Responses are wrapped as {"status":"success","data":{...}} and `data` contains a nested
# `containers` list with its own `id`. Parse the JSON properly: a greedy sed for "id"
# silently returns the LAST match, which is a container id, not the proxy id.
jfield() { python3 -c 'import json,sys; d=json.load(sys.stdin).get("data") or {}; print(d.get(sys.argv[1]) or "")' "$1"; }

pid=$(curl -s -b "$ALICE" -c "$ALICE" -X POST -H 'Content-Type: application/json' \
  -d '{}' "$BASE/api/proxy/hello" | jfield id)

if [ -n "$pid" ]; then
  ok "app 'hello' start accepted (proxy $pid)"
  status=""
  for _ in $(seq 1 30); do
    status=$(curl -s -b "$ALICE" -c "$ALICE" "$BASE/api/proxy/$pid" | jfield status)
    case "$status" in Up|Stopped|Crashed) break ;; esac
    sleep 2
  done
  check "app 'hello' reaches status Up" "$status" Up
  # Reached only through the container network: no app port is published to the host.
  #
  # Fetch through /api/route/<proxyId>/ -- the mapping ProxyMappingManager serves for a
  # running proxy. NOT /app_direct/hello/: that path is get-or-start keyed on
  # (user, app, instance "_"), and an API-started proxy carries no SHINYPROXY_APP_INSTANCE
  # runtime value, so it never matches (BaseController.java:149). app_direct then tries to
  # start a SECOND instance and trips proxy.default-max-instances -- default "1",
  # ShinyProxySpecProvider.java:117 -- a deterministic 500 that reads like a networking
  # fault but is not one.
  code=$(curl -s -o /dev/null -w '%{http_code}' -b "$ALICE" -c "$ALICE" "$BASE/api/route/$pid/")
  check "app 'hello' serves through the proxy" "$code" 200

  # Stop it, and ASSERT that it stopped. DELETE /api/proxy/<id> is not mapped -- the
  # server answers 405 with `Allow: POST,GET,HEAD,OPTIONS`; the stop verb is PUT on
  # .../status. The previous DELETE silently did nothing and its result was never
  # checked, so every run leaked a live container and the next run tripped max-instances.
  # An unconditional `ok` is a check that cannot fail: the same class of bug as the
  # `grep -q` pipeline above.
  curl -s -o /dev/null -X PUT -H 'Content-Type: application/json' \
    -d '{"status":"Stopping"}' -b "$ALICE" -c "$ALICE" "$BASE/api/proxy/$pid/status"
  stopped=no
  for _ in $(seq 1 15); do
    still=$(curl -s -b "$ALICE" -c "$ALICE" "$BASE/api/proxy" \
      | python3 -c 'import json,sys; print(sum(1 for p in json.load(sys.stdin)["data"] if p["id"]==sys.argv[1]))' "$pid")
    if [ "$still" = 0 ]; then stopped=yes; break; fi
    sleep 2
  done
  check "app 'hello' stopped" "$stopped" yes
else
  bad "app 'hello' did not start"
fi

echo "== runtime-added content (spine #1: publish with NO restart) =="
# The whole architectural bet in one block. Alice creates content through the admin endpoint
# while the platform is running, then runs it; bob is denied. Nothing restarts between the
# insert and the run -- if this needed a restart, the plan would have been wrong.
#
# Uses /admin/content rather than SQL on purpose: a smoke test that reaches around the API it
# is meant to exercise proves the database works, not the product.
#
# Content is addressed by a PATH and identified by an opaque id. The spec id is derived from
# that id, never from the path, so it survives a rename and is never handed to different
# content later -- which is what stopped a re-created name inheriting a cached authorization
# decision. The script therefore reads ids out of the API instead of building them from names.
# A fresh path per run. Paths are reserved permanently once used -- that is what stops a
# retired URL later pointing at different content -- so a script that hard-coded one would pass
# the first time and fail with 409 Conflict on every run after. Each run consumes two
# reservations in the dev registry, which is cheap and is the honest semantic.
RUN_ID="${RUN_ID:-$(date +%s)$$}"
PATHNAME="smoke/runtime-$RUN_ID"
jstatus() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
# Tolerates error bodies, where "data" is a string rather than an object -- a cleanup probe on
# an empty registry hits exactly that, and a traceback there would be noise that could hide a
# real failure later in the run.
jfld() { python3 -c 'import json,sys
try:
    d = json.load(sys.stdin).get("data")
except Exception:
    d = None
if not isinstance(d, dict):
    print(""); raise SystemExit
d = d.get("content", d)
print(d.get(sys.argv[1]) or "")' "$1"; }

created=$(curl -s -b "$ALICE" -c "$ALICE" -X POST -H 'Content-Type: application/json' \
  -d "{\"path\":\"$PATHNAME\",\"title\":\"Smoke runtime app\",\"owner\":\"alice\",\"type\":\"shiny\"}" \
  "$BASE/admin/content")
CID=$(printf '%s' "$created" | jfld id)
check "alice creates content over the admin API" "$([ -n "$CID" ] && echo yes || echo no)" yes

SPEC=$(curl -s -b "$ALICE" -c "$ALICE" -X POST -H 'Content-Type: application/json' \
  -d '{"image":"openanalytics/shinyproxy-demo"}' "$BASE/admin/content/$CID/versions" | jfld activeSpecId)
check "alice adds and activates version 1" "$([ -n "$SPEC" ] && echo yes || echo no)" yes
check "the spec id is derived from the content id, not the path" \
  "$(printf '%s' "$SPEC" | grep -qE '^c[0-9a-f]{32}--v1$' && echo yes || echo no)" yes

# No restart happens anywhere between the lines above and below.
check "alice sees the new app immediately"  "$(lists_spec "$ALICE" "$SPEC")" yes
check "alice may open the new app"          "$(opens_spec "$ALICE" "$SPEC")" 200
check "bob does NOT see alice's new app"    "$(lists_spec "$BOB" "$SPEC")"   no
check "bob is denied alice's new app"       "$(opens_spec "$BOB" "$SPEC")"   403
check "bob cannot reach the admin API"      "$(jstatus -b "$BOB" -c "$BOB" "$BASE/admin/content")" 403

# A rename keeps every link working and does not disturb the running spec id.
code=$(jstatus -b "$ALICE" -c "$ALICE" -X PUT -H 'Content-Type: application/json' \
  -d "{\"path\":\"smoke/renamed-$RUN_ID\"}" "$BASE/admin/content/$CID/path")
check "alice renames the content"                  "$code" 200
check "the spec id is unchanged by the rename" \
  "$(curl -s -b "$ALICE" -c "$ALICE" "$BASE/admin/content/by-path?path=smoke/renamed-$RUN_ID" | jfld activeSpecId)" "$SPEC"
check "the OLD path still resolves for scripts" \
  "$(jstatus -b "$ALICE" -c "$ALICE" "$BASE/admin/content/by-path?path=$PATHNAME")" 200
check "the old path may not be taken by anyone else" \
  "$(jstatus -b "$ALICE" -c "$ALICE" -X POST -H 'Content-Type: application/json' \
     -d "{\"path\":\"$PATHNAME\",\"title\":\"x\",\"owner\":\"alice\",\"type\":\"shiny\"}" "$BASE/admin/content")" 409

# Refusals that protect decisions taken in spine #1, each proved live rather than asserted.
check "a path nested inside another is refused" \
  "$(jstatus -b "$ALICE" -c "$ALICE" -X POST -H 'Content-Type: application/json' \
     -d '{"path":"smoke","title":"x","owner":"alice","type":"shiny"}' "$BASE/admin/content")" 409
check "visibility 'anonymous' is refused" \
  "$(jstatus -b "$ALICE" -c "$ALICE" -X POST -H 'Content-Type: application/json' \
     -d "{\"path\":\"smoke-public-$RUN_ID\",\"title\":\"x\",\"owner\":\"alice\",\"type\":\"shiny\",\"visibility\":\"anonymous\"}" "$BASE/admin/content")" 400
check "a form-encoded POST is refused (CSRF)" \
  "$(jstatus -b "$ALICE" -c "$ALICE" -X POST -d "path=smoke-csrf-$RUN_ID&title=x&owner=alice&type=shiny" "$BASE/admin/content")" 415

# A retired version must stop being startable, or activation never retires anything.
SPEC2=$(curl -s -b "$ALICE" -c "$ALICE" -X POST -H 'Content-Type: application/json' \
  -d '{"image":"openanalytics/shinyproxy-demo"}' "$BASE/admin/content/$CID/versions" | jfld activeSpecId)
check "alice activates version 2"                  "$([ -n "$SPEC2" ] && echo yes || echo no)" yes
check "the retired version is no longer listed"    "$(lists_spec "$ALICE" "$SPEC")"  no
check "the retired version cannot be opened"       "$(opens_spec "$ALICE" "$SPEC")"  403
check "the active version can be opened"           "$(opens_spec "$ALICE" "$SPEC2")" 200

check "alice deletes the content"                  "$(jstatus -b "$ALICE" -c "$ALICE" -X DELETE "$BASE/admin/content/$CID")" 200
check "the deleted app is gone from the index"     "$(lists_spec "$ALICE" "$SPEC2")" no
check "its path is GONE, not free to reuse" \
  "$(jstatus -b "$ALICE" -c "$ALICE" "$BASE/admin/content/by-path?path=smoke/renamed-$RUN_ID")" 410

rm -f "$ALICE" "$BOB"
echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
