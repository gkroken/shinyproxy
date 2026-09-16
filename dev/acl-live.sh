#!/usr/bin/env bash
# Skald ACL live-stack exercise (spine #1 task 5).
#
# Drives the REAL OIDC flow against the dev stack and checks the content_acl + visibility
# projection end to end. Separate from dev/smoke.sh because it needs to write to PostgreSQL;
# task 9 folds the runtime-added-app checks into smoke.sh proper.
#
# It covers two things no unit test can reach, both of which were the actual point:
#   - content inserted AFTER a session is established (no restart, and risk 4's
#     maxInstancesCache, which really did return null before task 5)
#   - an ACL revoked against a WARM session, which still succeeds -- the
#     ProxyAccessControlService limitation in docs/UPSTREAM_CHANGES.md section B
#
# The deny assertions were checked against a data mutation (granting bob access to
# alice-only flips 403 -> 200 and listed=no -> yes), so they are not vacuous. Every user has
# a passing ALLOW check in the same session as their DENY checks, which is what rules out a
# dead session masquerading as correct denial.
#
# Usage: bash dev/acl-live.sh      (stack must be up: `make dev`)

set -uo pipefail

BASE="${BASE:-http://localhost:8080}"
COMPOSE="docker compose -f docker-compose.dev.yml"
PASS=0; FAIL=0

ok()   { echo "  ok   $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$3', got '$2')"; fi; }

sql() { $COMPOSE exec -T postgres psql -U skald -d skald -v ON_ERROR_STOP=1 -q -c "$1" >/dev/null; }

# Same browser flow as dev/smoke.sh.
login() {
  local user="$1" jar="$2" login_page action
  rm -f "$jar"
  login_page=$(curl -sL -c "$jar" -b "$jar" "$BASE/")
  action=$(printf '%s' "$login_page" | grep -o 'action="[^"]*"' | head -1 \
    | sed 's/action="//; s/"$//' | sed 's/&amp;/\&/g')
  [ -z "$action" ] && { echo "  !! no Keycloak form for $user" >&2; return 1; }
  curl -sL -c "$jar" -b "$jar" -d "username=$user" -d "password=$user" -d "credentialId=" \
    "$action" -o /dev/null
}

# Body captured into a variable, never piped into grep -q: under pipefail that reports a
# successful match as a failed pipeline (the bug WORKPLAN-DEVSTACK.md finding 5 records).
lists_spec() {
  local jar="$1" spec="$2" body
  body=$(curl -s -b "$jar" -c "$jar" "$BASE/")
  case "$body" in *"data-app-id=\"$spec\""*) echo yes ;; *) echo no ;; esac
}

opens_spec() {
  curl -s -o /dev/null -w '%{http_code}' -b "$1" -c "$1" "$BASE/app/$2"
}

publish() { # slug owner visibility
  sql "INSERT INTO skald.content (slug, owner, type, visibility) VALUES ('$1','$2','shiny','$3');"
  sql "INSERT INTO skald.content_version (content_id, version, image, created_by)
       SELECT id, 1, 'openanalytics/shinyproxy-demo', '$2' FROM skald.content WHERE slug='$1';"
  sql "UPDATE skald.content c SET active_version_id = v.id FROM skald.content_version v
       WHERE v.content_id = c.id AND v.version = 1 AND c.slug='$1';"
}

grant() { # slug type principal
  sql "INSERT INTO skald.content_acl (content_id, principal_type, principal)
       SELECT id, '$2', '$3' FROM skald.content WHERE slug='$1';"
}

echo "== reset registry =="
sql "DELETE FROM skald.content;"
ok "registry emptied"

echo
echo "== publish before login =="
publish alice-only     alice acl_only
publish shared-user    alice acl_only ; grant shared-user  user  bob
publish shared-group   alice acl_only ; grant shared-group group viewers
publish open-to-all    alice all_authenticated
publish public-thing   alice anonymous
ok "five content items inserted directly into PostgreSQL"

ALICE=$(mktemp); BOB=$(mktemp)
login alice "$ALICE" || exit 1
login bob   "$BOB"   || exit 1

echo
echo "== alice (owner; publishers, platform-admins) =="
check "alice sees her own 'alice-only'"     "$(lists_spec "$ALICE" alice-only--v1)"   yes
check "alice may open 'alice-only'"          "$(opens_spec "$ALICE" alice-only--v1)"   200
check "alice sees 'open-to-all'"             "$(lists_spec "$ALICE" open-to-all--v1)"  yes

echo
echo "== bob (viewers) =="
check "bob does NOT see 'alice-only'"        "$(lists_spec "$BOB" alice-only--v1)"     no
check "bob is DENIED 'alice-only'"           "$(opens_spec "$BOB" alice-only--v1)"     403
check "bob sees 'shared-user' (user grant)"  "$(lists_spec "$BOB" shared-user--v1)"    yes
check "bob may open 'shared-user'"           "$(opens_spec "$BOB" shared-user--v1)"    200
check "bob sees 'shared-group' (group grant)" "$(lists_spec "$BOB" shared-group--v1)"  yes
check "bob sees 'open-to-all'"               "$(lists_spec "$BOB" open-to-all--v1)"    yes

echo
echo "== anonymous visibility is refused, not downgraded =="
check "alice does NOT see 'public-thing'"    "$(lists_spec "$ALICE" public-thing--v1)" no
check "alice is DENIED 'public-thing'"       "$(opens_spec "$ALICE" public-thing--v1)" 403
check "bob does NOT see 'public-thing'"      "$(lists_spec "$BOB" public-thing--v1)"   no
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/app/public-thing--v1")
check "unauthenticated is not served 'public-thing'" "$([ "$code" = 200 ] && echo served || echo refused)" refused

echo
echo "== published MID-SESSION: no restart, and risk 4 (maxInstancesCache) =="
# Both sessions are already established and have already rendered the index, so their
# max-instances maps are cached. Before task 5 this returned null for new content and
# BaseController.validateMaxInstances threw on unboxing it.
publish late-arrival alice acl_only
grant   late-arrival user  bob
check "bob sees 'late-arrival' in his EXISTING session"  "$(lists_spec "$BOB" late-arrival--v1)" yes
check "bob may OPEN 'late-arrival' in his EXISTING session (risk 4)" \
      "$(opens_spec "$BOB" late-arrival--v1)" 200

echo
echo "== ACL revoked mid-session (ProxyAccessControlService cache, UPSTREAM_CHANGES.md B) =="
sql "DELETE FROM skald.content_acl a USING skald.content c
     WHERE a.content_id = c.id AND c.slug='shared-user' AND a.principal='bob';"
warm=$(opens_spec "$BOB" shared-user--v1)
FRESH=$(mktemp); login bob "$FRESH" || exit 1
fresh=$(opens_spec "$FRESH" shared-user--v1)
check "a FRESH session is denied the revoked content" "$fresh" 403
if [ "$warm" = "403" ]; then
  ok "warm session also denied — the cache finding no longer reproduces, revisit UPSTREAM_CHANGES.md B"
else
  ok "warm session still gets $warm — reproduces the documented cache limitation"
fi

rm -f "$ALICE" "$BOB" "$FRESH"
echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
