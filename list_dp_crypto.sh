#!/usr/bin/env bash
#
# list_dp_crypto.sh - list every Crypto Key and Crypto Certificate object, with the crypto
#                     file it maps to, in all domains of an IBM DataPower Gateway, using the
#                     REST management interface (default port 5554). Read-only.
#
# Usage:
#   ./list_dp_crypto.sh [output.csv]
#
# Prints a table to the screen and writes a CSV (default: dp_crypto_<host>_<timestamp>.csv).
# CSV columns: domain,class,object,adminState,file
#   class = CryptoKey | CryptoCertificate
#   file  = the object's Filename (e.g. cert:///server_key.pem, sharedcert:///ca.pem);
#           empty for objects that do not map to a file (e.g. HSM keys).
#
# Requires: bash, curl, jq.
# Optional env vars to skip prompts:
#   DP_HOST DP_PORT DP_USER DP_PASS
#   DP_DOMAINS   space-separated list of domains to scan (default: all domains)

set -u
umask 077

for b in curl jq; do
  command -v "$b" >/dev/null 2>&1 || { echo "ERROR: '$b' is required." >&2; exit 1; }
done

TMP="$(mktemp -d)" || exit 1
trap 'rm -rf "$TMP"' EXIT

die()  { echo "ERROR: $*" >&2; exit 1; }
prompt() {  # prompt VAR "Question" [default]
  local ans
  if [[ -n "${3:-}" ]]; then read -r -p "$2 [$3]: " ans; ans="${ans:-$3}"; else read -r -p "$2: " ans; fi
  printf -v "$1" '%s' "${ans%$'\r'}"
}

# ---------------------------------------------------------------- connection
HOST="${DP_HOST:-}"; PORT="${DP_PORT:-5554}"
[[ -n "$HOST" ]] || prompt HOST "DataPower host/IP"
[[ -n "${DP_PORT:-}" ]] || prompt PORT "REST management port" "5554"
USER_NAME="${DP_USER:-}"; [[ -n "$USER_NAME" ]] || prompt USER_NAME "Username"
PASS="${DP_PASS:-}"; if [[ -z "$PASS" ]]; then read -r -s -p "Password: " PASS; echo; fi
[[ -n "$HOST" && -n "$USER_NAME" && -n "$PASS" ]] || die "host, username and password are required."

OUT="${1:-dp_crypto_${HOST//[^A-Za-z0-9._-]/_}_$(date +%Y%m%d%H%M%S).csv}"
API="https://$HOST:$PORT/mgmt"

# api URL -> prints HTTP code, response body in $TMP/out.json.
# The gateway's self-signed management certificate is trusted (-k).
# Credentials go to curl on stdin so they are not visible in the process list.
api() {
  local a=(-sS -k -X GET -K - -H "Accept: application/json" -o "$TMP/out.json" -w '%{http_code}') u p
  u="${USER_NAME//\\/\\\\}"; u="${u//\"/\\\"}"
  p="${PASS//\\/\\\\}";      p="${p//\"/\\\"}"
  printf 'user = "%s:%s"\n' "$u" "$p" | curl "${a[@]}" "$1"
}

# ------------------------------------------------------------------- domains
if [[ -n "${DP_DOMAINS:-}" ]]; then
  read -r -a DOMAINS <<< "$DP_DOMAINS"
else
  code="$(api "$API/domains/config/")" || die "cannot connect to $HOST:$PORT"
  [[ "$code" == 200 ]] || die "cannot list domains (HTTP $code): $(jq -r '.error // .' "$TMP/out.json" 2>/dev/null | head -n 3)"
  mapfile -t DOMAINS < <(jq -r '(.domain // []) | if type=="array" then . else [.] end | .[].name' "$TMP/out.json" | tr -d '\r')
fi
((${#DOMAINS[@]} > 0)) || die "no domains found."
echo "[*] $HOST:$PORT - scanning ${#DOMAINS[@]} domain(s): ${DOMAINS[*]}" >&2

# ------------------------------------------------------------------- collect
ROWS="$TMP/rows.tsv"; : > "$ROWS"
ERRORS=0
for dom in "${DOMAINS[@]}"; do
  for cls in CryptoKey CryptoCertificate; do
    code="$(api "$API/config/$dom/$cls")" || { echo "[!] $dom/$cls: connection failed" >&2; ERRORS=$((ERRORS+1)); continue; }
    if [[ "$code" == 404 ]]; then continue; fi   # no objects of this class in the domain
    if [[ "$code" != 200 ]]; then
      echo "[!] $dom/$cls: HTTP $code" >&2; ERRORS=$((ERRORS+1)); continue
    fi
    # The class key holds an array, a single object (one match) or is absent (none).
    jq -r --arg d "$dom" --arg c "$cls" '
      (.[$c] // []) | if type=="array" then . else [.] end | .[]
      | [$d, $c, .name, (.mAdminState // ""), (.Filename // "")] | @tsv' "$TMP/out.json" >> "$ROWS"
  done
done

# -------------------------------------------------------------------- output
{ echo "domain,class,object,adminState,file"
  jq -R -s -r 'split("\n") | map(select(length>0) | split("\t")) | sort_by(.[0], .[1], .[2]) | .[] | @csv' "$ROWS"
} > "$OUT"

COUNT=$(( $(wc -l < "$OUT") - 1 ))
if command -v column >/dev/null 2>&1; then
  { printf 'DOMAIN\tCLASS\tOBJECT\tSTATE\tFILE\n'; sort -t$'\t' -k1,1 -k2,2 -k3,3 "$ROWS"; } | column -t -s $'\t'
else
  { printf 'DOMAIN\tCLASS\tOBJECT\tSTATE\tFILE\n'; sort -t$'\t' -k1,1 -k2,2 -k3,3 "$ROWS"; }
fi
echo
echo "[+] $COUNT object(s) found. CSV written to: $OUT"
((ERRORS == 0)) || { echo "[!] $ERRORS request(s) failed; the list may be incomplete." >&2; exit 2; }
