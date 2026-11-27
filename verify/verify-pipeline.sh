#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <deploy-url> [--output-dir <dir>]" >&2
}

DEPLOY_URL=""
OUTPUT_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output-dir)
      [ $# -ge 2 ] || { usage; exit 1; }
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      usage
      exit 1
      ;;
    *)
      if [ -n "$DEPLOY_URL" ]; then
        usage
        exit 1
      fi
      DEPLOY_URL="$1"
      shift
      ;;
  esac
done

if [ -z "$DEPLOY_URL" ]; then
  usage
  exit 1
fi

DEPLOY_URL="${DEPLOY_URL%/}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERIFY_DATE="$(date +%Y-%m-%d)"
if [ -n "$OUTPUT_DIR" ]; then
  mkdir -p "$OUTPUT_DIR"
  OUTPUT_FILE="$OUTPUT_DIR/pipeline-verify-$VERIFY_DATE.txt"
else
  OUTPUT_FILE="$PWD/pipeline-verify-$VERIFY_DATE.txt"
fi

CONTENT_TYPE_WHITELIST=(
  "text/plain"
  "text/x-powershell"
  "application/powershell"
  "text/x-shellscript"
)

{
  echo "SSG Resolution Pipeline verification"
  echo "Deploy URL: $DEPLOY_URL"
  echo "Date: $VERIFY_DATE"
  echo "Content-type whitelist: ${CONTENT_TYPE_WHITELIST[*]}"
  echo ""
} > "$OUTPUT_FILE"

manifest="$REPO_ROOT/app/materialized.json"
signatures_manifest="$REPO_ROOT/app/signatures.json"
verify_script="$REPO_ROOT/scripts/verify-signature.ps1"
key_json="$REPO_ROOT/public/keys/root-public.json"
if [ ! -f "$manifest" ]; then
  echo "FAIL: materialize manifest missing: $manifest (run npm run build)" | tee -a "$OUTPUT_FILE"
  exit 1
fi

if [ ! -f "$signatures_manifest" ]; then
  echo "FAIL: signatures manifest missing: $signatures_manifest (run npm run build)" | tee -a "$OUTPUT_FILE"
  exit 1
fi

if [ ! -f "$key_json" ]; then
  echo "FAIL: public key JSON missing: $key_json (run npm run build)" | tee -a "$OUTPUT_FILE"
  exit 1
fi

verify_cmd=""
if command -v pwsh &> /dev/null; then
  verify_cmd="pwsh"
elif command -v powershell.exe &> /dev/null; then
  verify_cmd="powershell.exe"
fi

verify_mode="SKIP"
if [ -n "$verify_cmd" ]; then
if "$verify_cmd" -NoProfile -Command 'if (($IsWindows -eq $true) -or ([System.Environment]::OSVersion.Platform.ToString() -eq "Win32NT")) { Write-Output "true" } else { Write-Output "false" }' 2>/dev/null | grep -qi 'true'; then
    verify_mode="VERIFY"
  else
    echo "WARN: pwsh is available but this is not Windows; RSACng is unavailable, signature verification will be skipped" >&2
  fi
else
  echo "WARN: no pwsh or powershell.exe found; signature verification will be skipped locally" >&2
fi

mapfile -t materialized_handles < <(
  node -e "const m=require(process.argv[1]); console.log(m.join('\n'))" "$manifest"
)

if [ ${#materialized_handles[@]} -eq 0 ]; then
  echo "FAIL: materialize manifest contains no handles" | tee -a "$OUTPUT_FILE"
  exit 1
fi

declare -A actual_targets=()
for public_file in "$REPO_ROOT"/public/@*; do
  [ -f "$public_file" ] || continue
  handle="$(basename "$public_file")"
  handle="${handle#@}"
  actual_targets["$handle"]=1
done

reconcile_failed=0
for handle in "${materialized_handles[@]}"; do
  if [[ -z "${actual_targets[$handle]:-}" ]]; then
    echo "FAIL: expected materialized handle missing from public/@*: @$handle" | tee -a "$OUTPUT_FILE"
    reconcile_failed=1
  fi
done
if [ $reconcile_failed -ne 0 ]; then
  exit 1
fi

signature_reconcile_failed=0
for handle in "${materialized_handles[@]}"; do
  has_signature="$(node -e "
    const s = JSON.parse(require('fs').readFileSync(process.argv[1], 'utf8'));
    console.log(s.handles && s.handles[process.argv[2]] ? 'yes' : 'no');
  " "$signatures_manifest" "$handle")"
  if [ "$has_signature" != "yes" ]; then
    echo "FAIL: signatures manifest has no entry for @$handle" | tee -a "$OUTPUT_FILE"
    signature_reconcile_failed=1
  fi
done
if [ $signature_reconcile_failed -ne 0 ]; then
  exit 1
fi

failed=0
for handle in "${materialized_handles[@]}"; do
  request_url="$DEPLOY_URL/@$handle"
  body_file="$(mktemp)"
  http_status="$(curl -s -o "$body_file" -w '%{http_code}' "$request_url" || true)"
  response_headers="$(curl -s -D - -o /dev/null "$request_url" || true)"
  content_type=""
  content_type="$(printf '%s' "$response_headers" | grep -i '^content-type:' | tail -1 | sed 's/^[Cc]ontent-[Tt]ype:[[:space:]]*//' | tr -d '\r' || true)"
  body_first_line=""
  body_first_line="$(head -1 "$body_file" || true)"

  verify_status="SKIP"
  if [ "$verify_mode" = "VERIFY" ]; then
    verify_output="$("$verify_cmd" -NoProfile -File "$verify_script" -File "$body_file" -KeyJson "$key_json" 2>&1)" || true
    if printf '%s' "$verify_output" | grep -q '^PASS '; then
      verify_status="PASS"
    else
      verify_code="$(printf '%s' "$verify_output" | grep '^FAIL ' | head -1 | awk '{print $2}')"
      if [ -z "$verify_code" ]; then
        verify_code="UNKNOWN"
      fi
      verify_status="FAIL:$verify_code"
      failed=1
    fi
  fi
  rm -f "$body_file"

  status_line="PASS"
  if [ "$http_status" != "200" ]; then
    status_line="FAIL: HTTP $http_status"
    failed=1
  fi
  if [ -z "$content_type" ]; then
    status_line="FAIL: HTTP $http_status, empty content-type"
    failed=1
  else
    matched=false
    for allowed in "${CONTENT_TYPE_WHITELIST[@]}"; do
      if [ "$content_type" = "$allowed" ]; then
        matched=true
        break
      fi
    done
    if [ "$matched" = false ]; then
      status_line="FAIL: HTTP $http_status, content-type '$content_type' not in whitelist"
      failed=1
    fi
  fi
  if ! printf '%s' "$body_first_line" | grep -qE '^#|^<#'; then
    status_line="FAIL: HTTP $http_status, first line is not a PowerShell comment"
    failed=1
  elif printf '%s' "$body_first_line" | grep -qiE '^<!doctype|^<html|^not found'; then
    status_line="FAIL: HTTP $http_status, body looks like HTML or error text"
    failed=1
  fi
  if [[ "$verify_status" == FAIL:* ]]; then
    verify_code="${verify_status#FAIL:}"
    status_line="FAIL: signature verification failed ($verify_code)"
  fi

  echo "handle: @$handle" >> "$OUTPUT_FILE"
  echo "URL: $request_url" >> "$OUTPUT_FILE"
  echo "status: $http_status" >> "$OUTPUT_FILE"
  echo "content-type: $content_type" >> "$OUTPUT_FILE"
  echo "first-line: $body_first_line" >> "$OUTPUT_FILE"
  echo "VERIFY: $verify_status" >> "$OUTPUT_FILE"
  echo "result: $status_line" >> "$OUTPUT_FILE"
  echo "" >> "$OUTPUT_FILE"
  echo "$status_line @$handle VERIFY=$verify_status"
done

if [ $failed -ne 0 ]; then
  exit 1
fi
