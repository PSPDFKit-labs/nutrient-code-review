#!/bin/bash
#
# Temporarily hides git credentials that actions/checkout persisted into the
# current repository's local config, so the Claude review (which can read files
# in the checkout, including .git/config) never sees the workflow token.
#
# Usage:
#   git-credentials.sh hide <state-file>     Save and remove credential entries
#   git-credentials.sh restore <state-file>  Re-add saved entries, delete state file
#
# Handled entries (local config only):
#   - http.<url>.extraheader          (actions/checkout v4/v5 store the token here)
#   - includeIf.<cond>.path pointing at a git-credentials-*.config file
#                                     (actions/checkout v6+ keeps the token in that file)
#
# The state file holds NUL-separated key/value pairs; keep it outside the
# checkout (e.g. under $RUNNER_TEMP) so the reviewer cannot read it. Restoring
# keeps later steps of the caller's job (e.g. git push) working.

set -euo pipefail

usage() {
  echo "Usage: $0 hide|restore <state-file>" >&2
  exit 2
}

[ $# -eq 2 ] || usage
command="$1"
state_file="$2"

is_credential_entry() {
  local key="$1" value="$2"
  local lower_key
  lower_key=$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')
  case "$lower_key" in
    http.*.extraheader)
      return 0
      ;;
    includeif.*.path)
      case "$value" in
        *git-credentials-*.config) return 0 ;;
      esac
      ;;
  esac
  return 1
}

hide() {
  if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "Not a git repository; no credentials to hide"
    : > "$state_file"
    return 0
  fi

  ( umask 077; : > "$state_file" )
  local entries=()
  local entry key value

  # --null: each entry is "key\nvalue" terminated by NUL, so keys and values
  # with spaces or newlines are handled safely.
  while IFS= read -r -d '' entry; do
    key="${entry%%$'\n'*}"
    if [ "$key" = "$entry" ]; then
      value=""
    else
      value="${entry#*$'\n'}"
    fi
    if is_credential_entry "$key" "$value"; then
      entries+=("$key" "$value")
    fi
  done < <(git config --local --null --list 2>/dev/null || true)

  if [ ${#entries[@]} -eq 0 ]; then
    echo "No persisted git credentials found"
    return 0
  fi

  # Remove only the matching values: an includeIf key can also carry
  # unrelated include paths that must stay. Save before removing so a failure
  # midway can still be restored.
  local i
  for ((i = 0; i < ${#entries[@]}; i += 2)); do
    printf '%s\0%s\0' "${entries[i]}" "${entries[i+1]}" >> "$state_file"
  done
  for ((i = 0; i < ${#entries[@]}; i += 2)); do
    # Identical duplicate values are all removed by the first call; later
    # calls for the same pair find nothing (exit 5), which is fine.
    git config --local --fixed-value --unset-all "${entries[i]}" "${entries[i+1]}" || [ $? -eq 5 ]
    echo "Hid persisted git credential config: ${entries[i]}"
  done
}

restore() {
  if [ ! -f "$state_file" ]; then
    return 0
  fi
  local key value
  while IFS= read -r -d '' key && IFS= read -r -d '' value; do
    git config --local --add "$key" "$value"
    echo "Restored git credential config: $key"
  done < "$state_file"
  rm -f "$state_file"
}

case "$command" in
  hide) hide ;;
  restore) restore ;;
  *) usage ;;
esac
