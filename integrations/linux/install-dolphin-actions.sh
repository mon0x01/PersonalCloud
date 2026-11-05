#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
TARGET_DIR="$DATA_HOME/kio/servicemenus"
mkdir -p "$TARGET_DIR"

install_menu() {
  local source="$1" action="$2" target_name="$3"
  local target="$TARGET_DIR/$target_name"
  local tmp escaped
  if [[ ! -f "$source" || ! -x "$action" ]]; then
    echo "PersonalCloud Dolphin integration files are incomplete: $target_name" >&2
    return 1
  fi
  tmp="$(mktemp "$TARGET_DIR/.personalcloud.XXXXXX")"
  escaped="$(printf '%s' "$action" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\$/\\\$/g' -e 's/`/\\`/g')"
  {
    cat "$source"
    printf 'Exec="%s" %%f\n' "$escaped"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$target"
  printf 'Installed Dolphin action: %s\n' "$target"
}

install_menu "$ROOT/integrations/linux/dolphin/personalcloud-reference.desktop" \
  "$ROOT/integrations/linux/personalcloud-dolphin-reference" "personalcloud-reference.desktop"
install_menu "$ROOT/integrations/linux/dolphin/personalcloud-send-file.desktop" \
  "$ROOT/integrations/linux/personalcloud-dolphin-place-file" "personalcloud-send-file.desktop"
install_menu "$ROOT/integrations/linux/dolphin/personalcloud-share-file.desktop" \
  "$ROOT/integrations/linux/personalcloud-dolphin-share-file" "personalcloud-share-file.desktop"
printf 'Restart Dolphin or log out/in if the actions are not immediately visible.\n'
