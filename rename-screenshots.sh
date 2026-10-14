#!/usr/bin/env bash
#
# Investigating with Splunk (TryHackMe) — screenshot staging helper
# -----------------------------------------------------------------
# Places the original session screenshots into images/ using the
# descriptive filenames referenced by README.md.
#
# Usage:
#   1. Copy the 13 original PNGs into the repository root,
#      keeping their "Screenshot 2026-10-14 HHMMSS.png" names.
#   2. From the repository root, run:   ./rename-screenshots.sh
#   3. Delete this script once the images are in place.
#
# Safe to re-run: files that are already staged are reported as MISS
# and skipped without touching anything else.
#
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p images

# "<original filename>|<destination filename inside images/>"
MAP=(
  "Screenshot 2026-10-14 184725.png|q1-index-main-event-count.png"
  "Screenshot 2026-10-14 185157.png|q2-user-account-created-alberto.png"
  "Screenshot 2026-10-14 185134.png|q2-user-account-created-search.png"
  "Screenshot 2026-10-14 185852.png|q2-user-account-created-event-detail.png"
  "Screenshot 2026-10-14 190044.png|q3-sam-registry-key-sysmon.png"
  "Screenshot 2026-10-14 190719.png|q5-wmic-remote-command-4688.png"
  "Screenshot 2026-10-14 185913.png|q5-wmic-process-creation-detail.png"
  "Screenshot 2026-10-14 190836.png|q7-q8-powershell-operational-79-events.png"
  "Screenshot 2026-10-14 192237.png|q9-encoded-script-event.png"
  "Screenshot 2026-10-14 192807.png|q9-encoded-powershell-blob.png"
  "Screenshot 2026-10-14 192755.png|q9-arena-agent-decode.png"
  "Screenshot 2026-10-14 192022.png|q9-answer-format-incorrect.png"
  "Screenshot 2026-10-14 192921.png|summary-room-answers.png"
)

staged=0
missing=0

for entry in "${MAP[@]}"; do
  src="${entry%%|*}"
  dst="images/${entry##*|}"
  if [[ -f "$src" ]]; then
    mv -- "$src" "$dst"
    printf '  staged  %-38s ->  %s\n' "$src" "$dst"
    staged=$((staged + 1))
  else
    printf '  MISSING %s\n' "$src"
    missing=$((missing + 1))
  fi
done

echo
printf 'Staged %d of %d screenshot(s) into images/.\n' "$staged" "${#MAP[@]}"
if (( missing > 0 )); then
  echo 'Copy the missing originals into this directory and re-run the script.'
fi
