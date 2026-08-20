#!/usr/bin/env bash
#
# hunt_rare_processes.sh
# Finds statistically rare process names across a fleet by comparing a
# per-host process list against a fleet-wide frequency baseline. Rare
# processes running on very few hosts are worth analyst review — they're
# often either legitimate niche tooling or evidence of a targeted implant.
#
# Usage:
#   ./hunt_rare_processes.sh --input process_export.csv --threshold 2
#
# Expected input CSV format: host,process_name
# (export this from your EDR/SIEM process inventory)

set -euo pipefail

THRESHOLD=2
INPUT=""

usage() {
  echo "Usage: $0 --input <process_export.csv> [--threshold N]"
  echo "  --input      CSV with columns: host,process_name"
  echo "  --threshold  Max number of distinct hosts a process can appear on to be flagged as rare (default: 2)"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input) INPUT="$2"; shift 2 ;;
    --threshold) THRESHOLD="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown argument: $1"; usage ;;
  esac
done

if [[ -z "$INPUT" || ! -f "$INPUT" ]]; then
  echo "Error: --input file not found." >&2
  usage
fi

echo "Analyzing process rarity in: $INPUT (threshold: <= $THRESHOLD hosts)"
echo "-------------------------------------------------------------"

# Skip header, extract process_name column (2), count distinct hosts per process
tail -n +2 "$INPUT" | awk -F',' '{ print $2 }' | sort -u > /tmp/_procs_seen.$$

while read -r proc; do
  [[ -z "$proc" ]] && continue
  host_count=$(tail -n +2 "$INPUT" | awk -F',' -v p="$proc" '$2 == p { print $1 }' | sort -u | wc -l)
  if [[ "$host_count" -le "$THRESHOLD" ]]; then
    hosts=$(tail -n +2 "$INPUT" | awk -F',' -v p="$proc" '$2 == p { print $1 }' | sort -u | tr '\n' ',' | sed 's/,$//')
    printf "[RARE] %-40s hosts=%-3s (%s)\n" "$proc" "$host_count" "$hosts"
  fi
done < /tmp/_procs_seen.$$

rm -f /tmp/_procs_seen.$$
echo "-------------------------------------------------------------"
echo "Done. Rare processes above are candidates for analyst triage — cross-reference against known-good software inventory before escalating."
