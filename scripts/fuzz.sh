#!/usr/bin/env bash
# Run every Fuzz target in the packages given, for FUZZTIME each.
#
# Go before 1.28 can end a clean -fuzztime run with "--- FAIL ...
# context deadline exceeded" although no input failed
# (https://github.com/golang/go/issues/75804). A run that fails with that
# message and wrote no failing input is reported and treated as a pass;
# any other failure, or one that wrote a failing input, fails the run.
set -uo pipefail

go_cmd=${GO:-go}
fuzztime=${FUZZTIME:-5s}
# Overwritten for each target.
log="${TMPDIR:-/tmp}/go-cotp-fuzz.log"

targets=$("$go_cmd" test -list '^Fuzz' "$@" | grep '^Fuzz') || {
	echo "no Fuzz targets found" >&2
	exit 1
}
for t in $targets; do
	echo "fuzz $t"
	"$go_cmd" test -run '^$' -fuzz "^$t\$" -fuzztime "$fuzztime" "$@" 2>&1 | tee "$log"
	status=${PIPESTATUS[0]}
	[ "$status" -eq 0 ] && continue
	if grep -q 'context deadline exceeded' "$log" && ! grep -q 'Failing input written to' "$log"; then
		echo "fuzz $t: spurious deadline failure at the -fuzztime end (golang/go#75804); no failing input, treated as a pass"
		continue
	fi
	exit "$status"
done
