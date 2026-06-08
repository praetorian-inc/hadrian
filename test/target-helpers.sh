#!/usr/bin/env bash
# Target-selection helpers for run-live-tests.sh. SOURCE THIS FILE — do not
# execute directly.

# targets_contains <name> — exact comma-delimited membership test on $TARGETS.
# Avoids the substring pitfall of `grep -q "crapi"` (which also matches
# "crapi-planner"); the crapi → crapi-planner prerequisite coupling is made
# explicit at each call site instead of relying on a silent substring match.
# Reads the global $TARGETS (set from --targets) so call sites stay terse.
targets_contains() { case ",${TARGETS:-}," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }
