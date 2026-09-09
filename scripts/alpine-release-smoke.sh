#!/bin/sh
set -eu
/app/RegIns.Cli validate /fixtures/SYSTEM
/app/RegIns.Cli recover /fixtures/SYSTEM --out /tmp/release-plan.json
/app/RegIns.Cli export /tmp/release-plan.json --out /tmp/release-hive
/app/RegIns.Cli validate /tmp/release-hive
set +e
DISPLAY=:97 timeout 8 /app/RegIns.Gui >/tmp/release-gui.log 2>&1
result=$?
set -e
cat /tmp/release-gui.log
echo "GUI timeout status: $result"
# BusyBox timeout terminates a healthy long-running application with SIGTERM.
test "$result" -eq 143 -o "$result" -eq 124
