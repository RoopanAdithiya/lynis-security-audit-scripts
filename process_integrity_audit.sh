#!/bin/bash
#
# Script 1: Process Integrity Audit
# ----------------------------------
# Purpose:
#   Detect two classic signs of runtime tampering:
#     1. Processes whose backing executable has been DELETED from disk
#        but is still running in memory (common malware/persistence trick:
#        the binary deletes itself after launch so nothing is left for
#        a disk scan to find).
#     2. Processes whose executable is running FROM a temp directory
#        (/tmp, /dev/shm, /var/tmp) — a common location for droppers,
#        since these dirs are usually world-writable.
#
# Output:
#   A plain report for the admin to review. Nothing is killed or judged
#   as malicious automatically — this is detection/reporting only.

echo "==================================================="
echo " Process Integrity Audit"
echo " Run time: $(date)"
echo "==================================================="

# ---------------------------------------------------------
# CHECK 1: Deleted-but-running executables
# ---------------------------------------------------------
# How it works:
#   For every running process, the kernel exposes a symlink at
#   /proc/<PID>/exe pointing to the executable file that was used
#   to start it. If that file has since been deleted, `ls -l` or
#   `readlink` on that symlink shows "(deleted)" appended to the
#   target path. That's the tell-tale sign.

echo ""
echo "[*] Checking for deleted-but-running executables..."
FOUND_DELETED=0

for pid_path in /proc/[0-9]*; do
    pid=$(basename "$pid_path")

    # /proc/<pid>/exe may not be readable (permission) or may vanish
    # between listing and reading (process exited) — suppress errors.
    exe_target=$(readlink -f "$pid_path/exe" 2>/dev/null)
    exe_link=$(readlink "$pid_path/exe" 2>/dev/null)

    # Skip if we couldn't read it at all (kernel threads, permission denied, etc.)
    [ -z "$exe_link" ] && continue

    if [[ "$exe_link" == *"(deleted)"* ]]; then
        FOUND_DELETED=1
        cmdline=$(tr '\0' ' ' < "$pid_path/cmdline" 2>/dev/null)
        echo "  [WARN] PID $pid is running a deleted executable"
        echo "         Original path : $exe_link"
        echo "         Cmdline       : ${cmdline:-<unavailable>}"
        echo "         Owner         : $(ps -o user= -p "$pid" 2>/dev/null)"
    fi
done

if [ "$FOUND_DELETED" -eq 0 ]; then
    echo "  [OK] No processes running from deleted executables."
fi

# ---------------------------------------------------------
# CHECK 2: Processes executing from temp/world-writable dirs
# ---------------------------------------------------------
# How it works:
#   Same /proc/<PID>/exe symlink, but this time we check whether the
#   resolved path lives under a directory typically used for temp
#   files (/tmp, /dev/shm, /var/tmp). Legitimate long-running services
#   almost never execute their main binary from these locations.

echo ""
echo "[*] Checking for processes running from temp directories..."
FOUND_TEMP=0
TEMP_DIRS="^/tmp/|^/dev/shm/|^/var/tmp/"

for pid_path in /proc/[0-9]*; do
    pid=$(basename "$pid_path")
    exe_target=$(readlink -f "$pid_path/exe" 2>/dev/null)

    [ -z "$exe_target" ] && continue

    if echo "$exe_target" | grep -qE "$TEMP_DIRS"; then
        FOUND_TEMP=1
        cmdline=$(tr '\0' ' ' < "$pid_path/cmdline" 2>/dev/null)
        echo "  [WARN] PID $pid is executing from a temp directory"
        echo "         Path    : $exe_target"
        echo "         Cmdline : ${cmdline:-<unavailable>}"
        echo "         Owner   : $(ps -o user= -p "$pid" 2>/dev/null)"
    fi
done

if [ "$FOUND_TEMP" -eq 0 ]; then
    echo "  [OK] No processes running from temp directories."
fi

echo ""
echo "==================================================="
echo " Audit complete. Review any [WARN] lines above."
echo " This script does not kill or block processes —"
echo " findings require manual admin review."
echo "==================================================="
