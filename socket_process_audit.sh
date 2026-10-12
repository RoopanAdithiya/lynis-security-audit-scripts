#!/bin/bash
#
# Script 2: Socket-to-Process Correlation Audit
# -----------------------------------------------
# Purpose:
#   Reverse shells work by getting an interpreter (bash, sh, python,
#   perl, nc, socat, etc.) to hold open a live network socket instead
#   of just talking to a terminal. A normal system rarely has "bash"
#   itself owning a TCP connection — that pattern is unusual enough
#   to be worth flagging.
#
#   This script:
#     1. Lists active network connections and the PID that owns each
#        socket (via `ss -tnp`, which is the modern replacement for
#        `netstat`).
#     2. Looks up what binary/command each of those PIDs actually is.
#     3. Flags any match against a watchlist of shell/interpreter
#        binaries.
#
# Output:
#   Warnings only, for admin review — no automated killing.

echo "==================================================="
echo " Socket-to-Process Correlation Audit"
echo " Run time: $(date)"
echo "==================================================="

# Binaries we consider "interesting" if they hold a live socket.
# Extend this list as needed for your environment.
WATCHLIST="bash|sh|dash|zsh|ksh|python|python3|perl|ruby|php|socat|nc|ncat|netcat"

if ! command -v ss >/dev/null 2>&1; then
    echo "[!] 'ss' command not found. Please install iproute2."
    exit 1
fi

echo ""
echo "[*] Correlating active sockets with process names..."
echo ""

FOUND=0

# -tnp : TCP sockets, numeric (no DNS lookups, faster & avoids hangs), show process
# We skip the header line with `tail -n +2`.
ss -tnp 2>/dev/null | tail -n +2 | while read -r line; do

    # ss -tnp output looks like:
    # State   Recv-Q Send-Q Local:Port   Peer:Port   users:(("python3",pid=1234,fd=5))
    # We only care about lines that actually have a process attached.
    [[ "$line" != *"users:(("* ]] && continue

    local_addr=$(echo "$line" | awk '{print $4}')
    peer_addr=$(echo "$line"  | awk '{print $5}')
    state=$(echo "$line"      | awk '{print $1}')

    # Extract PID from the users:(("progname",pid=1234,fd=5)) chunk
    pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+' | head -n1)
    proc_name=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+')

    [ -z "$pid" ] && continue

    # Cross-check against watchlist using the actual /proc/<pid>/comm
    # (more reliable than the truncated name ss sometimes reports).
    real_comm=$(cat "/proc/$pid/comm" 2>/dev/null)
    check_name="${real_comm:-$proc_name}"

    if echo "$check_name" | grep -qwE "$WATCHLIST"; then
        FOUND=1
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
        owner=$(ps -o user= -p "$pid" 2>/dev/null)

        echo "  [WARN] Interpreter/shell process holding a network socket"
        echo "         Process   : $check_name (PID $pid)"
        echo "         Owner     : ${owner:-unknown}"
        echo "         State     : $state"
        echo "         Local     : $local_addr"
        echo "         Peer      : $peer_addr"
        echo "         Cmdline   : ${cmdline:-<unavailable>}"
        echo ""
    fi
done

# Note: the while-loop above runs in a subshell (because of the pipe),
# so FOUND=1 set inside it won't be visible out here. That's fine for
# this script since we print warnings as we find them; see the
# explanation notes for why this matters if you want a summary count.

echo "==================================================="
echo " Audit complete. Review any [WARN] lines above."
echo " A flagged process is not automatically malicious —"
echo " e.g. an SSH session running bash is normal. Context"
echo " (owner, peer IP, expected behavior) matters."
echo "==================================================="
