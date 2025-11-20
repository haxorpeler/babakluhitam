#!/bin/bash
# Detects: Suspicious env vars

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo -e "${GREEN}[*] Starting environment-based backdoor scan...${NC}\n"

# Kalo nemu pattern lain add aja disini:D
# Cara cari gimana bang? cat /proc/*/environ
PATTERNS=(
    "GS_ARGS"
    "GS_PROC"
    "GS_FS_EXENAME"
    "GS_HIDDEN_NAME"
    "GS_GS_NOCERTCHECK"
    "HISTFILE=/dev/null"
    "LD_PRELOAD"
    "SOCAT"
    "NETCAT"
    "REVERSE_SHELL"
)

SUSPICIOUS_PATHS=(
    "/tmp/"
    "/dev/shm/"
    "/var/tmp/"
    "\.config/.*\.dat"
    "\.gsocket"
    "\.ssh.*id_rsa"
)

read_environ() {
    local pid=$1
    if [ -r "/proc/$pid/environ" ]; then
        cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n'
    fi
}

get_process_info() {
    local pid=$1
    local user=$(stat -c %U /proc/$pid 2>/dev/null)
    local cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
    local ppid=$(awk '{print $4}' /proc/$pid/stat 2>/dev/null)
    local exe=$(readlink /proc/$pid/exe 2>/dev/null)
    
    echo "user=$user|cmdline=$cmdline|ppid=$ppid|exe=$exe"
}

FOUND=0
for pid in /proc/[0-9]*; do
    pid=$(basename "$pid")
    
    [ ! -r "/proc/$pid/environ" ] && continue
    
    environ_content=$(read_environ "$pid")
    [ -z "$environ_content" ] && continue
    
    for pattern in "${PATTERNS[@]}"; do
        if echo "$environ_content" | grep -q "$pattern"; then
            FOUND=1
            info=$(get_process_info "$pid")
            
            echo -e "${RED}[!] ALERT: Suspicious pattern detected${NC}"
            echo "    Pattern: $pattern"
            echo "    PID: $pid"
            echo "    User: $(echo $info | cut -d'|' -f1 | cut -d'=' -f2)"
            echo "    Command: $(echo $info | cut -d'|' -f2 | cut -d'=' -f2)"
            echo "    PPID: $(echo $info | cut -d'|' -f3 | cut -d'=' -f2)"
            echo "    Binary: $(echo $info | cut -d'|' -f4 | cut -d'=' -f2)"
            
            echo "    Full Environment Variable:"
            echo "$environ_content" | grep "$pattern" | sed 's/^/      /'
            
            connections=$(lsof -p "$pid" -n -P 2>/dev/null | grep -E 'ESTABLISHED|LISTEN' | grep -v '127.0.0.1')
            if [ -n "$connections" ]; then
                echo -e "    ${YELLOW}Network Connections:${NC}"
                echo "$connections" | sed 's/^/      /'
            fi
            
            echo ""
        fi
    done

    for sus_path in "${SUSPICIOUS_PATHS[@]}"; do
        if echo "$environ_content" | grep -qE "$sus_path"; then
            FOUND=1
            info=$(get_process_info "$pid")
            
            echo -e "${YELLOW}[!] WARNING: Suspicious path in environment${NC}"
            echo "    Path Pattern: $sus_path"
            echo "    PID: $pid"
            echo "    User: $(echo $info | cut -d'|' -f1 | cut -d'=' -f2)"
            echo "    Command: $(echo $info | cut -d'|' -f2 | cut -d'=' -f2)"
            echo "    Matching Lines:"
            echo "$environ_content" | grep -E "$sus_path" | sed 's/^/      /'
            echo ""
        fi
    done
done

echo -e "${GREEN}=== SCAN COMPLETE ===${NC}"
if [ $FOUND -eq 0 ]; then
    echo -e "${GREEN}No suspicious environment variables detected.${NC}"
else
    echo -e "${RED}Suspicious processes found! Review above output.${NC}"
fi

read -p "Kill detected processes? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Executing kill commands..."
    for pid in /proc/[0-9]*; do
        pid=$(basename "$pid")
        environ_content=$(read_environ "$pid")
        for pattern in "${PATTERNS[@]}"; do
            if echo "$environ_content" | grep -q "$pattern"; then
                echo "Killing PID $pid..."
                kill -9 "$pid" 2>/dev/null && echo "  [âœ“] Killed" || echo "  [âœ—] Failed"
            fi
        done
    done
fi
