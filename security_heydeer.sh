#!/bin/bash

# Tool Name: Security HEYDEER
# Credit: Muhammad Ammar
# Description: Advanced Security Header Analyzer with Active User Check

# ANSI Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Security Headers Configuration
security_headers=(
    "content-security-policy"
    "strict-transport-security"
    "x-content-type-options" 
    "x-frame-options"
    "x-xss-protection"
    "referrer-policy"
    "permissions-policy"
    "cross-origin-opener-policy"
    "cross-origin-embedder-policy"
)

declare -A recommendations=(
    ["content-security-policy"]="Implement strong CSP to prevent XSS attacks"
    ["strict-transport-security"]="Enforce HTTPS with proper max-age and preload"
    ["x-content-type-options"]="Set to 'nosniff' to prevent MIME sniffing"
    ["x-frame-options"]="Set to 'DENY' or 'SAMEORIGIN' for clickjacking protection"
    ["x-xss-protection"]="Deprecated - Use CSP instead"
    ["referrer-policy"]="Control referrer information leakage"
    ["permissions-policy"]="Restrict browser features and APIs"
    ["cross-origin-opener-policy"]="Isolate browsing context"
    ["cross-origin-embedder-policy"]="Control cross-origin resource embedding"
)

# Log File
log_file="scan_log.txt"

# Animation Characters
spin_chars=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")

show_banner() {
    clear
    echo -e "${YELLOW}"
    echo "╔═╗╔═╗╔═╗╦ ╦╦═╗╦╔╦╗╦ ╦  ╦ ╦╔═╗╦ ╦╔╦╗╔═╗╔═╗╦═╗"
    echo "╚═╗║╣ ║  ║ ║╠╦╝║ ║ ╚╦╝  ╠═╣║╣ ╚╦╝ ║║║╣ ║╣ ╠╦╝"
    echo "╚═╝╚═╝╚═╝╚═╝╩╚═╩ ╩  ╩   ╩ ╩╚═╝ ╩ ═╩╝╚═╝╚═╝╩╚═"
    echo -e "${NC}"
echo -e "${CYAN}------------------------------------------------------${NC}"
echo -e "${CYAN}    Created by Muhammad Ammar | AMXPRODUCTION      ${NC}"
echo -e "${CYAN}------------------------------------------------------${NC}"
    
}

log_message() {
    local message="$1"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$log_file"
}

show_animation() {
    local pid=$1
    while kill -0 $pid 2>/dev/null; do
        for char in "${spin_chars[@]}"; do
            echo -ne "\r${char} ${BLUE}Analyzing...${NC}  "
            sleep 0.1
        done
    done
    echo -ne "\r${GREEN}✔ Analysis Complete!${NC}          \n"
}

sanitize_filename() {
    local input="$1"
    echo "$input" | sed 's/[^a-zA-Z0-9._-]/_/g'
}

check_active_user() {
    local target="$1"
    echo -e "\n${CYAN}Checking if target is active...${NC}"
    if ping -c 1 "$target" &> /dev/null; then
        echo -e "${GREEN}✔ Target is active!${NC}"
        log_message "Target ${target} is active."
        return 0
    else
        echo -e "${RED}✗ Target is not active!${NC}"
        log_message "Target ${target} is not active."
        return 1
    fi
}

scan_by_ip() {
    echo -e "\n${CYAN}[IP/URL SCAN MODE]${NC}"
    
    # User Input
    while true; do
        read -p "Enter Target IP/Host or URL: " target
        if [[ -z "$target" ]]; then
            echo -e "${RED}Target cannot be empty!${NC}"
        else
            break
        fi
    done

    # Resolve URL to IP if necessary
    if [[ "$target" =~ ^https?:// ]]; then
        target=$(echo "$target" | sed -E 's|^https?://||; s|/.*||')
        ip=$(resolve_url_to_ip "$target")
        if [[ -z "$ip" ]]; then
            return 1
        fi
        target="$ip"
    fi

    while true; do
        read -p "Enter Port (default 443): " port
        port=${port:-443}
        if [[ "$port" =~ ^[0-9]+$ ]]; then
            break
        else
            echo -e "${RED}Invalid port! Please enter a number.${NC}"
        fi
    done

    read -p "Bypass SSL Certificate Validation? (y/n): " bypass_ssl
    read -p "Add Custom Cookies (optional): " cookies

    # Review Details
    echo -e "\n${YELLOW}⚡ Review Your Input:${NC}"
    echo -e "Target: ${GREEN}${target}${NC}"
    echo -e "Port: ${GREEN}${port}${NC}"
    echo -e "Bypass SSL: ${GREEN}${bypass_ssl}${NC}"
    echo -e "Cookies: ${GREEN}${cookies:-None}${NC}"
    
    # Check if target is active
    if ! check_active_user "$target"; then
        echo -e "${RED}✗ Cannot proceed with scan. Target is not active.${NC}"
        return 1
    fi

    read -p "Proceed with Scan? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo -e "${RED}Scan aborted!${NC}"
        log_message "Scan aborted by user."
        return
    fi

    # Prepare CURL Command
    curl_cmd="curl -sI"
    [[ "$bypass_ssl" == "y" ]] && curl_cmd+=" -k"
    [[ -n "$cookies" ]] && curl_cmd+=" -b '${cookies}'"
    curl_cmd+=" https://${target}:${port}"

    # Execute Scan
    echo -e "\n${MAGENTA}⚡ Scanning ${target}:${port}...${NC}"
    sanitized_target=$(sanitize_filename "$target")
    response_file="response_${sanitized_target}_$(date +%s).txt"
    eval "$curl_cmd" > "$response_file" 2>&1
    
    if [ ! -s "$response_file" ]; then
        echo -e "${RED}✗ Connection failed! Check target/port${NC}"
        log_message "Connection failed for ${target}:${port}."
        rm "$response_file" 2>/dev/null
        return 1
    fi
    
    analyze_headers "$response_file"
    rm "$response_file" 2>/dev/null
}

scan_by_certificate() {
    echo -e "\n${CYAN}[CERTIFICATE-BASED SCAN MODE]${NC}"
    
    # User Input
    while true; do
        read -p "Enter Target IP/Host: " target
        if [[ -z "$target" ]]; then
            echo -e "${RED}Target cannot be empty!${NC}"
        else
            break
        fi
    done

    while true; do
        read -p "Enter Port (default 443): " port
        port=${port:-443}
        if [[ "$port" =~ ^[0-9]+$ ]]; then
            break
        else
            echo -e "${RED}Invalid port! Please enter a number.${NC}"
        fi
    done

    while true; do
        read -p "Enter Path to Certificate (PEM/CRT): " cert_file
        if [[ -z "$cert_file" ]]; then
            echo -e "${RED}Certificate path cannot be empty!${NC}"
        elif [ ! -f "$cert_file" ]; then
            echo -e "${RED}Certificate file not found!${NC}"
        else
            break
        fi
    done

    # Review Details
    echo -e "\n${YELLOW}⚡ Review Your Input:${NC}"
    echo -e "Target: ${GREEN}${target}${NC}"
    echo -e "Port: ${GREEN}${port}${NC}"
    echo -e "Certificate: ${GREEN}${cert_file}${NC}"
    
    # Check if target is active
    if ! check_active_user "$target"; then
        echo -e "${RED}✗ Cannot proceed with scan. Target is not active.${NC}"
        return 1
    fi

    read -p "Proceed with Scan? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo -e "${RED}Scan aborted!${NC}"
        log_message "Certificate-based scan aborted by user."
        return
    fi

    # Execute Scan
    echo -e "\n${MAGENTA}⚡ Scanning ${target}:${port} with certificate...${NC}"
    sanitized_target=$(sanitize_filename "$target")
    response_file="response_${sanitized_target}_$(date +%s).txt"
    curl -sI --cert "$cert_file" "https://${target}:${port}" > "$response_file" 2>&1
    
    if [ ! -s "$response_file" ]; then
        echo -e "${RED}✗ Connection failed! Check target/port/certificate${NC}"
        log_message "Certificate-based scan failed for ${target}:${port}."
        rm "$response_file" 2>/dev/null
        return 1
    fi
    
    analyze_headers "$response_file"
    rm "$response_file" 2>/dev/null
}

scan_by_file() {
    echo -e "\n${CYAN}[RESPONSE FILE MODE]${NC}"
    
    while true; do
        read -p "Enter Path to Response File: " response_file
        if [[ -z "$response_file" ]]; then
            echo -e "${RED}File path cannot be empty!${NC}"
        elif [ ! -f "$response_file" ]; then
            echo -e "${RED}File not found!${NC}"
        else
            break
        fi
    done

    analyze_headers "$response_file"
}

analyze_headers() {
    local response_file=$1
    declare -A header_map

    echo -e "\n${GREEN}📊 Analyzing headers from: ${response_file}${NC}"
    log_message "Analyzing headers from: ${response_file}"
    
    # Header parsing
    while IFS= read -r line; do
        if [[ "$line" =~ ^([^:]+): ]]; then
            header_name=$(echo "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')
            header_map["$header_name"]=1
        fi
    done < <(grep -iE '^(HTTP/|[[[:alnum:]-]+:)' "$response_file")

    # Analysis
    echo -e "\n${YELLOW}🔍 Security Header Results:${NC}\n"
    
    for header in "${security_headers[@]}"; do
        if [[ -n "${header_map[$header]}" ]]; then
            echo -e "  ${GREEN}✓ [PRESENT]${NC} ${header}"
            log_message "Header Present: ${header}"
        else
            echo -e "  ${RED}✗ [MISSING]${NC} ${header}"
            echo -e "    ${CYAN}➤ Recommendation: ${recommendations[$header]}${NC}"
            log_message "Header Missing: ${header} - Recommendation: ${recommendations[$header]}"
        fi
    done
    
    show_additional_insights "$response_file"
}

show_additional_insights() {
    local file=$1
    echo -e "\n${YELLOW}📌 Additional Insights:${NC}"
    
    # Server Type
    server_header=$(grep -i '^server:' "$file" | cut -d' ' -f2-)
    [ -n "$server_header" ] && echo -e "${CYAN}• Server Technology: ${server_header}${NC}"
    
    # Cookies
    if grep -qi 'set-cookie' "$file"; then
        echo -e "${RED}• Cookies Detected: Check for Secure/HttpOnly flags${NC}"
        log_message "Cookies Detected: Check for Secure/HttpOnly flags"
    fi
    
    # HTTP Version
    http_ver=$(grep -oP 'HTTP/\d\.\d' "$file" | head -1)
    echo -e "${CYAN}• HTTP Version: ${http_ver:-Not Detected}${NC}"
}

main_menu() {
    show_banner
    echo -e "${MAGENTA}"
    echo "1. Scan by IP/URL"
    echo "2. Scan with Response File"
    echo "3. Certificate-based Scan"
    echo -e "4. Exit${NC}"
    read -p "Choose option (1-4): " main_choice

    case $main_choice in
        1) 
            scan_by_ip
            ;;
        2) 
            scan_by_file
            ;;
        3)
            scan_by_certificate
            ;;
        4)
            echo -e "\n${GREEN}🛡️  Stay Secure!${NC}\n"
            log_message "Tool exited by user."
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option!${NC}"
            ;;
    esac

    read -p $'\nPress any key to continue...' -n1 -s
    main_menu
}

# Initialization
check_deps() {
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}✗ curl is required but not installed!${NC}"
        exit 1
    fi
    if ! command -v nslookup &> /dev/null; then
        echo -e "${RED}✗ nslookup is required but not installed!${NC}"
        exit 1
    fi
    if ! command -v ping &> /dev/null; then
        echo -e "${RED}✗ ping is required but not installed!${NC}"
        exit 1
    fi
}

check_deps
main_menu
