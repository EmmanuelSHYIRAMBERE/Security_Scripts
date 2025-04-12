#!/bin/bash

################################################################################
#                      WINDOWS FORENSICS | PROJECT: ANALYZER                   #
#                            Program Code: NX212                               #
#                                                                              #
# Author: EMMANUEL SHYIRAMBERE                                                 #
# Class Code: RW-University-II.s7                                              #
# Lecturer: Mr. DOMINIC HARELIMANA                                             #
#                                                                              #
################################################################################
#                                REFERENCES                                     #
################################################################################
#                                                                              #
# 1. Volatility Documentation:                                                 #
#    - https://github.com/volatilityfoundation/volatility/wiki/command-reference                #
#    - Used for memory analysis implementation                                 #
#                                                                              #
# 2. Bulk Extractor Documentation:                                             #
#    - https://github.com/simsong/bulk_extractor/wiki                        #
#    - Used for carving sensitive information                                  #
#                                                                              #
# 3. Foremost Documentation:                                                   #
#    - https://github.com/korczis/foremost                                    #
#    - Used for file carving techniques                                        #
#                                                                              #
# 4. Binwalk Documentation:                                                    #
#    - https://github.com/ReFirmLabs/binwalk                                  #
#    - Used for firmware analysis and file extraction                          #
#                                                                              #
# 5. Shell Scripting Best Practices:                                           #
#    - Advanced Bash-Scripting Guide by Mendel Cooper                          #
#    - https://tldp.org/LDP/abs/html/                                          #
#    - Used for shell scripting patterns and practices                         #
#                                                                              #
################################################################################


# Color definitions for better output readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Global variables
START_TIME=$(date +%s)
OUTPUT_DIR=""
FULL_OUTPUT_PATH=""
REPORT_FILE=""
ANALYSIS_LOG=""
FILENAME=""
FILE_TYPE=""
VOLATILITY_PROFILE=""
FOUND_FILES_COUNT=0
EXTRACTION_SUMMARY=()
KEEP_RUNNING=true
CURRENT_OS=""

# Function to detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)     echo "Linux";;
        Darwin*)    echo "Mac";;
        CYGWIN*|MINGW*|MSYS*) echo "Windows";;
        *)          echo "Unknown"
    esac
}

# Function to display banner
display_banner() {
    clear
    echo -e "${BLUE}${BOLD}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                 WINDOWS FORENSICS - ANALYZER                   ║"
    echo "║                     Program Code: NX212                        ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}[*] Running on: ${CURRENT_OS}${NC}"
}

# Function to check if running as root
check_root() {
    echo -e "${YELLOW}[*] Checking if running as root...${NC}"
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] Error: This script must be run as root${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] Running as root. Continuing...${NC}"
}

# Function to check for volatility
check_volatility() {
    # First check for volatility
    if command -v volatility &>/dev/null; then
        return 0
    elif python3 -m volatility --help &>/dev/null; then
        return 0
    # Then check for volatility 2.6 in current directory
    elif [ -f "./volatility_2.6_lin64_standalone/volatility" ]; then
        return 0
    else
        return 1
    fi
}

# Function to locate volatility installation
locate_volatility() {
    echo -e "${YELLOW}[*] Searching for volatility installation...${NC}"
    
    # First check current directory for volatility 2.6
    if [ -f "./volatility_2.6_lin64_standalone/volatility" ]; then
        echo -e "${GREEN}[+] Found volatility 2.6 in current directory${NC}"
        export PATH="./volatility_2.6_lin64_standalone:$PATH"
        return 0
    fi
    
    # Check common installation paths
    local paths=(
        "/usr/local/bin/volatility"
        "/usr/bin/volatility"
        "/opt/volatility/vol.py"
        "$HOME/.local/bin/volatility"
        "$HOME/volatility/vol.py"
    )
    
    for path in "${paths[@]}"; do
        if [ -f "$path" ]; then
            echo -e "${GREEN}[+] Found volatility at: $path${NC}"
            export PATH="$(dirname "$path"):$PATH"
            return 0
        fi
    done
    
    # Check Python module installation
    if python3 -c "import volatility; print(volatility.__file__)" &>/dev/null; then
        local vol_path=$(python3 -c "import volatility; print(volatility.__file__)")
        echo -e "${GREEN}[+] Found volatility Python module at: $vol_path${NC}"
        export PATH="$(dirname "$vol_path"):$PATH"
        return 0
    fi
    
    return 1
}

# Function to install volatility with wget option
install_volatility() {
    echo -e "${YELLOW}[*] Installing volatility...${NC}"
    
    # Try different installation methods
    local success=false
    
    # Method 1: Download volatility 2.6 standalone with wget
	echo -e "${BLUE}[i] Trying to download volatility 2.6 standalone...${NC}"
	if command -v wget &>/dev/null; then
		echo -e "${YELLOW}[*] Downloading volatility 2.6...${NC}"
		wget https://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip
		if [ $? -eq 0 ]; then
			echo -e "${GREEN}[+] Download complete, extracting...${NC}"
			unzip volatility_2.6_lin64_standalone.zip
			if [ $? -eq 0 ]; then
				# Correct the executable name and path
				chmod +x volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone
				# Rename to simpler volatility executable
				mv volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone volatility_2.6_lin64_standalone/volatility
				export PATH="./volatility_2.6_lin64_standalone:$PATH"
				echo -e "${GREEN}[+] volatility 2.6 installed successfully in current directory${NC}"
				success=true
			else
				echo -e "${RED}[!] Failed to unzip volatility package${NC}"
			fi
		else
			echo -e "${RED}[!] Failed to download volatility package${NC}"
		fi
	else
		echo -e "${RED}[!] wget not available to download volatility${NC}"
	fi
    
    # Only try other methods if wget method failed
    if ! $success; then
        # Method 2: pipx
        if command -v pipx &>/dev/null; then
            echo -e "${BLUE}[i] Trying pipx installation...${NC}"
            if pipx install volatility; then
                export PATH="$HOME/.local/bin:$PATH"
                success=true
            fi
        fi
        
        # Method 3: pip
        if ! $success && command -v pip3 &>/dev/null; then
            echo -e "${BLUE}[i] Trying pip installation...${NC}"
            if pip3 install --user volatility; then
                export PATH="$HOME/.local/bin:$PATH"
                success=true
            fi
        fi
        
        # Method 4: System package manager
        if ! $success && command -v apt-get &>/dev/null; then
            echo -e "${BLUE}[i] Trying apt installation...${NC}"
            if apt-get install -y volatility; then
                success=true
            fi
        fi
        
        # Method 5: Clone from GitHub
        if ! $success && command -v git &>/dev/null; then
            echo -e "${BLUE}[i] Trying GitHub installation...${NC}"
            git clone https://github.com/volatilityfoundation/volatility.git /opt/volatility
            if [ -f "/opt/volatility/vol.py" ]; then
                chmod +x /opt/volatility/vol.py
                ln -s /opt/volatility/vol.py /usr/local/bin/volatility
                export PATH="/opt/volatility:$PATH"
                success=true
            fi
        fi
    fi
    
    if $success; then
        echo -e "${GREEN}[+] volatility installed successfully${NC}"
        return 0
    else
        echo -e "${RED}[!] Failed to install volatility${NC}"
        return 1
    fi
}

# Enhanced volatility handler with file browser
handle_volatility() {
    # First check if it's already available
    if check_volatility; then
        echo -e "${GREEN}[+] volatility is already installed${NC}"
        return 0
    fi
    
    # Try to locate existing installation
    if locate_volatility; then
        return 0
    fi

    while true; do
        echo -e "${YELLOW}[!] volatility not found${NC}"
        echo -e "${CYAN}Please choose an option:${NC}"
        echo -e "  ${GREEN}1${NC}) Install volatility automatically"
        echo -e "  ${GREEN}2${NC}) Browse to locate volatility manually"
        echo -e "  ${GREEN}3${NC}) Enter path to volatility manually"
        echo -e "  ${GREEN}4${NC}) Continue without volatility"
        
        read -p "Your choice (1-4): " choice
        
        case $choice in
            1)
                if install_volatility; then
                    return 0
                else
                    echo -e "${RED}[!] Automatic installation failed${NC}"
                fi
                ;;
            2)
                echo -e "${YELLOW}[*] Launching file browser...${NC}"
                if browse_for_volatility; then
                    return 0
                else
                    echo -e "${YELLOW}[*] File browser exited without selection${NC}"
                fi
                ;;
            3)
                read -e -p "Enter full path to volatility: " vol_path
                if [ -f "$vol_path" ] || [ -d "$vol_path" ]; then
                    echo "export PATH=\"$(dirname "$vol_path"):\$PATH\"" >> ~/.bashrc
                    source ~/.bashrc
                    echo -e "${GREEN}[+] Added to PATH${NC}"
                    return 0
                else
                    echo -e "${RED}[!] Invalid path${NC}"
                fi
                ;;
            4)
                echo -e "${YELLOW}[*] Continuing without volatility${NC}"
                return 1
                ;;
            *)
                echo -e "${RED}[!] Invalid choice${NC}"
                ;;
        esac
    done
}

# Enhanced file browser for locating volatility
browse_for_volatility() {
    local current_dir=$(pwd)
    local selected_path=""
    
    while true; do
        clear
        echo -e "${BLUE}${BOLD}╔════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}${BOLD}║               LOCATE VOLATILITY INSTALLATION                   ║${NC}"
        echo -e "${BLUE}${BOLD}╚════════════════════════════════════════════════════════════════╝${NC}"
        echo -e "${YELLOW}Current directory: ${current_dir}${NC}"
        
        # List contents
        echo -e "${CYAN}Directories:${NC}"
        local dirs=()
        local files=()
        local counter=1
        
        # Get directories and files
        while IFS= read -r item; do
            if [ -d "${current_dir}/${item}" ]; then
                dirs+=("$item")
                echo -e "${BOLD}${BLUE}[$counter]${NC} ${PURPLE}$item/${NC}"
                counter=$((counter + 1))
            elif [ -f "${current_dir}/${item}" ]; then
                files+=("$item")
            fi
        done < <(ls -A "$current_dir" 2>/dev/null)
        
        # List files that might be volatility
        echo -e "${CYAN}\nPotential volatility files:${NC}"
        local vol_files=($(ls -A "$current_dir" | grep -i "volatility"))
        local vol_counter=1
        for file in "${vol_files[@]}"; do
            if [ -f "${current_dir}/${file}" ]; then
                echo -e "${BOLD}${GREEN}[f${vol_counter}]${NC} ${file}"
                vol_counter=$((vol_counter + 1))
            fi
        done
        
        # Options
        echo -e "${CYAN}\nNavigation options:${NC}"
        echo -e "${BOLD}${BLUE}[0]${NC} Go up one directory"
        echo -e "${BOLD}${BLUE}[p]${NC} Print current path"
        echo -e "${BOLD}${BLUE}[s]${NC} Select current directory"
        echo -e "${BOLD}${BLUE}[q]${NC} Quit browser"
        
        read -p "Enter your choice (number, f#, or option): " choice
        
        case $choice in
            0)
                current_dir=$(dirname "$current_dir")
                ;;
            [pP])
                echo -e "${YELLOW}Current path: $current_dir${NC}"
                sleep 1
                ;;
            [sS])
                if [ -d "${current_dir}/volatility" ]; then
                    selected_path="${current_dir}/volatility"
                elif ls "${current_dir}" | grep -q -i "volatility"; then
                    selected_path="${current_dir}/$(ls "${current_dir}" | grep -i "volatility" | head -1)"
                else
                    echo -e "${RED}No volatility found in this directory${NC}"
                    sleep 1
                    continue
                fi
                ;;
            [qQ])
                return 1
                ;;
            f*)
                index=${choice#f}
                if [ -n "$index" ] && [ "$index" -gt 0 ] && [ "$index" -le "${#vol_files[@]}" ]; then
                    selected_path="${current_dir}/${vol_files[$((index-1))]}"
                else
                    echo -e "${RED}Invalid selection${NC}"
                    sleep 1
                    continue
                fi
                ;;
            *)
                if [[ $choice =~ ^[0-9]+$ ]] && [ "$choice" -gt 0 ] && [ "$choice" -le "${#dirs[@]}" ]; then
                    current_dir="${current_dir}/${dirs[$((choice-1))]}"
                else
                    echo -e "${RED}Invalid selection${NC}"
                    sleep 1
                    continue
                fi
                ;;
        esac
        
        if [ -n "$selected_path" ]; then
            if [ -f "$selected_path" ] || [ -d "$selected_path" ]; then
                echo -e "${GREEN}Selected: $selected_path${NC}"
                read -p "Is this correct? (y/n): " confirm
                if [[ "$confirm" =~ [yY] ]]; then
                    echo "export PATH=\"$(dirname "$selected_path"):\$PATH\"" >> ~/.bashrc
                    source ~/.bashrc
                    echo -e "${GREEN}[+] Added to PATH${NC}"
                    return 0
                else
                    selected_path=""
                fi
            else
                echo -e "${RED}Invalid selection${NC}"
                selected_path=""
                sleep 1
            fi
        fi
    done
}

# Function to install required tools
install_tools() {
    echo -e "${YELLOW}[*] Checking required forensic tools for ${CURRENT_OS}...${NC}"
    
    # Common tools
    TOOLS=("bulk_extractor" "binwalk" "foremost" "strings")
    
    # OS-specific additions
    case "$CURRENT_OS" in
        Linux|Mac)
            TOOLS+=("volatility")
            ;;
        Windows)
            TOOLS+=("volatility")  # Different name on Windows
            ;;
    esac
    
    MISSING_TOOLS=()
    
    # Check each tool
    for TOOL in "${TOOLS[@]}"; do
        if [[ "$TOOL" == "volatility" ]]; then
            if ! handle_volatility; then
                MISSING_TOOLS+=("$TOOL")
            fi
        elif ! command -v "$TOOL" &> /dev/null; then
            echo -e "${YELLOW}[-] $TOOL is not installed${NC}"
            MISSING_TOOLS+=("$TOOL")
        else
            echo -e "${GREEN}[+] $TOOL is available${NC}"
        fi
    done
    
    # Install missing tools (excluding volatility which was handled separately)
    MISSING_TOOLS=("${MISSING_TOOLS[@]/volatility}")
    if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
        echo -e "${YELLOW}[*] Installing missing tools...${NC}"
        
        case "$CURRENT_OS" in
            Linux)
                if command -v apt-get &> /dev/null; then
                    apt-get update
                    for TOOL in "${MISSING_TOOLS[@]}"; do
                        case "$TOOL" in
                            "bulk_extractor")
                                apt-get install -y bulk-extractor
                                ;;
                            *)
                                apt-get install -y "$TOOL"
                                ;;
                        esac
                    done
                elif command -v yum &> /dev/null; then
                    yum update -y
                    for TOOL in "${MISSING_TOOLS[@]}"; do
                        case "$TOOL" in
                            "bulk_extractor")
                                yum install -y bulk-extractor
                                ;;
                            *)
                                yum install -y "$TOOL"
                                ;;
                        esac
                    done
                else
                    echo -e "${RED}[!] Cannot determine package manager. Please install tools manually.${NC}"
                    return 1
                fi
                ;;
            Mac)
                if ! command -v brew &> /dev/null; then
                    echo -e "${RED}[!] Homebrew required for Mac installations${NC}"
                    return 1
                fi
                brew update
                for TOOL in "${MISSING_TOOLS[@]}"; do
                    case "$TOOL" in
                        "bulk_extractor")
                            brew install bulk-extractor
                            ;;
                        *)
                            brew install "$TOOL"
                            ;;
                    esac
                done
                ;;
            Windows)
                if command -v choco &> /dev/null; then
                    for TOOL in "${MISSING_TOOLS[@]}"; do
                        case "$TOOL" in
                            "volatility")
                                choco install volatility
                                ;;
                            "bulk_extractor")
                                choco install bulk-extractor
                                ;;
                            *)
                                choco install "$TOOL"
                                ;;
                        esac
                    done
                else
                    echo -e "${RED}[!] Chocolatey required for Windows installations${NC}"
                    return 1
                fi
                ;;
            *)
                echo -e "${RED}[!] Unsupported OS. Please install tools manually.${NC}"
                return 1
                ;;
        esac
        
        # Verify installations
        for TOOL in "${MISSING_TOOLS[@]}"; do
            if ! command -v "$TOOL" &> /dev/null; then
                echo -e "${RED}[!] $TOOL installation failed${NC}"
                return 1
            fi
        done
        
        echo -e "${GREEN}[+] Installation completed${NC}"
    else
        echo -e "${GREEN}[+] All required tools are installed${NC}"
    fi
    
    return 0
}

# Function to display a simple file browser
browse_files() {
    local current_dir=$(pwd)
    local selected_file=""
    
    while [ -z "$selected_file" ]; do
        clear
        echo -e "${BLUE}${BOLD}╔════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}${BOLD}║                      FILE BROWSER                              ║${NC}"
        echo -e "${BLUE}${BOLD}╚════════════════════════════════════════════════════════════════╝${NC}"
        echo -e "${YELLOW}Current location: ${current_dir}${NC}\n"
        
        # Get list of directories and files
        local dirs=()
        local files=()
        
        # Find directories and files in current location
        while IFS= read -r item; do
            if [ -d "$current_dir/$item" ]; then
                dirs+=("$item")
            elif [ -f "$current_dir/$item" ]; then
                files+=("$item")
            fi
        done < <(ls -A "$current_dir" 2>/dev/null | sort)
        
        # Display navigation options
        echo -e "${CYAN}============== NAVIGATION OPTIONS ==============${NC}"
        echo -e "${BOLD}${BLUE}[0]${NC} ${PURPLE}../${NC} (Go up one directory)"
        echo -e "${BOLD}${BLUE}[b]${NC} Enter path manually"
        echo -e "${BOLD}${BLUE}[q]${NC} Quit browser\n"
        
        # Display directories
        if [ ${#dirs[@]} -gt 0 ]; then
            echo -e "${CYAN}================= DIRECTORIES ================${NC}"
            local dir_counter=1
            for dir in "${dirs[@]}"; do
                echo -e "${BOLD}${BLUE}[$dir_counter]${NC} ${PURPLE}$dir/${NC}"
                dir_counter=$((dir_counter + 1))
            done
            echo ""
        fi
        
        # Display files with size and type information
        if [ ${#files[@]} -gt 0 ]; then
            echo -e "${CYAN}=================== FILES ===================${NC}"
            local file_counter=$dir_counter
            for file in "${files[@]}"; do
                local size=$(du -h "$current_dir/$file" 2>/dev/null | cut -f1)
                local file_type=$(file -b "$current_dir/$file" 2>/dev/null | cut -d ',' -f1)
                echo -e "${BOLD}${BLUE}[$file_counter]${NC} ${GREEN}$file${NC} ${YELLOW}($size)${NC} - ${CYAN}$file_type${NC}"
                file_counter=$((file_counter + 1))
            done
            echo ""
        fi
        
        # Display total count summary
        echo -e "${YELLOW}Found: ${#dirs[@]} directories and ${#files[@]} files in current location${NC}"
        echo -e "${CYAN}=================================================${NC}"
        
        # Get user selection
        read -p "Enter your choice (number, 'b', '0', or 'q'): " choice
        
        # Process user selection
        if [[ "$choice" == "q" ]]; then
            echo -e "${RED}Exiting file browser.${NC}"
            return 1
        elif [[ "$choice" == "b" ]]; then
            echo -e "${YELLOW}Enter absolute file path:${NC}"
            read -e abs_path
            if [ -f "$abs_path" ]; then
                FILENAME="$abs_path"
                echo -e "${GREEN}Selected file: $FILENAME${NC}"
                return 0
            elif [ -d "$abs_path" ]; then
                current_dir="$abs_path"
                continue
            else
                echo -e "${RED}Invalid path. Press Enter to continue...${NC}"
                read
            fi
        elif [[ "$choice" == "0" ]]; then
            # Navigate to parent directory
            current_dir=$(dirname "$current_dir")
        elif [[ "$choice" =~ ^[0-9]+$ ]]; then
            local choice_num=$choice
            
            # Check if user selected a directory
            if [ "$choice_num" -ge 1 ] && [ "$choice_num" -lt "$dir_counter" ]; then
                local dir_index=$((choice_num - 1))
                current_dir="$current_dir/${dirs[$dir_index]}"
            # Check if user selected a file
            elif [ "$choice_num" -ge "$dir_counter" ] && [ "$choice_num" -lt "$file_counter" ]; then
                local file_index=$((choice_num - dir_counter))
                selected_file="$current_dir/${files[$file_index]}"
                FILENAME="$selected_file"
                echo -e "${GREEN}Selected file: $FILENAME${NC}"
                sleep 1
                return 0
            else
                echo -e "${RED}Invalid selection. Press Enter to continue...${NC}"
                read
            fi
        else
            echo -e "${RED}Invalid input. Press Enter to continue...${NC}"
            read
        fi
    done
    
    return 0
}

# Function to get file or folder from user
get_file_or_folder() {
    echo -e "${YELLOW}[*] How would you like to select the file or folder to analyze?${NC}"
    echo -e "    ${BLUE}1.${NC} Browse files interactively (recommended)"
    echo -e "    ${BLUE}2.${NC} Enter file/folder path manually"
    read -p "Enter your choice (1-2): " choice
    
    case "$choice" in
        1)
            echo -e "${YELLOW}[*] Launching file browser...${NC}"
            if ! browse_files; then
                echo -e "${YELLOW}[*] File browser exited. Please enter file/folder path manually:${NC}"
                read -e -p "File/Folder path: " FILENAME
            fi
            ;;
        2)
            echo -e "${YELLOW}[*] Please specify the file or folder to analyze:${NC}"
            read -e -p "File/Folder path: " FILENAME
            ;;
        *)
            echo -e "${RED}[!] Invalid choice. Defaulting to manual entry.${NC}"
            echo -e "${YELLOW}[*] Please specify the file or folder to analyze:${NC}"
            read -e -p "File/Folder path: " FILENAME
            ;;
    esac
    
    # Check if file or folder exists
    if [ ! -e "$FILENAME" ]; then
        echo -e "${RED}[!] Error: File/Folder '$FILENAME' does not exist${NC}"
        return 1
    fi
    
    # Check if file or folder is readable
    if [ ! -r "$FILENAME" ]; then
        echo -e "${RED}[!] Error: File/Folder '$FILENAME' is not readable${NC}"
        return 1
    fi
    
    echo -e "${GREEN}[+] File/Folder '$FILENAME' exists and is readable${NC}"
    
    # Determine if it's a file or folder
    if [ -f "$FILENAME" ]; then
        FILE_TYPE=$(file -b "$FILENAME")
        echo -e "${BLUE}[i] File type: $FILE_TYPE${NC}"
    elif [ -d "$FILENAME" ]; then
        echo -e "${BLUE}[i] Selected item is a folder${NC}"
    fi
    
    # Create output directory using timestamp
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    BASENAME=$(basename "$FILENAME")
    
    # Create output directory with full path
    CURRENT_DIR=$(pwd)
    OUTPUT_DIR="forensic_analysis_${BASENAME}_${TIMESTAMP}"
    FULL_OUTPUT_PATH="$CURRENT_DIR/$OUTPUT_DIR"
    
    # Create output directory structure
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR/carved_files"
    mkdir -p "$OUTPUT_DIR/volatility_output"
    mkdir -p "$OUTPUT_DIR/bulk_extractor"
    mkdir -p "$OUTPUT_DIR/strings"
    
    # Create report and log files
    REPORT_FILE="$OUTPUT_DIR/analysis_report.txt"
    ANALYSIS_LOG="$OUTPUT_DIR/analysis.log"
    
    # Write report header
    echo "=============================================================" > "$REPORT_FILE"
    echo "            WINDOWS FORENSICS ANALYSIS REPORT                " >> "$REPORT_FILE"
    echo "=============================================================" >> "$REPORT_FILE"
    echo "Analysis Date: $(date)" >> "$REPORT_FILE"
    echo "File/Folder Analyzed: $FILENAME" >> "$REPORT_FILE"
    echo "File Type: $FILE_TYPE" >> "$REPORT_FILE"
    echo "Output Directory: $FULL_OUTPUT_PATH" >> "$REPORT_FILE"
    echo "=============================================================" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    return 0
}

# Function to extract data with different carvers
carve_data() {
    echo -e "${YELLOW}[*] Starting data carving processes...${NC}"
    
    # 1. First run binwalk to identify file signatures
    echo -e "${BLUE}[i] Running binwalk to identify file signatures...${NC}"
    binwalk "$FILENAME" > "$OUTPUT_DIR/binwalk_analysis.txt"
    echo -e "${GREEN}[+] Binwalk analysis complete${NC}"
    
    # 2. Use foremost to carve files
    echo -e "${BLUE}[i] Running foremost to carve files...${NC}"
    foremost -i "$FILENAME" -o "$OUTPUT_DIR/carved_files/foremost" >> "$ANALYSIS_LOG" 2>&1
    FOREMOST_COUNT=$(find "$OUTPUT_DIR/carved_files/foremost" -type f | wc -l)
    FOUND_FILES_COUNT=$((FOUND_FILES_COUNT + FOREMOST_COUNT))
    EXTRACTION_SUMMARY+=("Foremost: $FOREMOST_COUNT files")
    echo -e "${GREEN}[+] Foremost extracted $FOREMOST_COUNT files${NC}"

    # 3. Use bulk_extractor for sensitive information
    echo -e "${BLUE}[i] Running bulk_extractor to extract sensitive information...${NC}"
    bulk_extractor -o "$OUTPUT_DIR/bulk_extractor" "$FILENAME" >> "$ANALYSIS_LOG" 2>&1
    BULK_COUNT=$(find "$OUTPUT_DIR/bulk_extractor" -type f -name "*.txt" | wc -l)
    EXTRACTION_SUMMARY+=("Bulk Extractor: $BULK_COUNT text files")
    echo -e "${GREEN}[+] Bulk_extractor created $BULK_COUNT output files${NC}"

    # 4. Extract strings for human-readable content
    echo -e "${BLUE}[i] Extracting human-readable strings...${NC}"
    strings "$FILENAME" > "$OUTPUT_DIR/strings/all_strings.txt"

    # 5. Look for specific patterns (passwords, emails, etc.)
    echo -e "${BLUE}[i] Looking for specific patterns in strings...${NC}"

    # Extract potential passwords (patterns like "pass=", "password:", etc.)
    grep -i "pass\|pwd\|password" "$OUTPUT_DIR/strings/all_strings.txt" > "$OUTPUT_DIR/strings/possible_passwords.txt"
    PASSWORD_COUNT=$(wc -l < "$OUTPUT_DIR/strings/possible_passwords.txt")
    EXTRACTION_SUMMARY+=("Possible Passwords: $PASSWORD_COUNT entries")

    # Extract potential usernames
    grep -i "user\|username\|login" "$OUTPUT_DIR/strings/all_strings.txt" > "$OUTPUT_DIR/strings/possible_usernames.txt"
    USERNAME_COUNT=$(wc -l < "$OUTPUT_DIR/strings/possible_usernames.txt")
    EXTRACTION_SUMMARY+=("Possible Usernames: $USERNAME_COUNT entries")

    # Extract potential URLs
    grep -i "http\|https\|www\." "$OUTPUT_DIR/strings/all_strings.txt" > "$OUTPUT_DIR/strings/urls.txt"
    URL_COUNT=$(wc -l < "$OUTPUT_DIR/strings/urls.txt")
    EXTRACTION_SUMMARY+=("URLs: $URL_COUNT entries")

    # Extract potential IP addresses
    grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" "$OUTPUT_DIR/strings/all_strings.txt" > "$OUTPUT_DIR/strings/ip_addresses.txt"
    IP_COUNT=$(wc -l < "$OUTPUT_DIR/strings/ip_addresses.txt")
    EXTRACTION_SUMMARY+=("IP Addresses: $IP_COUNT entries")

    # Extract potential email addresses
    grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" "$OUTPUT_DIR/strings/all_strings.txt" > "$OUTPUT_DIR/strings/emails.txt"
    EMAIL_COUNT=$(wc -l < "$OUTPUT_DIR/strings/emails.txt")
    EXTRACTION_SUMMARY+=("Email Addresses: $EMAIL_COUNT entries")

    # 6. Look for executable references
    echo -e "${BLUE}[i] Looking for executable references...${NC}"
    grep -i "\.exe\|\.dll\|\.sys" "$OUTPUT_DIR/strings/all_strings.txt" > "$OUTPUT_DIR/strings/executables.txt"
    EXE_COUNT=$(wc -l < "$OUTPUT_DIR/strings/executables.txt")
    EXTRACTION_SUMMARY+=("Executable References: $EXE_COUNT entries")

    # 7. Search for network traffic
    echo -e "${BLUE}[i] Looking for network traffic...${NC}"
    if grep -q "TCP\|UDP\|HTTP\|FTP\|SMTP" "$OUTPUT_DIR/strings/all_strings.txt"; then
        echo -e "${GREEN}[+] Network traffic indicators found${NC}"
        grep -i "TCP\|UDP\|HTTP\|FTP\|SMTP" "$OUTPUT_DIR/strings/all_strings.txt" > "$OUTPUT_DIR/strings/network_traffic.txt"
        NETWORK_SIZE=$(stat -c%s "$OUTPUT_DIR/strings/network_traffic.txt")
        echo -e "${BLUE}[i] Network traffic data saved to: $FULL_OUTPUT_PATH/strings/network_traffic.txt (Size: $NETWORK_SIZE bytes)${NC}"
        EXTRACTION_SUMMARY+=("Network Traffic: Found ($NETWORK_SIZE bytes)")
    else
        echo -e "${YELLOW}[-] No clear network traffic indicators found${NC}"
        EXTRACTION_SUMMARY+=("Network Traffic: None found")
    fi

    echo -e "${GREEN}[+] Data carving completed${NC}"
    return 0
}

# Function to check if the file is a valid memory dump using Volatility
check_memory_dump() {
    echo -e "${YELLOW}[*] Checking if the file is a valid memory dump...${NC}"
    
    # Check if we're using volatility 2.6
    if [ -f "./volatility_2.6_lin64_standalone/volatility" ]; then
        ./volatility_2.6_lin64_standalone/volatility -f "$FILENAME" imageinfo > "$OUTPUT_DIR/volatility_output/imageinfo.txt" 2>&1
        if grep -q "Suggested Profile" "$OUTPUT_DIR/volatility_output/imageinfo.txt"; then
            echo -e "${GREEN}[+] File is a valid memory dump${NC}"
            return 0
        else
            echo -e "${YELLOW}[-] File does not appear to be a memory dump${NC}"
            return 1
        fi
    else
        # Otherwise use newer volatility version
        volatility -f "$FILENAME" windows.info > "$OUTPUT_DIR/volatility_output/windows_info.txt" 2>&1
        if grep -q "Suggested Profile" "$OUTPUT_DIR/volatility_output/windows_info.txt"; then
            echo -e "${GREEN}[+] File is a valid memory dump${NC}"
            return 0
        else
            echo -e "${YELLOW}[-] File does not appear to be a memory dump${NC}"
            return 1
        fi
    fi
}

# Function to analyze with Volatility
analyze_with_volatility() {
    echo -e "${YELLOW}[*] Attempting to analyze with Volatility...${NC}"
    
    # Check if we're using volatility 2.6
    if [ -f "./volatility_2.6_lin64_standalone/volatility" ]; then
        echo -e "${GREEN}[+] Using volatility 2.6 standalone${NC}"
        
        # First try to identify the profile automatically
        echo -e "${BLUE}[i] Attempting to identify memory profile...${NC}"
        ./volatility_2.6_lin64_standalone/volatility -f "$FILENAME" imageinfo > "$OUTPUT_DIR/volatility_output/imageinfo.txt" 2>&1
        
        # Extract the suggested profile(s)
        VOLATILITY_PROFILE=$(grep "Suggested Profile" "$OUTPUT_DIR/volatility_output/imageinfo.txt" | awk -F':' '{print $2}' | awk '{print $1}' | tr -d ',')
        
        if [ -z "$VOLATILITY_PROFILE" ]; then
            echo -e "${YELLOW}[-] Could not determine memory profile automatically. Using Win7SP1x64 as default.${NC}"
            VOLATILITY_PROFILE="Win7SP1x64"
        else
            echo -e "${GREEN}[+] Detected memory profile: $VOLATILITY_PROFILE${NC}"
        fi
        
        # Run Volatility 2.6 plugins
        echo -e "${BLUE}[i] Extracting process information...${NC}"
        ./volatility_2.6_lin64_standalone/volatility -f "$FILENAME" --profile="$VOLATILITY_PROFILE" pslist > "$OUTPUT_DIR/volatility_output/pslist.txt" 2>&1
        
        echo -e "${BLUE}[i] Extracting network connections...${NC}"
        ./volatility_2.6_lin64_standalone/volatility -f "$FILENAME" --profile="$VOLATILITY_PROFILE" netscan > "$OUTPUT_DIR/volatility_output/netscan.txt" 2>&1
        
        echo -e "${BLUE}[i] Extracting registry information...${NC}"
        ./volatility_2.6_lin64_standalone/volatility -f "$FILENAME" --profile="$VOLATILITY_PROFILE" hivelist > "$OUTPUT_DIR/volatility_output/hivelist.txt" 2>&1
        
        echo -e "${GREEN}[+] Volatility analysis completed${NC}"
        EXTRACTION_SUMMARY+=("Volatility Analysis: Completed successfully with v2.6")
    else
        # Otherwise use newer volatility version
        echo -e "${GREEN}[+] Using newer volatility version${NC}"
        
        # Check if the file is a valid memory dump
        if check_memory_dump; then
            # Extract the suggested profile
            VOLATILITY_PROFILE=$(grep "Suggested Profile" "$OUTPUT_DIR/volatility_output/windows_info.txt" | cut -d ":" -f 2 | cut -d "," -f 1 | tr -d ' ')
            
            if [ -z "$VOLATILITY_PROFILE" ]; then
                echo -e "${YELLOW}[-] Could not determine memory profile. Using Win10x64_18362 as default.${NC}"
                VOLATILITY_PROFILE="Win10x64_18362"
            else
                echo -e "${GREEN}[+] Detected memory profile: $VOLATILITY_PROFILE${NC}"
            fi
            
            # Run Volatility plugins
            echo -e "${BLUE}[i] Extracting process information...${NC}"
            volatility -f "$FILENAME" --profile="$VOLATILITY_PROFILE" pslist > "$OUTPUT_DIR/volatility_output/pslist.txt" 2>&1
            
            echo -e "${BLUE}[i] Extracting network connections...${NC}"
            volatility -f "$FILENAME" --profile="$VOLATILITY_PROFILE" netscan > "$OUTPUT_DIR/volatility_output/netscan.txt" 2>&1
            
            echo -e "${BLUE}[i] Extracting registry information...${NC}"
            volatility -f "$FILENAME" --profile="$VOLATILITY_PROFILE" hivelist > "$OUTPUT_DIR/volatility_output/hivelist.txt" 2>&1
            
            echo -e "${GREEN}[+] Volatility analysis completed${NC}"
            EXTRACTION_SUMMARY+=("Volatility Analysis: Completed successfully")
        else
            echo -e "${YELLOW}[-] File does not appear to be a memory dump. Skipping Volatility analysis.${NC}"
            EXTRACTION_SUMMARY+=("Volatility Analysis: Skipped (not a memory dump)")
        fi
    fi
    
    return 0
}

# Function to generate final report
generate_report() {
    echo -e "${YELLOW}[*] Generating final report...${NC}"
    
    # Calculate analysis duration
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    HOURS=$((DURATION / 3600))
    MINUTES=$(( (DURATION % 3600) / 60 ))
    SECONDS=$((DURATION % 60))
    
    # Add analysis statistics to report
    echo "ANALYSIS STATISTICS" >> "$REPORT_FILE"
    echo "===================" >> "$REPORT_FILE"
    echo "Analysis Duration: ${HOURS}h ${MINUTES}m ${SECONDS}s" >> "$REPORT_FILE"
    echo "Files Extracted/Generated: $FOUND_FILES_COUNT" >> "$REPORT_FILE"
    echo "Output Directory: $FULL_OUTPUT_PATH" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Add extraction summary to report
    echo "EXTRACTION SUMMARY" >> "$REPORT_FILE"
    echo "==================" >> "$REPORT_FILE"
    for item in "${EXTRACTION_SUMMARY[@]}"; do
        echo "- $item" >> "$REPORT_FILE"
    done
    echo "" >> "$REPORT_FILE"
    
    # Add specific findings sections
    if [ -f "$OUTPUT_DIR/strings/possible_passwords.txt" ]; then
        echo "POTENTIAL CREDENTIALS (TOP 10)" >> "$REPORT_FILE"
        echo "=============================" >> "$REPORT_FILE"
        head -10 "$OUTPUT_DIR/strings/possible_passwords.txt" >> "$REPORT_FILE"
        echo "..." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
    
    if [ -f "$OUTPUT_DIR/strings/ip_addresses.txt" ]; then
        echo "IDENTIFIED IP ADDRESSES (TOP 10)" >> "$REPORT_FILE"
        echo "===============================" >> "$REPORT_FILE"
        head -10 "$OUTPUT_DIR/strings/ip_addresses.txt" >> "$REPORT_FILE"
        echo "..." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
    
    if [ -f "$OUTPUT_DIR/volatility_output/pslist.txt" ]; then
        echo "RUNNING PROCESSES (TOP 10)" >> "$REPORT_FILE"
        echo "=========================" >> "$REPORT_FILE"
        head -10 "$OUTPUT_DIR/volatility_output/pslist.txt" >> "$REPORT_FILE"
        echo "..." >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
    
    # Add file structure information
    echo "OUTPUT DIRECTORY STRUCTURE" >> "$REPORT_FILE"
    echo "=========================" >> "$REPORT_FILE"
    find "$OUTPUT_DIR" -type d | sort >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Conclusion
    echo "CONCLUSION" >> "$REPORT_FILE"
    echo "==========" >> "$REPORT_FILE"
    echo "This analysis was performed automatically by the ANALYZER script." >> "$REPORT_FILE"
    echo "Please review the extracted files for further investigation." >> "$REPORT_FILE"
    echo "All extracted files are available in the output directory: $FULL_OUTPUT_PATH" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "Analysis completed on: $(date)" >> "$REPORT_FILE"
    
    echo -e "${GREEN}[+] Report generated: $FULL_OUTPUT_PATH/$REPORT_FILE${NC}"
    return 0
}

# Function to zip results
zip_results() {
    echo -e "${YELLOW}[*] Compressing results...${NC}"
    
    ZIP_NAME="${OUTPUT_DIR}_results.zip"
    
    # Create zip file with all analysis results
    zip -r "$ZIP_NAME" "$OUTPUT_DIR" >> "$ANALYSIS_LOG" 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] Results compressed: $FULL_OUTPUT_PATH/../$ZIP_NAME${NC}"
        echo -e "${GREEN}[+] Total size: $(du -h "$ZIP_NAME" | cut -f1)${NC}"
    else
        echo -e "${RED}[!] Error: Failed to compress results${NC}"
        return 1
    fi
    
    return 0
}

# Function to ask user if they want to continue analyzing
ask_continue() {
    while true; do
        echo -e "${YELLOW}"
        echo "╔════════════════════════════════════════════════════════════════╗"
        echo "║                        CONTINUE ANALYZING?                     ║"
        echo "╚════════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        echo -e "${CYAN}Would you like to analyze another file or folder?${NC}"
        echo -e "${GREEN}[1] Yes, analyze another file/folder${NC}"
        echo -e "${RED}[2] No, exit program${NC}"
        read -p "Enter your choice (1-2): " choice
        
        case "$choice" in
            1)
                echo -e "${GREEN}[+] Continuing with new analysis...${NC}"
                sleep 1
                return 0
                ;;
            2)
                echo -e "${YELLOW}[*] Exiting program. Thank you for using ANALYZER.${NC}"
                KEEP_RUNNING=false
                return 1
                ;;
            *)
                echo -e "${RED}[!] Invalid choice. Please enter 1 or 2.${NC}"
                ;;
        esac
    done
}

# Main function to orchestrate the analysis
main() {
    CURRENT_OS=$(detect_os)
    display_banner
    check_root
    
    # Install required tools
    if ! install_tools; then
        echo -e "${RED}[!] Failed to install required tools. Exiting.${NC}"
        exit 1
    fi
    
    # Main program loop
    while $KEEP_RUNNING; do
        # Reset variables for new analysis
        START_TIME=$(date +%s)
        OUTPUT_DIR=""
        FULL_OUTPUT_PATH=""
        REPORT_FILE=""
        ANALYSIS_LOG=""
        FILENAME=""
        FILE_TYPE=""
        VOLATILITY_PROFILE=""
        FOUND_FILES_COUNT=0
        EXTRACTION_SUMMARY=()
        
        # Get file or folder to analyze
        if ! get_file_or_folder; then
            echo -e "${RED}[!] Failed to get file/folder to analyze.${NC}"
            if ! ask_continue; then
                exit 0
            fi
            continue
        fi
        
        # Carve data from the file or folder
        if ! carve_data; then
            echo -e "${RED}[!] Error in data carving process${NC}"
            # Continue anyway to preserve partial results
        fi
        
        # Analyze with Volatility if appropriate
        if ! analyze_with_volatility; then
            echo -e "${RED}[!] Error in Volatility analysis${NC}"
            # Continue anyway to preserve partial results
        fi
        
        # Generate report
        if ! generate_report; then
            echo -e "${RED}[!] Error generating report${NC}"
            # Continue anyway to preserve partial results
        fi
        
        # Zip results
        if ! zip_results; then
            echo -e "${RED}[!] Error zipping results${NC}"
            # Continue anyway to preserve partial results
        fi
        
        # Final message
        echo -e "${GREEN}${BOLD}[+] Analysis completed successfully!${NC}"
        echo -e "${BLUE}[i] Analysis report: $FULL_OUTPUT_PATH/analysis_report.txt${NC}"
        echo -e "${BLUE}[i] Compressed results: $FULL_OUTPUT_PATH/../${OUTPUT_DIR}_results.zip${NC}"
        echo -e "${BLUE}[i] Raw output directory: $FULL_OUTPUT_PATH${NC}"
        
        # Ask if user wants to continue
        if ! ask_continue; then
            break
        fi
    done
    
    echo -e "${YELLOW}[*] Thank you for using ANALYZER${NC}"
}

# Run the main function
main
