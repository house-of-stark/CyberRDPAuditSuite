#!/bin/bash
# RDP Security Testing Suite Launcher
# Version: 3.1.0
# Focus: Comprehensive RDP security testing and validation
# Note: PCAP analysis has been moved to the RDP Tunnel Traffic Analyzer

# Global variables
SCRIPT_NAME="RDP Security Tester"
VERSION="3.1.0"
TARGET_RDP_IP=""
LOG_DIR="./logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/rdp_tester_${TIMESTAMP}.log"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'  # No Color
BOLD='\033[1m'
UNDERLINE='\033[4m'

# Minimum required versions
MIN_BASH_VERSION=4.2
MIN_PYTHON_VERSION=3.6
MIN_NMAP_VERSION=7.60
MIN_NCRACK_VERSION=0.7

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Logging functions
log() {
    local level="$1"
    local message="${*:2}"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "${level}" in
        "INFO") echo -e "[${timestamp}] ${BLUE}INFO:${NC} ${message}" ;;
        "WARN") echo -e "[${timestamp}] ${YELLOW}WARNING:${NC} ${message}" ;;
        "ERROR") echo -e "[${timestamp}] ${RED}ERROR:${NC} ${message}" ;;
        "SUCCESS") echo -e "[${timestamp}] ${GREEN}SUCCESS:${NC} ${message}" ;;
        *) echo -e "[${timestamp}] ${message}" ;;
    esac | tee -a "$LOG_FILE"
}

# Display banner
show_banner() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════╗"
    echo -e "║${BOLD}              RDP Security Testing Suite (v${VERSION})${NC}${BLUE}                ║"
    echo -e "║              CyberArk JIT DPA Testing - Active Testing Only             ║"
    echo -e "║${YELLOW}        WARNING: This tool performs active security testing${NC}${BLUE}             ║"
    echo -e "╚════════════════════════════════════════════════════════════════════╝${NC}\n"
    
    # Display current configuration
    if [ -n "$TARGET_RDP_IP" ]; then
        echo -e "${CYAN}Current Target:${NC} $TARGET_RDP_IP"
    else
        echo -e "${YELLOW}No target IP set. Please set a target IP before running tests.${NC}"
    fi
    echo ""
}

# Display main menu
show_menu() {
    echo -e "\n${YELLOW}${BOLD}Available Testing Options:${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════${NC}\n"
    
    echo -e "${BOLD}1. 🎯 ${UNDERLINE}Comprehensive Security Test${NC} (Recommended)"
    echo -e "   • Full MITM Test Criteria implementation"
    echo -e "   • Authentication, privilege escalation, session security"
    echo -e "   • Professional reporting\n"
    
    echo -e "${BOLD}2. 🔧 ${UNDERLINE}Run Specific Test Suite${NC}"
    echo -e "   • Authentication tests"
    echo -e "   • Privilege escalation tests"
    echo -e "   • Session security tests\n"
    
    echo -e "${BOLD}3. 📊 ${UNDERLINE}View Test Results${NC}"
    echo -e "   • View previous test results"
    echo -e "   • Generate reports\n"
    
    echo -e "${BOLD}4. ⚙️  ${UNDERLINE}Configuration${NC}"
    echo -e "   • Set target RDP server"
    echo -e "   • Configure test parameters\n"
    
    echo -e "${BOLD}5. ❓ ${UNDERLINE}Help & Documentation${NC}\n"
    
    echo -e "${BOLD}0. ${UNDERLINE}Exit${NC}\n"
    
    echo -e "${BLUE}═══════════════════════════════════════════════${NC}\n"
}

# Validate IP address format
validate_ip() {
    local ip="$1"
    local stat=1
    
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        [[ ${octets[0]} -le 255 && ${octets[1]} -le 255 &&
           ${octets[2]} -le 255 && ${octets[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

# Check if command exists and meets minimum version requirement
check_command_version() {
    local cmd="$1"
    local min_version="$2"
    local version_cmd="$3"
    local version_regex="$4"
    
    if ! command -v "$cmd" &> /dev/null; then
        log "ERROR" "Required command not found: $cmd"
        return 1
    fi
    
    if [ -n "$min_version" ]; then
        local version
        version=$($cmd $version_cmd 2>&1 | grep -oP "$version_regex" | head -1)
        if [ "$(printf '%s\n' "$min_version" "$version" | sort -V | head -n1)" = "$min_version" ]; then
            log "INFO" "$cmd version $version meets requirement (>= $min_version)"
        else
            log "ERROR" "$cmd version $version is below minimum required version $min_version"
            return 1
        fi
    fi
    return 0
}

# Check all dependencies
check_dependencies() {
    log "INFO" "Checking system dependencies..."
    
    # Check bash version
    if [ "$(printf '%s\n' "$MIN_BASH_VERSION" "${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}" | sort -V | head -n1)" != "$MIN_BASH_VERSION" ]; then
        log "ERROR" "Bash version ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]} is below minimum required version $MIN_BASH_VERSION"
        return 1
    fi
    
    # Check Python version
    if ! check_command_version "python3" "$MIN_PYTHON_VERSION" "--version" '[0-9]+\.[0-9]+\.[0-9]+'; then
        return 1
    fi
    
    # Check nmap
    if ! check_command_version "nmap" "$MIN_NMAP_VERSION" "--version" '(?<=Nmap version )[0-9]+\.[0-9]+'; then
        return 1
    fi
    
    # Check ncrack if available (optional)
    if command -v ncrack &> /dev/null; then
        if ! check_command_version "ncrack" "$MIN_NCRACK_VERSION" "--version" '[0-9]+\.[0-9]+'; then
            log "WARN" "ncrack version is below recommended, some tests may not work"
        fi
    else
        log "WARN" "ncrack not found, some authentication tests will be skipped"
    fi
    
    log "SUCCESS" "All required dependencies are installed"
    return 0
}

# Run comprehensive security test
run_comprehensive_test() {
    log "INFO" "Starting Comprehensive Security Test"
    
    # Check if target IP is set
    while [ -z "$TARGET_RDP_IP" ]; do
        read -p "${YELLOW}Enter target RDP IP address: ${NC}" TARGET_RDP_IP
        if ! validate_ip "$TARGET_RDP_IP"; then
            log "ERROR" "Invalid IP address format: $TARGET_RDP_IP"
            TARGET_RDP_IP=""
        fi
    done
    
    log "INFO" "Target RDP IP: $TARGET_RDP_IP"
    
    # Check dependencies
    if ! check_dependencies; then
        log "ERROR" "Dependency check failed. Please install the required tools."
        return 1
    fi
    
    # Check if target is reachable
    log "INFO" "Checking if target is reachable..."
    if ! ping -c 1 -W 2 "$TARGET_RDP_IP" &> /dev/null; then
        log "WARN" "Target $TARGET_RDP_IP is not responding to ping"
        read -p "${YELLOW}Continue anyway? [y/N]: ${NC}" -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log "INFO" "Test cancelled by user"
            return 0
        fi
    fi
    
    # Run the comprehensive test script with error handling
    if [ -f "./rdp_comprehensive_security_test.sh" ]; then
        log "INFO" "Starting RDP security tests..."
        if ! sudo ./rdp_comprehensive_security_test.sh "$TARGET_RDP_IP"; then
            log "ERROR" "Security tests failed"
            return 1
        fi
    else
        log "ERROR" "Comprehensive test script not found"
        return 1
    fi
    
    log "SUCCESS" "Security testing completed successfully"
    fi
}

# Show test suite selection
show_test_suites() {
    echo -e "${GREEN}Available Test Suites:${NC}\n"
    
    echo "1. Authentication Tests"
    echo "   - Test NTLM/Kerberos authentication"
    echo "   - Check for weak credentials"
    echo "   - Test account lockout policies"
    echo ""
    echo "2. Privilege Escalation Tests"
    echo "   - Check for vulnerable services"
    echo "   - Test for misconfigured permissions"
    echo "   - Validate JIT access controls"
    echo ""
    echo "3. Session Security Tests"
    echo "   - Test encryption levels"
    echo "   - Verify secure channel integrity"
    echo "   - Check for session hijacking vulnerabilities"
    echo ""
    echo "4. Return to Main Menu"
    echo ""
    
    read -p "Select a test suite to run (1-4): " suite_choice
    
    case $suite_choice in
        1)
            echo -e "\n${BLUE}Running Authentication Tests...${NC}"
            # Add authentication test commands here
            ;;
        2)
            echo -e "\n${BLUE}Running Privilege Escalation Tests...${NC}"
            # Add privilege escalation test commands here
            ;;
        3)
            echo -e "\n${BLUE}Running Session Security Tests...${NC}"
            # Add session security test commands here
            ;;
        4)
            return 0
            ;;
        *)
            echo -e "${RED}Invalid selection. Please try again.${NC}"
            ;;
    esac
}

# View test results
view_test_results() {
    echo -e "${GREEN}Test Results${NC}\n"
    
    # Check for results directory
    if [ ! -d "./results" ]; then
        echo -e "${YELLOW}No test results found.${NC}"
        return 1
    fi
    
    # List available result files
    echo -e "${BLUE}Available Test Results:${NC}\n"
    find ./results -type f -name "*.json" -printf "%f\n" | nl -w 3 -s '. ' | sed 's/^/  /'
    
    echo -e "\n${YELLOW}Enter the number of the result to view, or press Enter to return: ${NC}"
    read -r result_choice
    
    if [ -n "$result_choice" ] && [[ "$result_choice" =~ ^[0-9]+$ ]]; then
        result_file=$(find ./results -type f -name "*.json" | sed -n "${result_choice}p")
        if [ -f "$result_file" ]; then
            if command -v jq >/dev/null; then
                jq . "$result_file" | less -R
            else
                less "$result_file"
            fi
        else
            echo -e "${RED}Invalid selection.${NC}"
        fi
    fi
}

# Configuration menu
show_config_menu() {
    while true; do
        echo -e "${GREEN}Configuration${NC}\n"
        echo "1. Set Target RDP Server"
        echo "2. Configure Test Parameters"
        echo "3. View Current Configuration"
        echo "4. Back to Main Menu"
        echo -n "\nSelect an option: "
        
        read -r choice
        case $choice in
            1)
                read -p "Enter target RDP server IP/hostname: " TARGET_RDP_IP
                export TARGET_RDP_IP
                echo -e "${GREEN}Target set to: $TARGET_RDP_IP${NC}"
                ;;
            2)
                echo -e "\n${YELLOW}Test Configuration:${NC}"
                # Add configuration options here
                echo "Configuration options coming soon..."
                ;;
            3)
                echo -e "\n${BLUE}Current Configuration:${NC}"
                echo "Target RDP Server: ${TARGET_RDP_IP:-Not set}"
                ;;
            4)
                return 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                ;;
        esac
        echo ""
    done
}

# Show help and documentation
show_help() {
    echo -e "${BLUE}RDP Security Testing Suite Help${NC}\n"
    
    echo -e "${YELLOW}Overview:${NC}"
    echo "This suite provides comprehensive RDP security testing implementing"
    echo "the complete MITM Test Criteria for CyberArk JIT DPA analysis."
    
    echo -e "\n${YELLOW}Quick Start:${NC}"
    echo "1. Set target IP: export TARGET_RDP_IP=\"192.168.1.100\""
    echo "2. Run: sudo ./rdp_security_launcher.sh"
    echo "3. Select option 1 for comprehensive testing"
    
    echo -e "\n${YELLOW}Test Categories:${NC}"
    echo "• Authentication Flow Testing"
    echo "• Privilege Escalation Testing"
    echo "• Session Security Testing"
    
    echo -e "\n${YELLOW}Documentation:${NC}"
    echo "• README.md - Complete usage guide"
    echo "• docs/ - Detailed documentation"
    
    echo -e "\n${YELLOW}Note:${NC} PCAP analysis has been moved to the RDP Tunnel Traffic Analyzer tool."
    
    echo -e "\n${YELLOW}Press Enter to continue...${NC}"
    read -r
}

# Check for required dependencies
check_dependencies() {
    local missing_deps=()
    
    # Required tools
    command -v nmap >/dev/null || missing_deps+=("nmap")
    command -v crackmapexec >/dev/null || missing_deps+=("crackmapexec")
    command -v rdp-sec-check >/dev/null || missing_deps+=("rdp-sec-check")
    
    # Python modules
    python3 -c "import paramiko" 2>/dev/null || missing_deps+=("python3-paramiko")
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${YELLOW}Missing recommended dependencies: ${missing_deps[*]}${NC}"
        echo -e "Some tests may not function without these dependencies."
        echo -e "Install with:"
        echo "sudo apt-get install nmap crackmapexec"
        echo "pip3 install paramiko"
        echo -e "\n${YELLOW}rdp-sec-check can be installed from:${NC}"
        echo "https://github.com/portcullislabs/rdp-sec-check"
        echo ""
        read -p "Continue without these tools? (y/N): " continue_choice
        if [[ ! $continue_choice =~ ^[Yy] ]]; then
            exit 1
        fi
    fi
}

# Main function
main() {
    show_banner
    check_dependencies
    
    while true; do
        echo ""
        show_menu
        read -p "Select an option (0-5): " choice
        echo ""
        
        case $choice in
            1)
                run_comprehensive_test
                ;;
            2)
                show_test_suites
                ;;
            3)
                view_test_results
                ;;
            4)
                show_config_menu
                ;;
            5)
                show_help
                ;;
            0)
                echo -e "${GREEN}Goodbye!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please select 0-5.${NC}"
                ;;
        esac
    done
}

# Check if running as script
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
