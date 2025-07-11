#!/bin/bash
# Comprehensive RDP Security Testing Suite
# Based on MITM Test Criteria for CyberArk JIT DPA Testing

# Configuration
TARGET_RDP_IP=${TARGET_RDP_IP:-"TARGET_IP_HERE"}
PROXY_PORT=8080
LOG_DIR="./rdp_security_test_$(date +%Y%m%d_%H%M%S)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_FILE="$LOG_DIR/rdp_capture_$TIMESTAMP.pcap"
SESSION_LOG="$LOG_DIR/session_$TIMESTAMP.log"
REPORT_FILE="$LOG_DIR/security_report_$TIMESTAMP.md"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create directory structure
mkdir -p "$LOG_DIR"/{pcaps,logs,reports,analysis,scripts}

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" | tee -a "$SESSION_LOG"
}

log_test() {
    local test_name="$1"
    local status="$2"
    local details="$3"
    
    case $status in
        "PASS") echo -e "${GREEN}[PASS]${NC} $test_name: $details" | tee -a "$REPORT_FILE" ;;
        "FAIL") echo -e "${RED}[FAIL]${NC} $test_name: $details" | tee -a "$REPORT_FILE" ;;
        "WARN") echo -e "${YELLOW}[WARN]${NC} $test_name: $details" | tee -a "$REPORT_FILE" ;;
        "INFO") echo -e "${BLUE}[INFO]${NC} $test_name: $details" | tee -a "$REPORT_FILE" ;;
    esac
}

# Generate test report header
init_report() {
    cat > "$REPORT_FILE" << EOF
# RDP Security Test Report
**Target:** $TARGET_RDP_IP  
**Test Date:** $(date)  
**Test Suite:** Comprehensive RDP Security Analysis  

## Test Categories
1. Authentication Flow Testing
2. Privilege Escalation Testing  
3. Session Security Testing
4. Attack Simulation
5. Tool Integration

---

## Test Results

EOF
}

# 1. AUTHENTICATION FLOW TESTING
test_credential_caching() {
    log "INFO" "Starting Credential Caching Analysis"
    
    # Check for credential caching patterns in traffic
    tshark -r "$PCAP_FILE" -Y "rdp.authentication" -T fields -e frame.time -e ip.src -e ip.dst 2>/dev/null | \
    awk '
    BEGIN { prev_auth = ""; auth_count = 0 }
    {
        if ($0 == prev_auth) {
            auth_count++
        } else {
            if (auth_count > 1) {
                print "Potential credential caching detected: " prev_auth " repeated " auth_count " times"
                exit 1
            }
            prev_auth = $0
            auth_count = 1
        }
    }
    END { 
        if (auth_count > 1) exit 1
        else exit 0
    }' > "$LOG_DIR/analysis/credential_cache_analysis.txt"
    
    if [ $? -eq 0 ]; then
        log_test "Credential Caching Analysis" "PASS" "No evidence of improper credential caching"
    else
        log_test "Credential Caching Analysis" "FAIL" "Potential credential caching detected"
    fi
}

test_ntlm_analysis() {
    log "INFO" "Starting NTLM/Kerberos Analysis"
    
    # Extract NTLM traffic
    tshark -r "$PCAP_FILE" -Y "ntlmssp" -T fields -e ntlmssp.messagetype -e ntlmssp.auth.username -e ntlmssp.auth.domain > "$LOG_DIR/analysis/ntlm_traffic.txt" 2>/dev/null
    
    # Check for NTLM usage
    if [ -s "$LOG_DIR/analysis/ntlm_traffic.txt" ]; then
        log_test "NTLM Usage" "WARN" "NTLM authentication detected - consider upgrading to Kerberos"
        
        # Extract NTLM hashes for potential cracking
        tshark -r "$PCAP_FILE" -Y "ntlmssp.messagetype == 3" -T fields -e ntlmssp.auth.ntresponse > "$LOG_DIR/analysis/ntlm_hashes.txt" 2>/dev/null
        if [ -s "$LOG_DIR/analysis/ntlm_hashes.txt" ]; then
            log_test "NTLM Hash Extraction" "WARN" "NTLM hashes extracted for analysis"
        fi
    else
        log_test "NTLM Analysis" "PASS" "No NTLM authentication detected"
    fi
}

test_mfa_bypass() {
    log "INFO" "Analyzing MFA Implementation"
    
    # Look for MFA-related traffic patterns
    tshark -r "$PCAP_FILE" -Y "tcp.port == 3389" -T fields -e tcp.payload | \
    grep -i -E "(mfa|otp|token|2fa)" > "$LOG_DIR/analysis/mfa_patterns.txt" 2>/dev/null
    
    if [ -s "$LOG_DIR/analysis/mfa_patterns.txt" ]; then
        log_test "MFA Detection" "INFO" "MFA-related patterns detected in traffic"
    else
        log_test "MFA Detection" "WARN" "No MFA patterns detected - verify MFA implementation"
    fi
}

test_session_tokens() {
    log "INFO" "Analyzing Session Token Handling"
    
    # Extract potential session tokens
    tshark -r "$PCAP_FILE" -Y "tcp.port == 3389" -T fields -e tcp.payload | \
    grep -oE '[A-Za-z0-9+/]{32,}' | head -10 > "$LOG_DIR/analysis/session_tokens.txt" 2>/dev/null
    
    if [ -s "$LOG_DIR/analysis/session_tokens.txt" ]; then
        log_test "Session Token Extraction" "INFO" "Potential session tokens identified"
        
        # Check token randomness (basic entropy check)
        python3 -c "
import sys
tokens = open('$LOG_DIR/analysis/session_tokens.txt').readlines()
for token in tokens:
    token = token.strip()
    if len(set(token)) < len(token) * 0.6:
        print('Low entropy token detected: ' + token[:20] + '...')
        sys.exit(1)
print('Token entropy appears adequate')
" && log_test "Token Entropy" "PASS" "Session tokens show adequate entropy" || \
log_test "Token Entropy" "FAIL" "Low entropy tokens detected"
    fi
}

# 2. PRIVILEGE ESCALATION TESTING
test_jit_privilege_packets() {
    log "INFO" "Analyzing JIT Privilege Assignment"
    
    # Look for CyberArk/JIT related patterns
    tshark -r "$PCAP_FILE" -Y "tcp.port == 3389" -T fields -e tcp.payload | \
    grep -i -E "(cyberark|jit|privilege|role|access)" > "$LOG_DIR/analysis/jit_patterns.txt" 2>/dev/null
    
    if [ -s "$LOG_DIR/analysis/jit_patterns.txt" ]; then
        log_test "JIT Traffic Detection" "INFO" "JIT-related traffic patterns detected"
        
        # Check for plaintext privilege data
        if grep -i -E "(admin|root|elevated)" "$LOG_DIR/analysis/jit_patterns.txt" >/dev/null; then
            log_test "Privilege Data Encryption" "WARN" "Potential plaintext privilege data detected"
        else
            log_test "Privilege Data Encryption" "PASS" "No plaintext privilege data detected"
        fi
    else
        log_test "JIT Detection" "INFO" "No obvious JIT patterns detected in traffic"
    fi
}

test_rbac_validation() {
    log "INFO" "Testing RBAC Validation"
    
    # Simulate RBAC bypass attempts by looking for privilege escalation patterns
    tshark -r "$PCAP_FILE" -Y "tcp.port == 3389" -T fields -e tcp.payload | \
    grep -i -E "(elevate|sudo|admin|root)" > "$LOG_DIR/analysis/rbac_attempts.txt" 2>/dev/null
    
    if [ -s "$LOG_DIR/analysis/rbac_attempts.txt" ]; then
        log_test "RBAC Bypass Attempts" "WARN" "Potential privilege escalation attempts detected"
    else
        log_test "RBAC Validation" "PASS" "No obvious privilege escalation attempts"
    fi
}

test_credential_lifecycle() {
    log "INFO" "Analyzing Temporary Credential Lifecycle"
    
    # Track credential creation, usage, and revocation
    tshark -r "$PCAP_FILE" -Y "ntlmssp or kerberos" -T fields -e frame.time -e ntlmssp.auth.username > "$LOG_DIR/analysis/credential_timeline.txt" 2>/dev/null
    
    if [ -s "$LOG_DIR/analysis/credential_timeline.txt" ]; then
        log_test "Credential Tracking" "INFO" "Credential usage timeline generated"
        
        # Check for credential reuse
        awk '{print $2}' "$LOG_DIR/analysis/credential_timeline.txt" | sort | uniq -d > "$LOG_DIR/analysis/reused_creds.txt"
        if [ -s "$LOG_DIR/analysis/reused_creds.txt" ]; then
            log_test "Credential Reuse" "WARN" "Potential credential reuse detected"
        else
            log_test "Credential Reuse" "PASS" "No credential reuse detected"
        fi
    fi
}

test_time_based_attacks() {
    log "INFO" "Testing Time-Based Access Controls"
    
    # Analyze session duration
    first_packet=$(tshark -r "$PCAP_FILE" -Y "tcp.port == 3389" -T fields -e frame.time | head -1)
    last_packet=$(tshark -r "$PCAP_FILE" -Y "tcp.port == 3389" -T fields -e frame.time | tail -1)
    
    if [ -n "$first_packet" ] && [ -n "$last_packet" ]; then
        log_test "Session Duration" "INFO" "Session tracked from $first_packet to $last_packet"
    fi
}

# 3. SESSION SECURITY TESTING
test_encryption_strength() {
    log "INFO" "Analyzing Encryption Strength"
    
    # Check SSL/TLS handshake
    tshark -r "$PCAP_FILE" -Y "ssl.handshake" -T fields -e ssl.handshake.ciphersuite > "$LOG_DIR/analysis/cipher_suites.txt" 2>/dev/null
    
    if [ -s "$LOG_DIR/analysis/cipher_suites.txt" ]; then
        # Check for weak ciphers
        if grep -E "(RC4|DES|MD5)" "$LOG_DIR/analysis/cipher_suites.txt" >/dev/null; then
            log_test "Encryption Strength" "FAIL" "Weak encryption algorithms detected"
        else
            log_test "Encryption Strength" "PASS" "Strong encryption algorithms in use"
        fi
    else
        log_test "Encryption Analysis" "WARN" "No SSL/TLS handshake detected"
    fi
}

test_certificate_validation() {
    log "INFO" "Testing Certificate Validation"
    
    # Extract certificate information
    tshark -r "$PCAP_FILE" -Y "ssl.handshake.certificate" -T fields -e ssl.handshake.certificate > "$LOG_DIR/analysis/certificates.txt" 2>/dev/null
    
    if [ -s "$LOG_DIR/analysis/certificates.txt" ]; then
        log_test "Certificate Detection" "INFO" "SSL certificates detected in traffic"
    else
        log_test "Certificate Validation" "WARN" "No certificate validation detected"
    fi
}

test_session_hijacking() {
    log "INFO" "Analyzing Session Hijacking Vectors"
    
    # Look for session ID patterns
    tshark -r "$PCAP_FILE" -Y "tcp.port == 3389" -T fields -e tcp.seq -e tcp.ack > "$LOG_DIR/analysis/tcp_sequence.txt" 2>/dev/null
    
    # Check for sequence number patterns that might indicate vulnerabilities
    awk '{print $1}' "$LOG_DIR/analysis/tcp_sequence.txt" | sort -n | uniq -d > "$LOG_DIR/analysis/duplicate_sequences.txt"
    
    if [ -s "$LOG_DIR/analysis/duplicate_sequences.txt" ]; then
        log_test "TCP Sequence Analysis" "WARN" "Duplicate TCP sequences detected"
    else
        log_test "TCP Sequence Analysis" "PASS" "TCP sequence numbers appear random"
    fi
}

test_clipboard_redirection() {
    log "INFO" "Testing Clipboard Redirection Security"
    
    # Look for clipboard data patterns
    tshark -r "$PCAP_FILE" -Y "tcp.port == 3389" -T fields -e tcp.payload | \
    grep -i -E "(clipboard|copy|paste)" > "$LOG_DIR/analysis/clipboard_data.txt" 2>/dev/null
    
    if [ -s "$LOG_DIR/analysis/clipboard_data.txt" ]; then
        log_test "Clipboard Activity" "INFO" "Clipboard activity detected"
        # Check if data appears to be encrypted
        if grep -E "[A-Za-z0-9+/]{20,}" "$LOG_DIR/analysis/clipboard_data.txt" >/dev/null; then
            log_test "Clipboard Encryption" "PASS" "Clipboard data appears encrypted"
        else
            log_test "Clipboard Encryption" "WARN" "Clipboard data may be unencrypted"
        fi
    else
        log_test "Clipboard Activity" "INFO" "No clipboard activity detected"
    fi
}

# 4. ATTACK SIMULATION
simulate_mitm_attack() {
    log "INFO" "Simulating MITM Attack Detection"
    
    # Check for man-in-the-middle indicators
    tshark -r "$PCAP_FILE" -Y "tcp.port == 3389" -T fields -e ip.src -e ip.dst | \
    sort | uniq -c | sort -nr > "$LOG_DIR/analysis/traffic_patterns.txt"
    
    # Look for suspicious traffic patterns
    if awk '$1 > 100 {print}' "$LOG_DIR/analysis/traffic_patterns.txt" | head -1 >/dev/null; then
        log_test "MITM Detection" "WARN" "Suspicious traffic patterns detected"
    else
        log_test "MITM Detection" "PASS" "No obvious MITM patterns detected"
    fi
}

simulate_replay_attack() {
    log "INFO" "Testing Replay Attack Resistance"
    
    # Extract authentication packets for replay analysis
    tshark -r "$PCAP_FILE" -Y "ntlmssp.messagetype == 3" -w "$LOG_DIR/pcaps/auth_packets.pcap" 2>/dev/null
    
    if [ -s "$LOG_DIR/pcaps/auth_packets.pcap" ]; then
        log_test "Replay Attack Prep" "INFO" "Authentication packets extracted for replay testing"
    else
        log_test "Replay Attack Analysis" "INFO" "No authentication packets found for replay testing"
    fi
}

test_dos_resistance() {
    log "INFO" "Testing DoS Resistance"
    
    # Analyze connection patterns for DoS indicators
    tshark -r "$PCAP_FILE" -Y "tcp.flags.syn == 1" -T fields -e frame.time -e ip.src > "$LOG_DIR/analysis/connection_attempts.txt" 2>/dev/null
    
    if [ -s "$LOG_DIR/analysis/connection_attempts.txt" ]; then
        # Check for rapid connection attempts
        connection_rate=$(wc -l < "$LOG_DIR/analysis/connection_attempts.txt")
        if [ "$connection_rate" -gt 50 ]; then
            log_test "DoS Detection" "WARN" "High connection rate detected ($connection_rate connections)"
        else
            log_test "DoS Analysis" "PASS" "Normal connection rate observed"
        fi
    fi
}

# 5. AUTOMATED ANALYSIS
run_automated_analysis() {
    log "INFO" "Running Automated Security Analysis"
    
    # Create Python analysis script
    cat > "$LOG_DIR/scripts/rdp_analyzer.py" << 'EOF'
#!/usr/bin/env python3
import pyshark
import sys
import json
from collections import defaultdict

def analyze_rdp_security(pcap_file):
    results = {
        'vulnerabilities': [],
        'statistics': defaultdict(int),
        'recommendations': []
    }
    
    try:
        cap = pyshark.FileCapture(pcap_file, display_filter='tcp.port == 3389')
        
        for pkt in cap:
            results['statistics']['total_packets'] += 1
            
            # Check for weak encryption
            if hasattr(pkt, 'ssl') and hasattr(pkt.ssl, 'handshake_ciphersuite'):
                if any(weak in pkt.ssl.handshake_ciphersuite for weak in ['RC4', 'DES', 'MD5']):
                    results['vulnerabilities'].append('Weak encryption cipher detected')
            
            # Check for NTLM usage
            if hasattr(pkt, 'ntlmssp'):
                results['statistics']['ntlm_packets'] += 1
                results['recommendations'].append('Consider migrating from NTLM to Kerberos')
        
    except Exception as e:
        results['error'] = str(e)
    
    return results

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 rdp_analyzer.py <pcap_file>")
        sys.exit(1)
    
    results = analyze_rdp_security(sys.argv[1])
    print(json.dumps(results, indent=2))
EOF
    
    # Run automated analysis if pyshark is available
    if command -v python3 >/dev/null && python3 -c "import pyshark" 2>/dev/null; then
        python3 "$LOG_DIR/scripts/rdp_analyzer.py" "$PCAP_FILE" > "$LOG_DIR/analysis/automated_results.json" 2>/dev/null
        if [ $? -eq 0 ]; then
            log_test "Automated Analysis" "PASS" "Automated security analysis completed"
        else
            log_test "Automated Analysis" "WARN" "Automated analysis encountered errors"
        fi
    else
        log_test "Automated Analysis" "WARN" "PyShark not available for automated analysis"
    fi
}

# Generate final report
generate_final_report() {
    log "INFO" "Generating Final Security Report"
    
    cat >> "$REPORT_FILE" << EOF

---

## Summary

**Test Completion Time:** $(date)  
**Total Tests Run:** $(grep -E '\[(PASS|FAIL|WARN)\]' "$REPORT_FILE" | wc -l)  
**Tests Passed:** $(grep '\[PASS\]' "$REPORT_FILE" | wc -l)  
**Tests Failed:** $(grep '\[FAIL\]' "$REPORT_FILE" | wc -l)  
**Warnings:** $(grep '\[WARN\]' "$REPORT_FILE" | wc -l)  

## Files Generated
- PCAP Capture: \`$PCAP_FILE\`
- Session Log: \`$SESSION_LOG\`
- Analysis Files: \`$LOG_DIR/analysis/\`
- Test Scripts: \`$LOG_DIR/scripts/\`

## Recommendations
1. Review all FAIL and WARN items above
2. Implement missing security controls
3. Regular security testing schedule
4. Monitor for new vulnerabilities

---
*Report generated by RDP Comprehensive Security Test Suite*
EOF
    
    log "INFO" "Security report saved to: $REPORT_FILE"
}

# Main execution functions
setup_environment() {
    log "INFO" "Setting up test environment"
    
    # Check prerequisites
    command -v tshark >/dev/null || { log "ERROR" "tshark not found - install wireshark"; exit 1; }
    command -v socat >/dev/null || { log "ERROR" "socat not found"; exit 1; }
    
    # Validate target IP
    if [ "$TARGET_RDP_IP" == "TARGET_IP_HERE" ]; then
        log "ERROR" "Please set TARGET_RDP_IP environment variable"
        exit 1
    fi
    
    # Initialize report
    init_report
    
    log "INFO" "Environment setup complete"
}

start_mitm_proxy() {
    log "INFO" "Starting MITM proxy for traffic capture"
    
    # Enable IP forwarding
    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null
    
    # Set up iptables
    sudo iptables -t nat -F
    sudo iptables -t nat -A PREROUTING -p tcp --dport 3389 -j REDIRECT --to-port $PROXY_PORT
    sudo iptables -t nat -A OUTPUT -p tcp --dport 3389 -j REDIRECT --to-port $PROXY_PORT
    
    # Start packet capture
    sudo tcpdump -i any -w "$PCAP_FILE" port 3389 -v &
    TCPDUMP_PID=$!
    
    # Start proxy
    socat -v "TCP-LISTEN:$PROXY_PORT,reuseaddr,fork" "TCP:$TARGET_RDP_IP:3389" > "$LOG_DIR/logs/proxy_$TIMESTAMP.log" 2>&1 &
    PROXY_PID=$!
    
    log "INFO" "MITM proxy started (PID: $PROXY_PID), packet capture started (PID: $TCPDUMP_PID)"
}

run_all_tests() {
    log "INFO" "Starting comprehensive security tests"
    
    # Wait for some traffic to be captured
    sleep 5
    
    # Authentication Flow Tests
    test_credential_caching
    test_ntlm_analysis  
    test_mfa_bypass
    test_session_tokens
    
    # Privilege Escalation Tests
    test_jit_privilege_packets
    test_rbac_validation
    test_credential_lifecycle
    test_time_based_attacks
    
    # Session Security Tests
    test_encryption_strength
    test_certificate_validation
    test_session_hijacking
    test_clipboard_redirection
    
    # Attack Simulation
    simulate_mitm_attack
    simulate_replay_attack
    test_dos_resistance
    
    # Automated Analysis
    run_automated_analysis
}

cleanup() {
    log "INFO" "Cleaning up test environment"
    
    # Kill background processes
    [ -n "$TCPDUMP_PID" ] && sudo kill $TCPDUMP_PID 2>/dev/null
    [ -n "$PROXY_PID" ] && kill $PROXY_PID 2>/dev/null
    
    # Restore iptables
    sudo iptables -t nat -F
    
    # Generate final report
    generate_final_report
    
    log "INFO" "Test suite completed successfully"
    echo -e "\n${GREEN}Security test suite completed!${NC}"
    echo -e "${BLUE}Report available at:${NC} $REPORT_FILE"
    echo -e "${BLUE}Log directory:${NC} $LOG_DIR"
}

# Signal handlers
trap cleanup INT TERM

# Main execution
main() {
    echo -e "${BLUE}RDP Comprehensive Security Test Suite${NC}"
    echo -e "${BLUE}Target: $TARGET_RDP_IP${NC}"
    echo -e "${BLUE}Log Directory: $LOG_DIR${NC}\n"
    
    setup_environment
    start_mitm_proxy
    
    echo -e "\n${YELLOW}Proxy is running. Start your RDP session now.${NC}"
    echo -e "${YELLOW}Press Ctrl+C when you want to stop testing and generate report.${NC}\n"
    
    # Run tests in background
    (
        sleep 10  # Give time for initial connection
        run_all_tests
    ) &
    
    # Keep proxy running until interrupted
    wait $PROXY_PID 2>/dev/null || true
    
    cleanup
}

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This script must be run as root${NC}"
    exit 1
fi

# Run main function
main "$@"
