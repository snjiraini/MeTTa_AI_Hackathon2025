#!/bin/bash

# 🛡️ MeTTa Security Guard Demo Script
# ===================================
# 
# Comprehensive demonstration of MeTTa-orchestrated LLM security system
# All security decisions are now made through symbolic reasoning
#
# Available Demos:
# - Phase 2 Enhanced: Advanced pattern detection with context awareness
# - Phase 3 Advanced: Sophisticated symbolic reasoning and threat analysis  
# - Comprehensive: Complete system overview with all MeTTa capabilities
# - Legacy Security: Original security demo (for comparison)
# - Basic Security: Simple security demonstration
#
# Usage: ./run_demo.sh [option]
# Options: comprehensive, phase2, phase3, legacy, basic, interactive

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored headers
print_header() {
    echo -e "${CYAN}================================${NC}"
    echo -e "${CYAN}🛡️  $1${NC}"
    echo -e "${CYAN}================================${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Demo Functions
run_comprehensive_demo() {
    print_header "Comprehensive MeTTa Security Demo"
    print_info "Running complete MeTTa symbolic reasoning demonstration..."
    echo ""
    python comprehensive_metta_demo.py
    print_success "Comprehensive demo completed!"
}

run_phase2_demo() {
    print_header "Phase 2: Enhanced Pattern Detection Demo"
    print_info "Running Phase 2 enhanced MeTTa pattern detection..."
    echo ""
    python demo_phase2_enhanced.py
    print_success "Phase 2 demo completed!"
}

run_phase3_demo() {
    print_header "Phase 3: Advanced Symbolic Reasoning Demo"
    print_info "Running Phase 3 advanced MeTTa symbolic reasoning..."
    echo ""
    python demo_phase3_advanced.py
    print_success "Phase 3 demo completed!"
}

run_legacy_demo() {
    print_header "Legacy Security Demo (For Comparison)"
    print_info "Running original security demo for comparison..."
    echo ""
    python run_security_demo.py
    print_success "Legacy demo completed!"
}

run_basic_demo() {
    print_header "Basic Security Demo"
    print_info "Running basic security demonstration..."
    echo ""
    python enhanced_security_demo.py
    print_success "Basic demo completed!"
}

# Interactive menu
show_menu() {
    echo -e "${PURPLE}🛡️  MeTTa Security Guard Demo Menu${NC}"
    echo -e "${PURPLE}===================================${NC}"
    echo ""
    echo -e "${YELLOW}Select a demo to run:${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} Comprehensive MeTTa Demo (Recommended)"
    echo -e "  ${GREEN}2)${NC} Phase 2: Enhanced Pattern Detection"
    echo -e "  ${GREEN}3)${NC} Phase 3: Advanced Symbolic Reasoning"
    echo -e "  ${GREEN}4)${NC} Legacy Security Demo (For Comparison)"
    echo -e "  ${GREEN}5)${NC} Basic Security Demo"
    echo -e "  ${RED}6)${NC} Exit"
    echo ""
    echo -ne "${YELLOW}Enter your choice [1-6]: ${NC}"
}

# Interactive mode
interactive_mode() {
    while true; do
        clear
        show_menu
        read -r choice
        echo ""
        
        case $choice in
            1)
                run_comprehensive_demo
                ;;
            2)
                run_phase2_demo
                ;;
            3)
                run_phase3_demo
                ;;
            4)
                run_legacy_demo
                ;;
            5)
                run_basic_demo
                ;;
            6)
                print_info "Exiting demo..."
                exit 0
                ;;
            *)
                print_error "Invalid option. Please choose 1-6."
                ;;
        esac
        
        echo ""
        echo -ne "${YELLOW}Press any key to continue...${NC}"
        read -n 1
    done
}

# Main execution
if [ $# -eq 0 ]; then
    # No arguments provided, run interactive mode
    interactive_mode
else
    # Command line mode
    case "$1" in
        "comprehensive")
            run_comprehensive_demo
            ;;
        "phase2")
            run_phase2_demo
            ;;
        "phase3")
            run_phase3_demo
            ;;
        "legacy")
            run_legacy_demo
            ;;
        "basic")
            run_basic_demo
            ;;
        "interactive")
            interactive_mode
            ;;
        *)
            print_error "Invalid option: $1"
            echo ""
            print_info "Usage: $0 [comprehensive|phase2|phase3|legacy|basic|interactive]"
            echo ""
            print_info "Available options:"
            echo "  comprehensive - Complete MeTTa symbolic reasoning demo"
            echo "  phase2        - Enhanced pattern detection demo"
            echo "  phase3        - Advanced symbolic reasoning demo"
            echo "  legacy        - Original security demo (comparison)"
            echo "  basic         - Basic security demonstration"
            echo "  interactive   - Interactive menu mode"
            echo ""
            exit 1
            ;;
    esac
fi
