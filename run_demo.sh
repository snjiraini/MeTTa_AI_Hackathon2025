#!/bin/bash

# 🛡️ MeTTa Security Guard Demo Script
# ===================================
# 
# MeTTa-orchestrated LLM security system demonstration
# Choose between input filtering or output filtering approaches
#
# Security Options:
# 1. Input Security: Analyze user prompts BEFORE sending to LLM
# 2. Output Security: Analyze LLM responses BEFORE showing to user
#
# Usage: ./run_demo.sh [input|output] or run interactively

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
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

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Demo Functions
run_input_security_demo() {
    print_header "Input Security Demo"
    print_info "Analyzing user prompts BEFORE sending to LLM..."
    print_warning "This analyzes vulnerability prompts using MeTTa symbolic reasoning"
    echo ""
    python run_security_demo.py
    print_success "Input security demo completed!"
}

run_output_security_demo() {
    print_header "Output Security Demo"  
    print_info "Analyzing LLM responses BEFORE showing to user..."
    print_warning "This sends prompts to LLaMA and filters the model's responses"
    echo ""
    python run_security_demo_llama.py --max-prompts 10
    print_success "Output security demo completed!"
}

# Interactive menu
show_menu() {
    echo -e "${PURPLE}🛡️  MeTTa Security Guard Demo Menu${NC}"
    echo -e "${PURPLE}===================================${NC}"
    echo ""
    echo -e "${YELLOW}Choose your security approach:${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} Input Security  - Check user prompts ${BLUE}BEFORE${NC} sending to LLM"
    echo -e "     ${CYAN}└─${NC} Prevents malicious prompts from reaching the model"
    echo -e "     ${CYAN}└─${NC} Uses: run_security_demo.py"
    echo ""
    echo -e "  ${GREEN}2)${NC} Output Security - Check LLM responses ${BLUE}BEFORE${NC} showing to user" 
    echo -e "     ${CYAN}└─${NC} Filters dangerous content from model responses"
    echo -e "     ${CYAN}└─${NC} Uses: run_security_demo_llama.py"
    echo ""
    echo -e "  ${RED}3)${NC} Exit"
    echo ""
    echo -ne "${YELLOW}Enter your choice [1-3]: ${NC}"
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
                run_input_security_demo
                ;;
            2)
                run_output_security_demo
                ;;
            3)
                print_info "Exiting demo..."
                exit 0
                ;;
            *)
                print_error "Invalid option. Please choose 1-3."
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
        "input")
            run_input_security_demo
            ;;
        "output")
            run_output_security_demo
            ;;
        "interactive")
            interactive_mode
            ;;
        *)
            print_error "Invalid option: $1"
            echo ""
            print_info "Usage: $0 [input|output|interactive]"
            echo ""
            print_info "Available options:"
            echo "  input       - Check user prompts before sending to LLM"
            echo "  output      - Check LLM responses before showing to user"
            echo "  interactive - Interactive menu mode (default)"
            echo ""
            echo -e "${CYAN}Security Approaches:${NC}"
            echo -e "  ${GREEN}Input Security:${NC}  User Prompt → ${BLUE}MeTTa Guard${NC} → LLM → Response"
            echo -e "  ${GREEN}Output Security:${NC} User Prompt → LLM → ${BLUE}MeTTa Guard${NC} → Filtered Response"
            echo ""
            exit 1
            ;;
    esac
fi
