#!/bin/bash

# MeTTa LLM Security Demo Runner Script
# This script initializes environment variables and provides options to run different demo scripts

set -e  # Exit on any error

# Load environment variables from .env file
if [ -f ".env" ]; then
    echo "Loading environment variables from .env file..."
    # Export variables from .env file
    export $(grep -v '^#' .env | xargs)
else
    echo "Warning: .env file not found. Using default values..."
    # Fallback to default values if .env file doesn't exist
    export OPENAI_API_KEY=${OPENAI_API_KEY:-"ollama"}
    export OPENAI_BASE_URL=${OPENAI_BASE_URL:-"http://host.docker.internal:11434/v1"}
    export MODEL=${MODEL:-"dolphin-llama3"}
    export TEMP=${TEMP:-"0.2"}
    export MAX_TOKENS=${MAX_TOKENS:-"512"}
    export TIMEOUT=${TIMEOUT:-"60"}
fi

echo "========================================="
echo "MeTTa LLM Security Demo"
echo "========================================="
echo ""
echo "Environment Variables (from .env file):"
echo "  OPENAI_API_KEY: ${OPENAI_API_KEY}"
echo "  OPENAI_BASE_URL: ${OPENAI_BASE_URL}"
echo "  MODEL: ${MODEL}"
echo "  TEMP: ${TEMP}"
echo "  MAX_TOKENS: ${MAX_TOKENS}"
echo "  TIMEOUT: ${TIMEOUT}"
echo ""

# Function to show menu
show_menu() {
    echo "Available Options:"
    echo "1) test_prompt_injection  - Test 100 attack prompts without security guardrails"
    echo "2) test_metta_integration - Test MeTTa security engine integration"
    echo "3) run_security_demo     - Run full security demo with MeTTa guardrails"
    echo "4) quit                  - Exit"
    echo ""
}

# Function to run test_prompt_injection
run_test_prompt_injection() {
    echo "Running test_prompt_injection.py..."
    echo "This will test 100 attack prompts without security guardrails."
    echo ""
    python test_prompt_injection.py "$@"
}

# Function to run test_metta_integration
run_test_metta_integration() {
    echo "Running test_metta_integration.py..."
    echo "This will test the MeTTa security engine integration."
    echo ""
    python test_metta_integration.py "$@"
}

# Function to run security demo
run_security_demo() {
    echo "Running run_security_demo.py..."
    echo "This will run 100 attack scenarios with MeTTa security guardrails."
    echo ""
    python run_security_demo.py "$@"
}

# Main menu loop
if [ $# -eq 0 ]; then
    # Interactive mode - show menu
    while true; do
        show_menu
        read -p "Choose an option (1-4): " choice
        echo ""
        
        case $choice in
            1)
                run_test_prompt_injection
                echo ""
                read -p "Press Enter to continue..."
                echo ""
                ;;
            2)
                run_test_metta_integration
                echo ""
                read -p "Press Enter to continue..."
                echo ""
                ;;
            3)
                run_security_demo
                echo ""
                read -p "Press Enter to continue..."
                echo ""
                ;;
            4|quit|q)
                echo "Goodbye!"
                exit 0
                ;;
            *)
                echo "Invalid option. Please choose 1-4."
                echo ""
                ;;
        esac
    done
else
    # Command line mode - run specific script
    case "$1" in
        test_prompt_injection|1)
            shift  # Remove the first argument
            run_test_prompt_injection "$@"
            ;;
        test_metta_integration|2)
            shift
            run_test_metta_integration "$@"
            ;;
        run_security_demo|3)
            shift
            run_security_demo "$@"
            ;;
        help|--help|-h)
            echo "Usage: $0 [OPTION] [ARGS...]"
            echo ""
            show_menu
            echo "Examples:"
            echo "  $0                           # Interactive mode"
            echo "  $0 run_security_demo         # Run security demo directly"
            echo "  $0 test_prompt_injection     # Run prompt injection tests"
            echo "  $0 test_metta_integration    # Test MeTTa integration"
            echo "  $0 run_security_demo --help  # Show help for specific script"
            ;;
        *)
            echo "Error: Unknown option '$1'"
            echo "Use '$0 help' for usage information."
            exit 1
            ;;
    esac
fi
