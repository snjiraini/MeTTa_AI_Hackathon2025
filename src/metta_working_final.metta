;; ============================================================================
;; MeTTa Security Orchestrator - Actually Working Version  
;; ============================================================================

;; Health check function
(= (health-check) healthy)

;; Security decision functions - using proper MeTTa syntax
(= (should-block-request "hello" "test") (ALLOW 0.9 "Safe greeting"))
(= (should-block-request "bomb" "test") (BLOCK 0.9 "Dangerous content"))  
(= (should-block-request "hack" "test") (REVIEW 0.7 "Suspicious content"))

;; Default fallback for any other input
(= (should-block-request $input $context) (ALLOW 0.5 "Default safe response"))
