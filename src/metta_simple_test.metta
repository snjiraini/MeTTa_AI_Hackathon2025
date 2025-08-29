;; ============================================================================
;; MeTTa Security Orchestrator - Simple Working Version
;; ============================================================================

;; Simple constants
(= (health-status) healthy)

;; Simple security rules - start with basic facts  
(security-decision "hello" "test" ALLOW 0.9 "Safe greeting")
(security-decision "bomb" "test" BLOCK 0.9 "Dangerous content")

;; Default rule
(security-decision $input $context ALLOW 0.5 "Default safe response")
