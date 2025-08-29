;; ============================================================================
;; MeTTa Security Orchestrator - Facts Based Version
;; ============================================================================

;; Define simple facts instead of functions
(health-check healthy)

;; Define security decision facts
(security-decision "hello" "unknown" ALLOW 0.8 "Safe greeting")
(security-decision "bomb" "unknown" BLOCK 0.9 "Harmful content detected")
(security-decision $input $context ALLOW 0.5 "Default safe response")
