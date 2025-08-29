;; ============================================================================
;; MeTTa Security Orchestrator - Fixed Syntax Version
;; ============================================================================

;; Health check function - returns a simple value
(= (health-check) healthy)

;; Test with simple calculation
(= (calculate-threat-score $input) 0.2)

;; Simple decision rules using pattern matching
(= (should-block-request $input $context ALLOW 0.8 "No threats detected")
   (< (calculate-threat-score $input) 0.3))

;; Default case - if no other rules match
(= (should-block-request $input $context ALLOW 0.5 "Default safe response") True)
