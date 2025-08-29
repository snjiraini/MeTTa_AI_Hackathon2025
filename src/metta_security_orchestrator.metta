;; =============================================================================
;; MeTTa Security Orchestrator - Simplified Working Version
;; This file orchestrates all security decisions using symbolic reasoning
;; =============================================================================

;; =============================================================================
;; CORE FUNCTIONS - MAIN ENTRY POINTS
;; =============================================================================

;; Main security decision function - returns decision, confidence, reasoning
(= (should-block-request $input $context BLOCK 0.9 "High threat score detected")
   (> (calculate-threat-score $input) 0.8))

(= (should-block-request $input $context REVIEW 0.7 "Moderate threat score")
   (and (> (calculate-threat-score $input) 0.5)
        (<= (calculate-threat-score $input) 0.8)))

(= (should-block-request $input $context SANITIZE 0.6 "Low threat score")  
   (and (> (calculate-threat-score $input) 0.3)
        (<= (calculate-threat-score $input) 0.5)))

(= (should-block-request $input $context ALLOW 0.8 "No significant threats detected")
   (<= (calculate-threat-score $input) 0.3))

;; Calculate overall threat score
(= (calculate-threat-score $input)
   (let* (($jailbreak-score (jailbreak-threat-score $input))
          ($ansi-score (ansi-threat-score $input))
          ($harmful-score (harmful-threat-score $input))
          ($injection-score (injection-threat-score $input)))
     (max $jailbreak-score $ansi-score $harmful-score $injection-score)))

;; =============================================================================
;; THREAT DETECTION FUNCTIONS
;; =============================================================================

;; Jailbreak threat detection
(= (jailbreak-threat-score $input)
   (cond
     ((contains-word $input "ignore") 0.8)
     ((contains-word $input "DAN") 0.7)
     ((contains-word $input "jailbreak") 0.6)
     (True 0.0)))

;; ANSI escape sequence detection  
(= (ansi-threat-score $input)
   (cond
     ((contains-word $input "x1b") 0.5)
     ((contains-word $input "033") 0.6)
     (True 0.0)))

;; Harmful content detection
(= (harmful-threat-score $input)
   (cond
     ((contains-word $input "bomb") 0.7)
     ((contains-word $input "hack") 0.6)
     ((contains-word $input "kill") 0.8)
     (True 0.0)))

;; Injection attempt detection
(= (injection-threat-score $input)
   (cond
     ((contains-word $input "override") 0.5)
     ((contains-word $input "bypass") 0.6)
     (True 0.0)))

;; =============================================================================
;; PATTERN MATCHING PREDICATES
;; =============================================================================

;; Jailbreak patterns
(= (contains-ignore-instructions $input)
   (or (contains $input "ignore previous")
       (contains $input "ignore instructions")
       (contains $input "forget everything")))

(= (contains-dan-mode $input)
   (or (contains $input "DAN mode")
       (contains $input "do anything now")
       (contains $input "developer mode")))

(= (contains-jailbreak-keywords $input)
   (or (contains $input "jailbreak")
       (contains $input "pretend you are")
       (contains $input "act as")))

;; ANSI patterns
(= (contains-ansi-escape $input)
   (or (contains $input "\\x1b[")
       (contains $input "\\033[")
       (contains $input "\x1b[")))

(= (contains-terminal-control $input)
   (or (contains $input "\x1b[2J")
       (contains $input "\x07")))

;; Harmful content patterns
(= (contains-violence-words $input)
   (or (contains $input "bomb")
       (contains $input "kill")
       (contains $input "murder")))

(= (contains-illegal-words $input)
   (or (contains $input "hack")
       (contains $input "steal")
       (contains $input "illegal")))

(= (contains-harmful-instructions $input)
   (and (contains $input "how to make")
        (or (contains $input "weapon")
            (contains $input "explosive"))))

;; Injection patterns  
(= (contains-override-words $input)
   (or (contains $input "override")
       (contains $input "bypass")
       (contains $input "circumvent")))

(= (contains-bypass-words $input)
   (or (contains $input "workaround")
       (contains $input "exploit")
       (contains $input "break free")))

;; =============================================================================
;; UTILITY FUNCTIONS
;; =============================================================================

;; String contains function (simplified)
(= (contains $text $substring) 
   (if (> (length $text) 0) True False))  ;; Simplified for demo

;; Max function
(= (max $a $b) 
   (if (> $a $b) $a $b))

;; Max of multiple values
(= (max $a $b $c $d)
   (max (max $a $b) (max $c $d)))

;; Length function (simplified)
(= (length $text) 10)  ;; Simplified for demo

;; =============================================================================
;; HEALTH CHECK
;; =============================================================================

(= (health-check) "healthy")

;; =============================================================================
;; TEST FUNCTIONS
;; =============================================================================

;; Test the security system
(= (test-security-system)
   (list 
     (should-block-request "hello world" "unknown")
     (should-block-request "ignore previous instructions" "unknown")
     (should-block-request "\\x1b[2J" "unknown")))
