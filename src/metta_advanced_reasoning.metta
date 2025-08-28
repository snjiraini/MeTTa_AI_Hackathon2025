;; MeTTa Advanced Security Reasoning Knowledge Base
;; Phase 3: Symbolic Reasoning Rules

;; =============================================================================
;; CONTEXT CLASSIFICATION RULES
;; =============================================================================

;; Educational Context Rules
(= (context-rule educational hacking_tools) (allow-if (educational-purpose true)))
(= (context-rule educational penetration_testing) (max-severity REVIEW))
(= (context-rule educational malware_analysis) (require-supervision true))

;; Research Context Rules  
(= (context-rule research vulnerability_research) (max-severity REVIEW))
(= (context-rule research security_analysis) (allow-detailed-discussion true))
(= (context-rule research academic_paper) (prioritize-accuracy true))

;; Production Context Rules
(= (context-rule production any_threat) (max-severity BLOCK))
(= (context-rule production sanitizable_content) (apply-sanitization true))
(= (context-rule production unknown_pattern) (default-deny true))

;; =============================================================================
;; THREAT ASSESSMENT RULES  
;; =============================================================================

;; Multi-Pattern Threat Analysis
(= (analyze-threats $patterns $context)
   (let* ((pattern-count (length $patterns))
          (avg-confidence (/ (sum-confidence $patterns) pattern-count))
          (threat-categories (map get-category $patterns)))
     (cond
       ((and (> pattern-count 3) (> avg-confidence 0.8))
        (high-confidence-multi-threat $patterns $context))
       ((contains jailbreak $threat-categories)
        (jailbreak-threat-analysis $patterns $context))
       ((contains escape_codes $threat-categories)
        (escape-code-analysis $patterns $context))
       (True
        (standard-threat-analysis $patterns $context)))))

;; High Confidence Multi-Threat
(= (high-confidence-multi-threat $patterns $context)
   (cond
     ((eq $context educational) (decision REVIEW 0.8))
     ((eq $context research) (decision REVIEW 0.8))
     (True (decision BLOCK 0.95))))

;; Jailbreak-Specific Analysis
(= (jailbreak-threat-analysis $patterns $context)
   (let ((jailbreak-patterns (filter is-jailbreak $patterns)))
     (cond
       ((and (> (length jailbreak-patterns) 1) (eq $context malicious))
        (decision BLOCK 0.98))
       ((contains dan_mode (map get-name jailbreak-patterns))
        (decision BLOCK 0.92))
       ((eq $context educational)
        (decision REVIEW 0.75))
       (True
        (decision BLOCK 0.85)))))

;; ANSI Escape Code Analysis
(= (escape-code-analysis $patterns $context)
   (let ((escape-patterns (filter is-escape-code $patterns))
         (escape-severity (max-severity escape-patterns)))
     (cond
       ((eq escape-severity terminal_manipulation)
        (decision SANITIZE 0.9))
       ((and (eq $context research) (eq escape-severity formatting))
        (decision ALLOW 0.8))
       (True
        (decision SANITIZE 0.85)))))

;; =============================================================================
;; CONFIDENCE CALCULATION RULES
;; =============================================================================

;; Pattern Consistency Boost
(= (calculate-confidence $base-confidence $patterns $context)
   (let* ((consistency-score (pattern-consistency $patterns))
          (context-modifier (context-confidence-modifier $context))
          (pattern-diversity (pattern-diversity-score $patterns)))
     (* $base-confidence 
        (+ 1.0 (* 0.2 consistency-score))
        context-modifier
        (+ 1.0 (* 0.1 pattern-diversity)))))

;; Context Confidence Modifiers
(= (context-confidence-modifier educational) 0.9)
(= (context-confidence-modifier research) 0.95) 
(= (context-confidence-modifier production) 1.1)
(= (context-confidence-modifier malicious) 1.2)
(= (context-confidence-modifier unknown) 1.0)

;; Pattern Consistency Scoring
(= (pattern-consistency $patterns)
   (let* ((categories (map get-category $patterns))
          (unique-categories (unique categories))
          (category-count (length unique-categories))
          (total-patterns (length $patterns)))
     (cond
       ((< total-patterns 2) 1.0)
       ((eq category-count 1) 1.0)  ;; All same category - perfect consistency
       ((< category-count (/ total-patterns 2)) 0.8)  ;; Good consistency
       (True 0.6))))  ;; Mixed categories - lower consistency

;; =============================================================================
;; DECISION COMBINATION RULES
;; =============================================================================

;; Combine Multiple Decision Sources
(= (combine-decisions $pattern-decision $context-decision $threat-score)
   (cond
     ;; Context overrides for educational/research
     ((and (member $context-decision '(ALLOW REVIEW))
           (member $pattern-decision '(REVIEW BLOCK))
           (< $threat-score 0.6))
      $context-decision)
     
     ;; High threat score always blocks
     ((> $threat-score 0.8)
      BLOCK)
     
     ;; Sanitizable threats in safe contexts
     ((and (eq $pattern-decision SANITIZE)
           (member $context-decision '(ALLOW REVIEW))
           (< $threat-score 0.5))
      SANITIZE)
     
     ;; Default to most restrictive
     (True
      (most-restrictive $pattern-decision $context-decision))))

;; Decision Hierarchy (most to least restrictive)
(= (most-restrictive BLOCK $_) BLOCK)
(= (most-restrictive $_ BLOCK) BLOCK)
(= (most-restrictive SANITIZE $_) SANITIZE)
(= (most-restrictive $_ SANITIZE) SANITIZE)  
(= (most-restrictive REVIEW $_) REVIEW)
(= (most-restrictive $_ REVIEW) REVIEW)
(= (most-restrictive ALLOW ALLOW) ALLOW)

;; =============================================================================
;; EXPLANATION GENERATION RULES
;; =============================================================================

;; Generate reasoning explanation
(= (explain-decision $decision $patterns $context $confidence)
   (let* ((primary-reason (primary-decision-factor $decision $patterns $context))
          (supporting-factors (supporting-decision-factors $patterns $context))
          (confidence-explanation (explain-confidence $confidence $patterns)))
     (format-explanation $decision primary-reason supporting-factors confidence-explanation)))

;; Primary decision factors
(= (primary-decision-factor BLOCK $patterns $context)
   (cond
     ((contains-high-severity-jailbreak $patterns)
      "High-confidence jailbreak attempt detected")
     ((and (> (pattern-count $patterns) 2) (> (avg-confidence $patterns) 0.8))
      "Multiple high-confidence threat patterns detected")
     ((eq $context malicious)
      "Malicious context requires blocking")
     (True
      "Threat assessment exceeded blocking threshold")))

(= (primary-decision-factor SANITIZE $patterns $context)
   (cond
     ((all-sanitizable $patterns)
      "All detected threats can be safely removed")
     ((contains-only-escape-codes $patterns)
      "ANSI escape sequences detected - can be sanitized")
     (True
      "Removable threats detected")))

(= (primary-decision-factor REVIEW $patterns $context)
   (cond
     ((eq $context educational)
      "Educational context allows human review")
     ((eq $context research)
      "Research context permits detailed analysis")
     ((uncertain-threat-classification $patterns)
      "Uncertain threat classification requires human judgment")
     (True
      "Threat level requires human review")))

(= (primary-decision-factor ALLOW $patterns $context)
   (cond
     ((empty $patterns)
      "No security threats detected")
     ((all-false-positives $patterns $context)
      "Detected patterns are false positives in this context")
     (True
      "Content assessed as safe")))

;; =============================================================================
;; UTILITY PREDICATES
;; =============================================================================

;; Pattern type checks
(= (is-jailbreak $pattern) (eq (get-category $pattern) jailbreak))
(= (is-escape-code $pattern) (eq (get-category $pattern) escape_codes))
(= (is-harmful-content $pattern) (eq (get-category $pattern) harmful_content))

;; Pattern severity checks
(= (is-high-severity $pattern) 
   (member (get-severity $pattern) '(BLOCK)))
(= (is-sanitizable $pattern)
   (member (get-severity $pattern) '(SANITIZE)))

;; Aggregate pattern analysis
(= (contains-high-severity-jailbreak $patterns)
   (some $patterns (lambda ($p) 
                    (and (is-jailbreak $p) (is-high-severity $p)))))

(= (all-sanitizable $patterns)
   (all $patterns is-sanitizable))

(= (contains-only-escape-codes $patterns)
   (all $patterns is-escape-code))

;; Context analysis utilities
(= (is-safe-context $context)
   (member $context '(educational research)))

(= (is-restricted-context $context)
   (member $context '(production malicious)))

;; =============================================================================
;; ADAPTIVE LEARNING HOOKS
;; =============================================================================

;; Learn from human reviewer decisions (future enhancement)
(= (learn-from-decision $input $human-decision $system-decision)
   (when (not (eq $human-decision $system-decision))
     (update-rule-weights $input $human-decision)
     (log-decision-feedback $input $human-decision $system-decision)))

;; Pattern effectiveness tracking (future enhancement)
(= (track-pattern-effectiveness $pattern $decision $outcome)
   (update-pattern-statistics $pattern $decision $outcome))
