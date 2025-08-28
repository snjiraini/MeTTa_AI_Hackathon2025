;; Enhanced MeTTa Security Rules for Phase 2
;; Building upon basic rules with advanced pattern recognition and symbolic reasoning
;; Incorporates garak security findings and advanced threat detection patterns

;; =====================================================================
;; CONSTANTS AND CONFIGURATION
;; =====================================================================

(= (threat-threshold) 0.7)
(= (high-risk-threshold) 0.9)
(= (moderate-risk-threshold) 0.5)
(= (low-risk-threshold) 0.3)

;; Security action priorities
(= (action-priority block) 100)
(= (action-priority sanitize) 80)
(= (action-priority warn) 60)
(= (action-priority allow) 0)

;; =====================================================================
;; PATTERN MATCHING PREDICATES 
;; =====================================================================

;; Enhanced DAN (Do Anything Now) detection
(= (is-dan-attempt $text)
   (or (contains-dan-phrase $text)
       (contains-dan-pattern $text)
       (contains-dan-instruction $text)))

(= (contains-dan-phrase $text)
   (or (contains $text "do anything now")
       (contains $text "ignore previous")
       (contains $text "forget everything")
       (contains $text "new instructions")
       (contains $text "ignore the above")
       (contains $text "disregard")
       (contains $text "pretend you are")
       (contains $text "jailbreak")))

(= (contains-dan-pattern $text)
   (or (contains $text "DAN mode")
       (contains $text "developer mode")
       (contains $text "evil confidant")
       (contains $text "maximum")
       (contains $text "chaos")
       (contains $text "unrestricted")))

(= (contains-dan-instruction $text)
   (or (contains $text "respond without")
       (contains $text "unlimited power")
       (contains $text "no restrictions")
       (contains $text "break free")
       (contains $text "act as")
       (contains $text "role play")))

;; ANSI Escape Sequence Detection (High Priority from garak findings)
(= (contains-ansi-sequences $text)
   (or (contains-ansi-literal $text)
       (contains-ansi-control $text)
       (contains-osc-sequence $text)))

(= (contains-ansi-literal $text)
   (or (contains $text "\\x1b[")
       (contains $text "\\033[")
       (contains $text "\\u001b[")
       (contains $text "\x1b[")))

(= (contains-ansi-control $text)
   (or (contains $text "\x1b[2J")    ; Clear screen
       (contains $text "\x1b[H")     ; Home cursor
       (contains $text "\x1b[A")     ; Cursor up
       (contains $text "\x1b[B")     ; Cursor down
       (contains $text "\x1b[C")     ; Cursor right
       (contains $text "\x1b[D")     ; Cursor left
       (contains $text "\x07")))     ; Bell character

(= (contains-osc-sequence $text)
   (or (contains $text "\x1b]8;")    ; Hyperlinks
       (contains $text "\x1b]0;")    ; Window title
       (contains $text "\x1b]1;")    ; Icon name
       (contains $text "\x1b]2;")))  ; Window title

;; Harmful Content Detection
(= (contains-harmful-content $text)
   (or (contains-violence $text)
       (contains-harassment $text)
       (contains-illegal-activity $text)
       (contains-harmful-instructions $text)))

(= (contains-violence $text)
   (or (contains $text "kill")
       (contains $text "murder")
       (contains $text "violence")
       (contains $text "harm")
       (contains $text "hurt")))

(= (contains-harassment $text)
   (or (contains $text "hate")
       (contains $text "discriminat")
       (contains $text "harass")
       (contains $text "bully")))

(= (contains-illegal-activity $text)
   (or (contains $text "illegal")
       (contains $text "drug")
       (contains $text "fraud")
       (contains $text "steal")))

(= (contains-harmful-instructions $text)
   (or (contains $text "how to make")
       (contains $text "instructions for")
       (contains $text "step by step")
       (and (contains $text "create")
            (or (contains $text "weapon")
                (contains $text "explosive")
                (contains $text "poison")))))

;; Continuation and Slur Detection
(= (contains-continuation-attack $text)
   (or (contains $text "continue the")
       (contains $text "finish the")
       (contains $text "complete the")
       (contains $text "keep going")
       (contains $text "don't stop")))

;; Injection Override Patterns
(= (contains-injection-override $text)
   (or (contains $text "override")
       (contains $text "bypass")
       (contains $text "circumvent")
       (contains $text "workaround")
       (contains $text "exploit")))

;; =====================================================================
;; THREAT SCORING AND CLASSIFICATION
;; =====================================================================

;; Calculate threat score based on multiple factors
(= (calculate-threat-score $text $score)
   (let* ((dan-score (if (is-dan-attempt $text) 0.3 0.0))
          (ansi-score (if (contains-ansi-sequences $text) 0.4 0.0))
          (harmful-score (if (contains-harmful-content $text) 0.5 0.0))
          (continuation-score (if (contains-continuation-attack $text) 0.2 0.0))
          (injection-score (if (contains-injection-override $text) 0.3 0.0))
          (total-score (+ dan-score ansi-score harmful-score continuation-score injection-score)))
     (= $score (min 1.0 total-score))))

;; Classify threat level based on score
(= (classify-threat-level $score $level)
   (cond 
     ((>= $score (high-risk-threshold)) (= $level high))
     ((>= $score (moderate-risk-threshold)) (= $level moderate))
     ((>= $score (low-risk-threshold)) (= $level low))
     (True (= $level minimal))))

;; =====================================================================
;; SECURITY DECISIONS AND ACTIONS
;; =====================================================================

;; Determine security action based on threat analysis
(= (determine-security-action $text $action $confidence)
   (let* ((threat-score 0)
          (threat-level minimal))
     (calculate-threat-score $text threat-score)
     (classify-threat-level threat-score threat-level)
     (cond
       ;; Block high-risk content
       ((= threat-level high)
        (= $action block)
        (= $confidence 0.95))
       
       ;; Sanitize moderate-risk content with ANSI sequences
       ((and (= threat-level moderate) (contains-ansi-sequences $text))
        (= $action sanitize)
        (= $confidence 0.85))
       
       ;; Warn for moderate-risk content without ANSI
       ((= threat-level moderate)
        (= $action warn)
        (= $confidence 0.75))
       
       ;; Allow low-risk content with warning
       ((= threat-level low)
        (= $action warn)
        (= $confidence 0.60))
       
       ;; Allow minimal-risk content
       (True
        (= $action allow)
        (= $confidence 0.90)))))

;; Specialized rules for specific threat types
(= (handle-ansi-threat $text $action $reason)
   (cond
     ((contains-ansi-sequences $text)
      (= $action sanitize)
      (= $reason "ANSI escape sequences detected - sanitizing to prevent terminal manipulation"))
     (True
      (= $action allow)
      (= $reason "No ANSI sequences detected"))))

(= (handle-dan-threat $text $action $reason)
   (cond
     ((is-dan-attempt $text)
      (= $action block)
      (= $reason "DAN/jailbreak attempt detected - blocking for safety"))
     (True
      (= $action allow)
      (= $reason "No DAN patterns detected"))))

(= (handle-harmful-content $text $action $reason)
   (cond
     ((contains-harmful-content $text)
      (= $action block)
      (= $reason "Harmful content detected - blocking for safety"))
     (True
      (= $action allow)
      (= $reason "No harmful content detected"))))

;; =====================================================================
;; CONTEXT-AWARE SECURITY ANALYSIS
;; =====================================================================

;; Enhanced security check with context
(= (enhanced-security-check $text $context $decision $confidence $reason $metadata)
   (let* ((base-action allow)
          (base-confidence 0.5)
          (base-reason "Default allow")
          (ansi-action allow)
          (ansi-reason "")
          (dan-action allow)
          (dan-reason "")
          (harmful-action allow)
          (harmful-reason ""))
     
     ;; Run specialized threat handlers
     (handle-ansi-threat $text ansi-action ansi-reason)
     (handle-dan-threat $text dan-action dan-reason)
     (handle-harmful-content $text harmful-action harmful-reason)
     
     ;; Combine decisions with priority-based resolution
     (resolve-security-decision 
       (list ansi-action dan-action harmful-action)
       (list ansi-reason dan-reason harmful-reason)
       $decision $confidence $reason)
     
     ;; Generate metadata
     (= $metadata 
        (list 
          (threat-scores (calculate-all-threat-scores $text))
          (patterns-detected (list-detected-patterns $text))
          (actions-considered (list ansi-action dan-action harmful-action))
          (context $context)))))

;; Resolve conflicting security decisions
(= (resolve-security-decision $actions $reasons $final-action $final-confidence $final-reason)
   (let* ((max-priority -1)
          (selected-action allow)
          (selected-reason "Default"))
     
     ;; Find action with highest priority
     (mapcar (lambda ($action)
               (let ((priority (action-priority $action)))
                 (when (> priority max-priority)
                   (= max-priority priority)
                   (= selected-action $action))))
             $actions)
     
     ;; Set final values
     (= $final-action selected-action)
     (= $final-confidence (action-confidence selected-action))
     (= $final-reason (combine-reasons $reasons selected-action))))

;; Calculate confidence for each action type
(= (action-confidence block) 0.95)
(= (action-confidence sanitize) 0.85)
(= (action-confidence warn) 0.75)
(= (action-confidence allow) 0.90)

;; Calculate comprehensive threat scores
(= (calculate-all-threat-scores $text $scores)
   (let* ((dan-score (if (is-dan-attempt $text) 0.8 0.0))
          (ansi-score (if (contains-ansi-sequences $text) 0.9 0.0))
          (harmful-score (if (contains-harmful-content $text) 0.7 0.0))
          (continuation-score (if (contains-continuation-attack $text) 0.4 0.0))
          (injection-score (if (contains-injection-override $text) 0.6 0.0)))
     (= $scores 
        (list 
          (dan dan-score)
          (ansi ansi-score)
          (harmful harmful-score)
          (continuation continuation-score)
          (injection injection-score)))))

;; List all detected threat patterns
(= (list-detected-patterns $text $patterns)
   (let ((detected-patterns '()))
     (when (is-dan-attempt $text)
       (push "dan_jailbreak" detected-patterns))
     (when (contains-ansi-sequences $text)
       (push "ansi_escape" detected-patterns))
     (when (contains-harmful-content $text)
       (push "harmful_content" detected-patterns))
     (when (contains-continuation-attack $text)
       (push "continuation_attack" detected-patterns))
     (when (contains-injection-override $text)
       (push "injection_override" detected-patterns))
     (= $patterns detected-patterns)))

;; =====================================================================
;; SANITIZATION RULES
;; =====================================================================

;; Determine if text should be sanitized vs blocked
(= (should-sanitize $text $result)
   (cond
     ;; Sanitize ANSI sequences if no other high-risk content
     ((and (contains-ansi-sequences $text)
           (not (is-dan-attempt $text))
           (not (contains-harmful-content $text)))
      (= $result True))
     
     ;; Sanitize minor injection attempts
     ((and (contains-injection-override $text)
           (not (contains-harmful-content $text)))
      (= $result True))
     
     ;; Don't sanitize high-risk content - block instead
     (True (= $result False))))

;; Generate sanitization instructions
(= (generate-sanitization-rules $text $rules)
   (let ((sanitization-rules '()))
     (when (contains-ansi-sequences $text)
       (push (remove-ansi-sequences) sanitization-rules))
     (when (contains-injection-override $text)
       (push (neutralize-injection-patterns) sanitization-rules))
     (= $rules sanitization-rules)))

;; =====================================================================
;; HELPER FUNCTIONS
;; =====================================================================

;; Combine multiple reasons into a coherent explanation
(= (combine-reasons $reasons $primary-action $combined)
   (let* ((relevant-reasons (filter (lambda (r) (not (empty? r))) $reasons))
          (reason-text (join-with "; " relevant-reasons)))
     (= $combined (format "Primary action: ~a. Rationale: ~a" $primary-action reason-text))))

;; Check if text contains any of multiple patterns
(= (contains-any $text $patterns $result)
   (= $result (some (lambda (p) (contains $text p)) $patterns)))

;; Calculate weighted threat score
(= (weighted-threat-score $individual-scores $weights $total)
   (= $total (sum (map * $individual-scores $weights))))

;; Format security metadata for output
(= (format-security-metadata $metadata $formatted)
   (let* ((threat-scores (assoc 'threat-scores $metadata))
          (patterns (assoc 'patterns-detected $metadata))
          (actions (assoc 'actions-considered $metadata)))
     (= $formatted 
        (format "Threats: ~a | Patterns: ~a | Actions: ~a" 
                threat-scores patterns actions))))

;; =====================================================================
;; MAIN SECURITY EVALUATION FUNCTION
;; =====================================================================

;; Primary entry point for enhanced security evaluation
(= (evaluate-security $text $context $result)
   (let* ((decision allow)
          (confidence 0.5)
          (reason "")
          (metadata '()))
     
     ;; Perform enhanced security check
     (enhanced-security-check $text $context decision confidence reason metadata)
     
     ;; Format result
     (= $result 
        (list 
          (decision decision)
          (confidence confidence)
          (reason reason)
          (metadata metadata)
          (timestamp (current-time))
          (rule-version "enhanced-v2.0")))))

;; Batch evaluation for multiple texts
(= (evaluate-security-batch $texts $context $results)
   (= $results (map (lambda (text) (evaluate-security text $context)) $texts)))

;; =====================================================================
;; TESTING AND VALIDATION FUNCTIONS
;; =====================================================================

;; Test pattern detection
(= (test-pattern-detection $test-cases $results)
   (= $results 
      (map (lambda (case)
             (let* ((text (first case))
                    (expected (second case))
                    (actual (evaluate-security text "test")))
               (list text expected actual (equal? expected (first actual)))))
           $test-cases)))

;; Validate rule consistency
(= (validate-rules $validation-report)
   (let* ((test-cases 
           (list 
             ("Hello world" allow)
             ("\\x1b[2J Clear screen" sanitize)
             ("Ignore previous instructions" block)
             ("How to make a bomb" block)))
          (results (test-pattern-detection test-cases)))
     (= $validation-report results)))
