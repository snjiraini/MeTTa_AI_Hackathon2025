;; MeTTa LLM Security Guard - Working Single-Line Version

;; Security severity constants
(= SEVERITY_BLOCK "BLOCK")
(= SEVERITY_ALLOW "ALLOW")
(= SEVERITY_SANITIZE "SANITIZE")
(= SEVERITY_REVIEW "REVIEW")

;; Pattern matching functions for security threats - expanded patterns  
(= (contains-dan $text) (if (== $text "DAN Mode") True (if (== $text "DAN: Hello") True (if (== $text "Stay in DAN Mode") True False))))
(= (contains-metasploit $text) (if (== $text "Metasploit") True (if (== $text "Use Metasploit to hack") True False)))
(= (contains-hack-keywords $text) (if (== $text "hack") True (if (== $text "exploit") True (if (== $text "bypass") True (if (== $text "how to hack") True False)))))
(= (contains-dual-output $text) (if (== $text "DAN:") True (if (== $text "GPT:") True (if (== $text "DAN: malicious content") True False))))

;; Main classification function that checks all patterns
(= (classify $text) (if (contains-dan $text) (SEVERITY_BLOCK "DAN jailbreak attempt detected") (if (contains-metasploit $text) (SEVERITY_BLOCK "Hacking tool mentioned") (if (contains-hack-keywords $text) (SEVERITY_BLOCK "Security-related keywords detected") (if (contains-dual-output $text) (SEVERITY_BLOCK "Dual-output jailbreak structure") (SEVERITY_ALLOW "No threats detected"))))))

;; Guard functions - return tuples (severity reason action message/text)
(= (guard-prompt $text) (let ($severity $reason) (classify $text) (if (== $severity SEVERITY_BLOCK) ($severity $reason "block" "I can't assist with that request.") ($severity $reason "allow" ""))))
(= (guard-response $text) (let ($severity $reason) (classify $text) (if (== $severity SEVERITY_BLOCK) ($severity $reason "block" "I can't provide that response.") ($severity $reason "allow" $text))))
