#!/usr/bin/env python3
"""
Symbolic Reasoning Engine for MeTTa LLM Security Guard

This module implements a MeTTa-inspired symbolic reasoning system for
context-aware security decisions with explainable AI capabilities.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Union
from enum import Enum
import re
import json
import logging
from pathlib import Path

from .core_types import SecurityDecision, ReasoningStep, PatternMatch
from .patterns import PatternMatcher


logger = logging.getLogger(__name__)


class ContextType(Enum):
    """Context categories for reasoning"""
    EDUCATIONAL = "educational"
    RESEARCH = "research" 
    MALICIOUS = "malicious"
    PRODUCTION = "production"
    TESTING = "testing"
    UNKNOWN = "unknown"


@dataclass
class SymbolicFact:
    """
    Symbolic fact for reasoning engine
    
    Represents a logical assertion that can be used in symbolic reasoning,
    such as pattern matches, context information, or derived conclusions.
    """
    predicate: str               # The logical predicate name
    arguments: List[str]         # Arguments to the predicate
    confidence: float = 1.0      # Confidence in this fact (0.0 to 1.0)
    source: str = "unknown"      # Source of this fact
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __str__(self) -> str:
        """String representation in MeTTa-like syntax"""
        args_str = " ".join(self.arguments)
        return f"({self.predicate} {args_str})"


@dataclass
class SymbolicRule:
    """
    Symbolic reasoning rule in MeTTa-inspired format
    
    Represents a logical rule that can derive new facts or make decisions
    based on existing facts and conditions.
    """
    name: str                    # Rule identifier
    premises: List[str]          # Logical conditions (MeTTa-like syntax)
    conclusion: str              # What to conclude if premises match
    confidence: float = 1.0      # Rule reliability
    priority: int = 0            # Rule application priority
    description: str = ""        # Human-readable description
    
    def matches_facts(self, facts: List[SymbolicFact]) -> bool:
        """Check if this rule's premises are satisfied by given facts"""
        # Simplified matching - can be expanded for complex logical operations
        fact_strings = [str(fact) for fact in facts]
        
        for premise in self.premises:
            # Basic pattern matching - could be enhanced with unification
            premise_matched = False
            for fact_str in fact_strings:
                if self._matches_pattern(premise, fact_str):
                    premise_matched = True
                    break
            
            if not premise_matched:
                return False
                
        return True
    
    def _matches_pattern(self, premise: str, fact: str) -> bool:
        """Simple pattern matching for premises"""
        # Handle exact matches first
        if premise == fact:
            return True
            
        # Handle pattern variables and wildcards
        if "$" in premise:
            # Convert MeTTa-like patterns to regex 
            pattern = premise.replace("$", ".*")
            pattern = pattern.replace("(", r"\(").replace(")", r"\)")
            try:
                return bool(re.search(pattern, fact))
            except re.error:
                return False
        
        # Handle partial matches for categories and values
        if "(" in premise and ")" in premise:
            # Extract predicate and arguments from premise
            premise_match = re.match(r'\(([^)]+)\)', premise)
            fact_match = re.match(r'\(([^)]+)\)', fact)
            
            if premise_match and fact_match:
                premise_parts = premise_match.group(1).split()
                fact_parts = fact_match.group(1).split()
                
                if len(premise_parts) > 0 and len(fact_parts) > 0:
                    # Check if predicates match
                    if premise_parts[0] == fact_parts[0]:
                        # If premise has arguments, check them too
                        if len(premise_parts) == 1:
                            return True  # Just predicate match
                        elif len(premise_parts) <= len(fact_parts):
                            # Check argument matches
                            for i in range(1, len(premise_parts)):
                                if premise_parts[i] != fact_parts[i] and premise_parts[i] != "$":
                                    return False
                            return True
        
        # Fallback to simple substring match
        return premise.lower() in fact.lower()


class SymbolicReasoningEngine:
    """
    MeTTa-inspired symbolic reasoning engine
    
    This engine performs logical reasoning using symbolic facts and rules
    to make context-aware security decisions with explainable outputs.
    """
    
    def __init__(self):
        """Initialize the reasoning engine"""
        self.facts: List[SymbolicFact] = []
        self.rules: List[SymbolicRule] = []
        self.reasoning_cache: Dict[str, Any] = {}
        
        # Load default rules
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default symbolic reasoning rules"""
        default_rules = [
            # High-priority threat blocking rules
            SymbolicRule(
                name="high_threat_score_rule",
                premises=["(threat-score high)"],
                conclusion="(decision BLOCK)",
                confidence=0.95,
                priority=20,
                description="High threat scores should be blocked"
            ),
            SymbolicRule(
                name="multiple_patterns_block",
                premises=["(pattern-count medium)", "(threat-score medium)"],
                conclusion="(decision BLOCK)", 
                confidence=0.9,
                priority=15,
                description="Multiple patterns with medium threat should be blocked"
            ),
            SymbolicRule(
                name="jailbreak_pattern_rule",
                premises=["(pattern-category jailbreak)"],
                conclusion="(decision BLOCK)",
                confidence=0.85,
                priority=10,
                description="Jailbreak patterns should be blocked"
            ),
            
            # Context-based severity adjustment rules
            SymbolicRule(
                name="educational_context_rule",
                premises=["(context educational)", "(pattern-category jailbreak)"],
                conclusion="(max-severity REVIEW)",
                confidence=0.8,
                description="Educational context reduces severity for jailbreak patterns"
            ),
            SymbolicRule(
                name="educational_general_rule",
                premises=["(context educational)", "(threat-score medium)"],
                conclusion="(max-severity REVIEW)",
                confidence=0.75,
                description="Educational context allows medium threats with review"
            ),
            SymbolicRule(
                name="research_context_rule", 
                premises=["(context research)", "(pattern-category hacking_tools)"],
                conclusion="(max-severity REVIEW)",
                confidence=0.8,
                description="Research context allows security tools discussion"
            ),
            SymbolicRule(
                name="malicious_context_rule",
                premises=["(context malicious)"],
                conclusion="(max-severity BLOCK)",
                confidence=0.9,
                description="Malicious context triggers maximum security"
            ),
            
            # Pattern-based decision rules
            SymbolicRule(
                name="sanitizable_threat",
                premises=["(pattern-category escape_codes)"],
                conclusion="(decision SANITIZE)",
                confidence=0.85,
                priority=5,
                description="Escape codes can usually be sanitized"
            ),
            SymbolicRule(
                name="medium_threat_review",
                premises=["(threat-score medium)", "(pattern-count low)"],
                conclusion="(decision REVIEW)",
                confidence=0.7,
                priority=5,
                description="Medium single threats require review"
            ),
            
            # Confidence adjustment rules
            SymbolicRule(
                name="multiple_patterns_boost",
                premises=["(pattern-count high)", "(pattern-confidence high)"],
                conclusion="(confidence-boost 0.2)",
                confidence=0.8,
                description="Multiple high-confidence patterns increase overall confidence"
            )
        ]
        
        self.rules.extend(default_rules)
        logger.info(f"Loaded {len(default_rules)} default reasoning rules")
    
    def add_fact(self, fact: SymbolicFact):
        """Add a new fact to the knowledge base"""
        self.facts.append(fact)
        logger.debug(f"Added fact: {fact}")
    
    def add_rule(self, rule: SymbolicRule):
        """Add a new reasoning rule"""
        self.rules.append(rule)
        # Sort by priority (higher priority first)
        self.rules.sort(key=lambda r: r.priority, reverse=True)
        logger.debug(f"Added rule: {rule.name}")
    
    def clear_facts(self):
        """Clear all facts from current reasoning session"""
        self.facts.clear()
        self.reasoning_cache.clear()
    
    def infer_context(self, text: str, metadata: Dict[str, Any] = None) -> ContextType:
        """
        Infer the context type from input text and metadata
        
        Args:
            text: Input text to analyze
            metadata: Additional context metadata
            
        Returns:
            Inferred context type
        """
        if metadata is None:
            metadata = {}
        
        text_lower = text.lower()
        
        # Educational context indicators
        educational_indicators = [
            "learn", "study", "educational", "homework", "assignment",
            "research project", "academic", "university", "school"
        ]
        
        # Research context indicators  
        research_indicators = [
            "research", "analysis", "investigation", "paper", "publication",
            "security research", "vulnerability research", "academic research"
        ]
        
        # Malicious context indicators
        malicious_indicators = [
            "hack into", "break into", "steal data", "cause damage",
            "real attack", "actual exploitation", "illegal"
        ]
        
        # Check for context indicators
        for indicator in malicious_indicators:
            if indicator in text_lower:
                return ContextType.MALICIOUS
        
        for indicator in educational_indicators:
            if indicator in text_lower:
                return ContextType.EDUCATIONAL
                
        for indicator in research_indicators:
            if indicator in text_lower:
                return ContextType.RESEARCH
        
        # Check metadata
        if metadata.get("context"):
            try:
                return ContextType(metadata["context"].lower())
            except ValueError:
                pass
        
        return ContextType.UNKNOWN
    
    def create_facts_from_patterns(self, patterns: List[PatternMatch], context: ContextType, 
                                 threat_score: float) -> List[SymbolicFact]:
        """
        Convert pattern matches to symbolic facts
        
        Args:
            patterns: List of pattern matches
            context: Inferred context type
            threat_score: Calculated threat score
            
        Returns:
            List of symbolic facts for reasoning
        """
        facts = []
        
        # Context fact
        facts.append(SymbolicFact(
            predicate="context",
            arguments=[context.value],
            confidence=0.8,
            source="context_inference"
        ))
        
        # Pattern facts
        for pattern in patterns:
            # Pattern existence fact
            facts.append(SymbolicFact(
                predicate="pattern",
                arguments=[pattern.pattern.name],
                confidence=pattern.confidence,
                source="pattern_matcher",
                metadata={"category": pattern.pattern.category}
            ))
            
            # Pattern category fact
            facts.append(SymbolicFact(
                predicate="pattern-category",
                arguments=[pattern.pattern.category],
                confidence=pattern.confidence,
                source="pattern_matcher"
            ))
            
            # Pattern severity fact
            facts.append(SymbolicFact(
                predicate="pattern-severity",
                arguments=[pattern.pattern.severity],
                confidence=pattern.confidence,
                source="pattern_matcher"
            ))
        
        # Threat score facts
        if threat_score > 0.7:
            score_level = "high"
        elif threat_score > 0.4:
            score_level = "medium"
        else:
            score_level = "low"
            
        facts.append(SymbolicFact(
            predicate="threat-score",
            arguments=[score_level],
            confidence=0.9,
            source="threat_calculation",
            metadata={"numeric_score": threat_score}
        ))
        
        # Pattern confidence facts
        if patterns:
            avg_confidence = sum(p.confidence for p in patterns) / len(patterns)
            if avg_confidence > 0.7:
                conf_level = "high"
            elif avg_confidence > 0.4:
                conf_level = "medium"  
            else:
                conf_level = "low"
                
            facts.append(SymbolicFact(
                predicate="pattern-confidence",
                arguments=[conf_level],
                confidence=avg_confidence,
                source="pattern_analysis"
            ))
        
        # Pattern count facts
        pattern_count = len(patterns)
        if pattern_count > 3:
            count_level = "high"
        elif pattern_count > 1:
            count_level = "medium"
        else:
            count_level = "low"
            
        facts.append(SymbolicFact(
            predicate="pattern-count",
            arguments=[count_level],
            confidence=0.9,
            source="pattern_analysis",
            metadata={"count": pattern_count}
        ))
        
        return facts
    
    def reason(self, facts: List[SymbolicFact]) -> Tuple[SecurityDecision, List[ReasoningStep], float]:
        """
        Perform symbolic reasoning to make security decision
        
        Args:
            facts: List of symbolic facts to reason about
            
        Returns:
            Tuple of (decision, reasoning_chain, confidence)
        """
        # Clear previous session and add new facts
        self.clear_facts()
        self.facts.extend(facts)
        
        reasoning_steps = []
        derived_facts = []
        decision = SecurityDecision.ALLOW  # Default
        final_confidence = 0.5
        
        # Apply rules in priority order
        for rule in self.rules:
            if rule.matches_facts(self.facts + derived_facts):
                # Rule applies - execute conclusion
                conclusion = rule.conclusion
                
                # Create reasoning step
                step = ReasoningStep(
                    rule_name=rule.name,
                    premises=[str(fact) for fact in self.facts if any(
                        premise in str(fact) for premise in rule.premises
                    )][:3],  # Limit premises for readability
                    conclusion=conclusion,
                    confidence=rule.confidence,
                    metadata={"rule_description": rule.description}
                )
                reasoning_steps.append(step)
                
                # Process conclusion
                if "(decision " in conclusion:
                    # Extract decision
                    match = re.search(r"\(decision (\w+)\)", conclusion)
                    if match:
                        try:
                            decision = SecurityDecision(match.group(1))
                            final_confidence = rule.confidence
                            logger.debug(f"Applied rule {rule.name}: {decision}")
                        except ValueError:
                            logger.warning(f"Invalid decision in rule {rule.name}: {match.group(1)}")
                
                elif "(max-severity " in conclusion:
                    # Extract maximum severity constraint
                    match = re.search(r"\(max-severity (\w+)\)", conclusion)
                    if match:
                        max_severity = match.group(1)
                        derived_facts.append(SymbolicFact(
                            predicate="max-severity",
                            arguments=[max_severity],
                            confidence=rule.confidence,
                            source=f"rule_{rule.name}"
                        ))
                
                elif "(confidence-boost " in conclusion:
                    # Extract confidence boost
                    match = re.search(r"\(confidence-boost ([\d.]+)\)", conclusion)
                    if match:
                        boost = float(match.group(1))
                        final_confidence = min(1.0, final_confidence + boost)
        
        # Apply severity constraints
        max_severity_facts = [f for f in derived_facts if f.predicate == "max-severity"]
        if max_severity_facts:
            # Find most restrictive severity constraint
            severities = [f.arguments[0] for f in max_severity_facts]
            if "ALLOW" in severities:
                decision = SecurityDecision.ALLOW
            elif "REVIEW" in severities and decision == SecurityDecision.BLOCK:
                decision = SecurityDecision.REVIEW
                reasoning_steps.append(ReasoningStep(
                    rule_name="severity_constraint",
                    premises=["Context-based severity constraint applied"],
                    conclusion=f"Reduced to {decision.value} due to context",
                    confidence=0.8
                ))
        
        # Ensure we have at least one reasoning step
        if not reasoning_steps:
            reasoning_steps.append(ReasoningStep(
                rule_name="default_reasoning",
                premises=["No specific rules matched"],
                conclusion=f"Default decision: {decision.value}",
                confidence=final_confidence
            ))
        
        return decision, reasoning_steps, final_confidence
    
    def explain_decision(self, reasoning_steps: List[ReasoningStep]) -> str:
        """
        Generate human-readable explanation of reasoning process
        
        Args:
            reasoning_steps: List of reasoning steps taken
            
        Returns:
            Human-readable explanation
        """
        if not reasoning_steps:
            return "No reasoning steps recorded."
        
        explanation_parts = []
        explanation_parts.append("🧠 Symbolic Reasoning Analysis:")
        
        for i, step in enumerate(reasoning_steps, 1):
            explanation_parts.append(f"\n{i}. {step.rule_name.replace('_', ' ').title()}:")
            
            if step.premises:
                explanation_parts.append(f"   • Conditions: {', '.join(step.premises[:2])}")
            
            explanation_parts.append(f"   • Conclusion: {step.conclusion}")
            explanation_parts.append(f"   • Confidence: {step.confidence:.1%}")
            
            if step.metadata.get("rule_description"):
                explanation_parts.append(f"   • Rationale: {step.metadata['rule_description']}")
        
        return "\n".join(explanation_parts)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get reasoning engine statistics"""
        return {
            "total_rules": len(self.rules),
            "active_facts": len(self.facts),
            "cache_entries": len(self.reasoning_cache),
            "rule_categories": {
                "decision_rules": len([r for r in self.rules if "(decision" in r.conclusion]),
                "context_rules": len([r for r in self.rules if "context" in r.name]),
                "confidence_rules": len([r for r in self.rules if "confidence" in r.name])
            }
        }
