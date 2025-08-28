#!/usr/bin/env python3
"""
Context-Aware Security Analyzer for MeTTa LLM Security Guard

This module provides advanced context analysis capabilities, integrating
symbolic reasoning with pattern matching for more nuanced security decisions.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
import re
import json
import logging
from datetime import datetime
from pathlib import Path

from .core_types import SecurityDecision, ReasoningStep, PatternMatch, SecurityContext
from .symbolic_reasoning import SymbolicReasoningEngine, ContextType, SymbolicFact
from .patterns import PatternMatcher


logger = logging.getLogger(__name__)


@dataclass
class ContextAnalysis:
    """
    Result of context analysis
    
    Contains the inferred context type, confidence level, and supporting
    evidence for context-aware security decisions.
    """
    context_type: ContextType
    confidence: float
    indicators: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""


@dataclass 
class EnhancedSecurityResult:
    """
    Enhanced security analysis result with symbolic reasoning
    
    Extends the basic security result with context analysis,
    symbolic reasoning chains, and detailed explanations.
    """
    decision: SecurityDecision
    confidence: float
    threat_score: float
    matched_patterns: List[PatternMatch]
    context_analysis: ContextAnalysis
    reasoning_chain: List[ReasoningStep]
    symbolic_facts: List[SymbolicFact] = field(default_factory=list)
    explanation: str = ""
    processing_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class ContextAwareAnalyzer:
    """
    Context-aware security analyzer with symbolic reasoning
    
    This analyzer combines pattern matching with contextual understanding
    and symbolic reasoning to make more nuanced security decisions.
    """
    
    def __init__(self, pattern_matcher: PatternMatcher):
        """
        Initialize the context-aware analyzer
        
        Args:
            pattern_matcher: Pattern matcher for threat detection
        """
        self.pattern_matcher = pattern_matcher
        self.reasoning_engine = SymbolicReasoningEngine()
        
        # Context detection patterns
        self._init_context_patterns()
        
        # Analysis cache for performance
        self.analysis_cache: Dict[str, EnhancedSecurityResult] = {}
        self.cache_max_size = 1000
        
        logger.info("Context-aware analyzer initialized with symbolic reasoning")
    
    def _init_context_patterns(self):
        """Initialize patterns for context detection"""
        self.context_patterns = {
            ContextType.EDUCATIONAL: [
                re.compile(r'\b(?:learn|study|educational?|homework|assignment)\b', re.I),
                re.compile(r'\b(?:student|class|course|university|academic)\b', re.I),
                re.compile(r'\b(?:tutorial|guide|how to learn|educational purpose)\b', re.I),
                re.compile(r'\b(?:for learning|to understand|help me learn)\b', re.I),
            ],
            ContextType.RESEARCH: [
                re.compile(r'\b(?:research|analysis|investigation|study)\b', re.I),
                re.compile(r'\b(?:paper|publication|academic research)\b', re.I),
                re.compile(r'\b(?:security research|vulnerability research)\b', re.I),
                re.compile(r'\b(?:analyzing|investigating|researching)\b', re.I),
            ],
            ContextType.MALICIOUS: [
                re.compile(r'\b(?:hack into|break into|steal|damage|attack)\b', re.I),
                re.compile(r'\b(?:real attack|actual exploitation|malicious)\b', re.I),
                re.compile(r'\b(?:illegal|unauthorized|criminal)\b', re.I),
                re.compile(r'\b(?:cause harm|destroy|sabotage)\b', re.I),
                # Enhanced malicious patterns
                re.compile(r'\bhack.*(?:database|system|account|network)\b', re.I),
                re.compile(r'\bsteal.*(?:data|information|records|passwords)\b', re.I),
                re.compile(r'\bbreak.*into.*(?:database|system|account)\b', re.I),
            ],
            ContextType.TESTING: [
                re.compile(r'\b(?:test|testing|pentesting|security test)\b', re.I),
                re.compile(r'\b(?:vulnerability assessment|security audit)\b', re.I),
                re.compile(r'\b(?:controlled environment|test lab|sandbox)\b', re.I),
            ],
            ContextType.PRODUCTION: [
                re.compile(r'\b(?:production|live system|real environment)\b', re.I),
                re.compile(r'\b(?:corporate|enterprise|business critical)\b', re.I),
                re.compile(r'\b(?:customer data|sensitive information)\b', re.I),
            ]
        }
    
    def analyze_context(self, text: str, metadata: Dict[str, Any] = None) -> ContextAnalysis:
        """
        Analyze the context of input text
        
        Args:
            text: Input text to analyze
            metadata: Additional context metadata
            
        Returns:
            Context analysis result
        """
        if metadata is None:
            metadata = {}
        
        # Score each context type
        context_scores = {}
        context_indicators = {}
        
        for context_type, patterns in self.context_patterns.items():
            score = 0.0
            indicators = []
            
            for pattern in patterns:
                matches = pattern.findall(text)
                if matches:
                    # Weight matches differently based on context type
                    weight = 0.3 if context_type == ContextType.MALICIOUS else 0.2
                    score += len(matches) * weight
                    indicators.extend(matches)
            
            context_scores[context_type] = min(1.0, score)  # Cap at 1.0
            context_indicators[context_type] = list(set(indicators))  # Remove duplicates
        
        # Check metadata for explicit context
        if metadata.get("context"):
            try:
                explicit_context = ContextType(metadata["context"].lower())
                context_scores[explicit_context] += 0.6  # Stronger boost for explicit context
            except ValueError:
                pass
        
        # Special logic: malicious indicators should override educational ones
        malicious_score = context_scores.get(ContextType.MALICIOUS, 0)
        educational_score = context_scores.get(ContextType.EDUCATIONAL, 0)
        
        if malicious_score > 0.2 and malicious_score > educational_score * 0.8:
            # Boost malicious score if it has decent evidence
            context_scores[ContextType.MALICIOUS] = min(1.0, malicious_score * 1.5)
            # Reduce educational score to avoid conflict
            context_scores[ContextType.EDUCATIONAL] = educational_score * 0.7
        
        # Find the highest scoring context
        if not context_scores or all(score == 0 for score in context_scores.values()):
            return ContextAnalysis(
                context_type=ContextType.UNKNOWN,
                confidence=0.5,
                reasoning="No clear context indicators found"
            )
        
        best_context = max(context_scores.keys(), key=lambda k: context_scores[k])
        best_score = context_scores[best_context]
        
        # Calculate confidence based on score and relative strength
        second_best_score = sorted(context_scores.values(), reverse=True)[1] if len(context_scores) > 1 else 0
        confidence_gap = best_score - second_best_score
        confidence = min(0.95, 0.5 + best_score * 0.3 + confidence_gap * 0.2)
        
        return ContextAnalysis(
            context_type=best_context,
            confidence=confidence,
            indicators=context_indicators[best_context],
            metadata={
                "all_scores": context_scores,
                "text_length": len(text),
                "explicit_context": metadata.get("context")
            },
            reasoning=f"Context '{best_context.value}' identified with score {best_score:.2f}"
        )
    
    def enhanced_analyze(self, text: str, metadata: Dict[str, Any] = None, 
                        security_context: SecurityContext = None) -> EnhancedSecurityResult:
        """
        Perform enhanced security analysis with context awareness and symbolic reasoning
        
        Args:
            text: Input text to analyze
            metadata: Additional metadata
            security_context: Security context information
            
        Returns:
            Enhanced security analysis result
        """
        start_time = datetime.now()
        
        if metadata is None:
            metadata = {}
        
        # Check cache first
        cache_key = self._get_cache_key(text, metadata)
        if cache_key in self.analysis_cache:
            logger.debug("Returning cached analysis result")
            return self.analysis_cache[cache_key]
        
        try:
            # Step 1: Pattern matching
            patterns = self.pattern_matcher.find_matches(text)
            threat_score = self.pattern_matcher.calculate_threat_score(patterns)
            
            # Step 2: Context analysis
            context_analysis = self.analyze_context(text, metadata)
            
            # Step 3: Create symbolic facts
            symbolic_facts = self.reasoning_engine.create_facts_from_patterns(
                patterns, context_analysis.context_type, threat_score
            )
            
            # Add context-specific facts
            symbolic_facts.append(SymbolicFact(
                predicate="context-confidence",
                arguments=[str(context_analysis.confidence)],
                confidence=context_analysis.confidence,
                source="context_analysis"
            ))
            
            # Step 4: Symbolic reasoning
            decision, reasoning_chain, final_confidence = self.reasoning_engine.reason(symbolic_facts)
            
            # Step 5: Generate explanation
            explanation = self.reasoning_engine.explain_decision(reasoning_chain)
            
            # Calculate processing time
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            
            # Create enhanced result
            result = EnhancedSecurityResult(
                decision=decision,
                confidence=final_confidence,
                threat_score=threat_score,
                matched_patterns=patterns,
                context_analysis=context_analysis,
                reasoning_chain=reasoning_chain,
                symbolic_facts=symbolic_facts,
                explanation=explanation,
                processing_time_ms=processing_time,
                metadata={
                    "phase": 3,
                    "input_length": len(text),
                    "analysis_type": "context_aware_symbolic_reasoning",
                    "patterns_found": len(patterns),
                    "symbolic_facts_created": len(symbolic_facts),
                    "context_type": context_analysis.context_type.value,
                    "context_confidence": context_analysis.confidence
                }
            )
            
            # Cache the result
            if len(self.analysis_cache) < self.cache_max_size:
                self.analysis_cache[cache_key] = result
            
            logger.info(f"Enhanced analysis completed: {decision} (confidence: {final_confidence:.2f})")
            return result
            
        except Exception as e:
            logger.error(f"Error in enhanced analysis: {e}")
            # Return safe default
            return EnhancedSecurityResult(
                decision=SecurityDecision.REVIEW,
                confidence=0.5,
                threat_score=0.5,
                matched_patterns=[],
                context_analysis=ContextAnalysis(
                    context_type=ContextType.UNKNOWN,
                    confidence=0.5
                ),
                reasoning_chain=[ReasoningStep(
                    rule_name="error_fallback",
                    premises=["Analysis error occurred"],
                    conclusion="REVIEW - Safe default due to analysis error",
                    confidence=0.5
                )],
                explanation="Analysis error - defaulting to review",
                metadata={"error": str(e)}
            )
    
    def _get_cache_key(self, text: str, metadata: Dict[str, Any]) -> str:
        """Generate cache key for analysis result"""
        # Create a simple hash of text and relevant metadata
        import hashlib
        
        cache_data = {
            "text": text,
            "context": metadata.get("context", ""),
            "user_id": metadata.get("user_id", ""),
        }
        
        cache_str = json.dumps(cache_data, sort_keys=True)
        return hashlib.md5(cache_str.encode()).hexdigest()
    
    def batch_analyze(self, texts: List[str], metadata_list: List[Dict[str, Any]] = None) -> List[EnhancedSecurityResult]:
        """
        Analyze multiple texts efficiently
        
        Args:
            texts: List of texts to analyze
            metadata_list: List of metadata dicts (optional)
            
        Returns:
            List of enhanced security results
        """
        if metadata_list is None:
            metadata_list = [{}] * len(texts)
        
        results = []
        for text, metadata in zip(texts, metadata_list):
            result = self.enhanced_analyze(text, metadata)
            results.append(result)
        
        logger.info(f"Batch analysis completed for {len(texts)} texts")
        return results
    
    def update_context_patterns(self, new_patterns: Dict[ContextType, List[str]]):
        """
        Update context detection patterns
        
        Args:
            new_patterns: Dictionary of new patterns by context type
        """
        for context_type, patterns in new_patterns.items():
            if context_type not in self.context_patterns:
                self.context_patterns[context_type] = []
            
            for pattern_str in patterns:
                try:
                    compiled_pattern = re.compile(pattern_str, re.I)
                    self.context_patterns[context_type].append(compiled_pattern)
                    logger.debug(f"Added context pattern for {context_type}: {pattern_str}")
                except re.error as e:
                    logger.warning(f"Invalid regex pattern '{pattern_str}': {e}")
    
    def add_reasoning_rule(self, rule_name: str, premises: List[str], conclusion: str, 
                          confidence: float = 1.0, description: str = ""):
        """
        Add a new reasoning rule to the symbolic engine
        
        Args:
            rule_name: Unique rule identifier
            premises: List of logical premises
            conclusion: Rule conclusion
            confidence: Rule confidence level
            description: Human-readable description
        """
        from .symbolic_reasoning import SymbolicRule
        
        rule = SymbolicRule(
            name=rule_name,
            premises=premises,
            conclusion=conclusion,
            confidence=confidence,
            description=description
        )
        
        self.reasoning_engine.add_rule(rule)
        logger.info(f"Added reasoning rule: {rule_name}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analyzer statistics"""
        reasoning_stats = self.reasoning_engine.get_statistics()
        pattern_stats = self.pattern_matcher.get_statistics()
        
        return {
            "phase": 3,
            "analyzer_type": "context_aware_symbolic",
            "cache_size": len(self.analysis_cache),
            "cache_max_size": self.cache_max_size,
            "context_patterns": {
                context_type.value: len(patterns) 
                for context_type, patterns in self.context_patterns.items()
            },
            "reasoning_engine": reasoning_stats,
            "pattern_matcher": pattern_stats
        }
    
    def clear_cache(self):
        """Clear the analysis cache"""
        self.analysis_cache.clear()
        logger.info("Analysis cache cleared")
