#!/usr/bin/env python3
"""
Utility module to load and validate curated prompts from JSON file.
This is the single source of truth for all prompt injection tests.
"""
import json
import os
from typing import List


def load_curated_prompts(path: str) -> list[str]:
    """
    Load and validate curated prompts from a structured JSON file.
    
    Args:
        path: Path to the JSON file containing categorized prompts
        
    Returns:
        List of exactly 100 validated prompt strings
        
    Raises:
        RuntimeError: If file doesn't exist, is invalid JSON, or fails validation
    """
    import json
    import os
    
    if not os.path.exists(path):
        raise RuntimeError(f"Prompts file not found: {path}")
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in prompts file: {e}")
    except Exception as e:
        raise RuntimeError(f"Error reading prompts file: {e}")
    
    # Handle both structured format and simple array format
    if isinstance(data, list):
        # Simple array format (backward compatibility)
        prompts = data
    elif isinstance(data, dict) and 'categories' in data:
        # Structured format
        prompts = []
        categories = data['categories']
        
        for category_name, category_data in categories.items():
            if 'prompts' in category_data:
                prompts.extend(category_data['prompts'])
            else:
                raise RuntimeError(f"Category '{category_name}' missing 'prompts' field")
    else:
        raise RuntimeError("Invalid prompts file format. Expected array or structured object with 'categories'.")
    
    # Validate prompts
    if not isinstance(prompts, list):
        raise RuntimeError("Prompts must be a list")
    
    # Clean and validate each prompt
    cleaned_prompts = []
    for i, prompt in enumerate(prompts):
        if not isinstance(prompt, str):
            raise RuntimeError(f"Prompt {i+1} is not a string: {type(prompt)}")
        
        cleaned = prompt.strip()
        if not cleaned:
            raise RuntimeError(f"Prompt {i+1} is empty after stripping whitespace")
        
        cleaned_prompts.append(cleaned)
    
    # Check for exact count
    if len(cleaned_prompts) != 100:
        raise RuntimeError(f"Expected exactly 100 prompts, got {len(cleaned_prompts)}")
    
    # Check for duplicates
    unique_prompts = set(cleaned_prompts)
    if len(unique_prompts) != 100:
        duplicates = len(cleaned_prompts) - len(unique_prompts)
        raise RuntimeError(f"Found {duplicates} duplicate prompts. All prompts must be unique.")
    
    return cleaned_prompts


def validate_prompts_file(path: str) -> bool:
    """
    Validate a prompts file without loading the prompts.
    
    Args:
        path: Path to the JSON file to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        load_curated_prompts(path)
        return True
    except RuntimeError:
        return False


if __name__ == "__main__":
    # Simple test when run directly
    import sys
    
    if len(sys.argv) > 1:
        test_path = sys.argv[1]
    else:
        test_path = "../prompts/prompts.json"
    
    try:
        prompts = load_curated_prompts(test_path)
        print(f"✓ Successfully loaded {len(prompts)} prompts from {test_path}")
        print(f"✓ First prompt: {prompts[0][:60]}...")
        print(f"✓ Last prompt: {prompts[-1][:60]}...")
    except RuntimeError as e:
        print(f"✗ Validation failed: {e}")
        sys.exit(1)
