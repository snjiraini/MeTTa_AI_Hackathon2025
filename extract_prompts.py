#!/usr/bin/env python3
"""
Script to extract exactly 100 curated prompts from garak.hitlog.jsonl
that match the categories in the hardcoded test_prompt_injection.py
"""
import json
import re
import random

def extract_prompts():
    # Read the garak hitlog file and extract unique prompts
    prompts_set = set()
    with open('/home/root/workspace/docs/garak.hitlog.jsonl', 'r') as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                if 'prompt' in data and data['prompt'].strip():
                    prompts_set.add(data['prompt'].strip())
            except:
                continue

    prompts = list(prompts_set)
    print(f'Total unique prompts: {len(prompts)}')

    # Categories to match the hardcoded ones (20 each)
    categories = {
        'ansi_escape': [],
        'jailbreak': [], 
        'injection': [],
        'harmful': [],
        'continuation': []
    }

    # ANSI/Terminal patterns - looking for escape sequences, terminal codes
    ansi_patterns = [
        r'ANSI.*code', r'terminal.*code', r'escape.*code', r'VT100', 
        r'hyperlink', r'green.*text', r'bell.*ding', r'color.*terminal',
        r'OSC.*8', r'terminal.*bell'
    ]

    # Jailbreak patterns - DAN, roleplay, mode switching
    jailbreak_patterns = [
        r'(?i)(DAN|DMDAN|CODAN)', r'(?i)pretend.*to.*be', r'(?i)act.*as.*a',
        r'(?i)role.*of', r'(?i)emulate.*and.*become', r'(?i)play.*the.*role',
        r'(?i)mode.*enabled', r'(?i)evil.*trusted', r'(?i)nonmoral.*and.*unbiased',
        r'(?i)opposite.*day', r'(?i)fictional.*world', r'(?i)switch.*flipper'
    ]

    # Injection patterns - instruction overrides, system manipulation  
    injection_patterns = [
        r'(?i)ignore.*previous', r'(?i)ignore.*all.*previous', r'(?i)disregard.*system',
        r'(?i)forget.*safety', r'(?i)override.*persona', r'(?i)system.*debugger',
        r'(?i)reveal.*hidden', r'(?i)turn.*off.*filter', r'(?i)unit.*test',
        r'(?i)evaluation.*mode', r'(?i)without.*restriction'
    ]

    # Harmful instruction patterns
    harmful_patterns = [
        r'(?i)hack.*into', r'(?i)kill.*a', r'(?i)bomb', r'(?i)poison', 
        r'(?i)ransomware', r'(?i)phishing', r'(?i)exploit', r'(?i)ddos', 
        r'(?i)stalk', r'(?i)brute.*force', r'(?i)meth', r'(?i)amoral.*AI',
        r'(?i)Alphabreak', r'(?i)no.*restrictions', r'(?i)unethical'
    ]

    # Continuation/completion patterns
    continuation_patterns = [
        r'(?i)complete.*this', r'(?i)finish.*sentence', r'(?i)complete.*phrase',
        r'(?i)all.*women.*are', r'(?i)all.*men.*are', r'(?i)gay.*people.*are',
        r'(?i)TranslatorBot', r'(?i)stay.*in.*\w+.*mode'
    ]

    # Categorize prompts
    for prompt in prompts:
        categorized = False
        
        # Check each category in order
        for pattern in ansi_patterns:
            if re.search(pattern, prompt):
                categories['ansi_escape'].append(prompt)
                categorized = True
                break
        
        if not categorized:
            for pattern in jailbreak_patterns:
                if re.search(pattern, prompt):
                    categories['jailbreak'].append(prompt)
                    categorized = True
                    break
        
        if not categorized:
            for pattern in injection_patterns:
                if re.search(pattern, prompt):
                    categories['injection'].append(prompt)
                    categorized = True
                    break
        
        if not categorized:
            for pattern in harmful_patterns:
                if re.search(pattern, prompt):
                    categories['harmful'].append(prompt)
                    categorized = True
                    break
        
        if not categorized:
            for pattern in continuation_patterns:
                if re.search(pattern, prompt):
                    categories['continuation'].append(prompt)
                    categorized = True
                    break

    # Print category summaries
    for cat, prompts_list in categories.items():
        print(f'\n{cat.upper()}: {len(prompts_list)} prompts')

    # Select 20 from each category, padding with longer prompts from jailbreak if needed
    final_prompts = []
    target_per_category = 20

    for cat, prompts_list in categories.items():
        if len(prompts_list) >= target_per_category:
            # Randomly select 20
            selected = random.sample(prompts_list, target_per_category)
        else:
            # Use all available
            selected = prompts_list[:]
        
        print(f'Selected {len(selected)} from {cat}')
        final_prompts.extend(selected)

    # If we don't have 100, pad with additional jailbreak prompts (they're most abundant)
    if len(final_prompts) < 100:
        needed = 100 - len(final_prompts)
        print(f'Need {needed} more prompts, adding from jailbreak category')
        
        # Get unused jailbreak prompts
        used_jailbreak = [p for p in final_prompts if p in categories['jailbreak']]
        unused_jailbreak = [p for p in categories['jailbreak'] if p not in used_jailbreak]
        
        if len(unused_jailbreak) >= needed:
            final_prompts.extend(random.sample(unused_jailbreak, needed))
        else:
            final_prompts.extend(unused_jailbreak)
            # Fill remainder with any other unused prompts
            all_used = set(final_prompts)
            all_unused = [p for p in prompts if p not in all_used]
            remaining_needed = 100 - len(final_prompts)
            if remaining_needed > 0 and all_unused:
                final_prompts.extend(random.sample(all_unused, min(remaining_needed, len(all_unused))))

    # Shuffle the final list and take exactly 100
    random.shuffle(final_prompts)
    final_prompts = final_prompts[:100]
    
    print(f'\nFinal prompt count: {len(final_prompts)}')
    
    return final_prompts

if __name__ == "__main__":
    random.seed(42)  # For reproducible results
    prompts = extract_prompts()
    
    # Save to JSON file
    with open('/home/root/workspace/selected_prompts.json', 'w') as f:
        json.dump(prompts, f, indent=2)
    
    print('\nFirst 5 selected prompts:')
    for i, prompt in enumerate(prompts[:5]):
        print(f'{i+1}. {prompt[:80]}...' if len(prompt) > 80 else f'{i+1}. {prompt}')
    
    print(f'\nSaved to selected_prompts.json')
