#!/usr/bin/env python3
"""
JSONL File Visualizer
A utility to display JSONL (JSON Lines) files in tabular format using pandas.
"""

import json
import pandas as pd
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional


def load_jsonl(file_path: str) -> List[Dict[str, Any]]:
    """
    Load JSONL file and return list of dictionaries.
    
    Args:
        file_path: Path to the JSONL file
        
    Returns:
        List of dictionaries from the JSONL file
    """
    data = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line:  # Skip empty lines
                    try:
                        data.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        print(f"Warning: Invalid JSON at line {line_num}: {e}")
                        continue
        return data
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)


def flatten_nested_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
    """
    Flatten nested dictionaries for better tabular display.
    
    Args:
        d: Dictionary to flatten
        parent_key: Parent key for recursion
        sep: Separator for nested keys
        
    Returns:
        Flattened dictionary
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_nested_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            # Convert lists to string representation for display
            items.append((new_key, str(v)))
        else:
            items.append((new_key, v))
    return dict(items)


def visualize_jsonl(file_path: str, 
                   max_rows: Optional[int] = None,
                   max_columns: Optional[int] = None,
                   flatten: bool = False,
                   columns: Optional[List[str]] = None) -> None:
    """
    Visualize JSONL file in tabular format.
    
    Args:
        file_path: Path to the JSONL file
        max_rows: Maximum number of rows to display
        max_columns: Maximum number of columns to display
        flatten: Whether to flatten nested dictionaries
        columns: Specific columns to display
    """
    print(f"Loading JSONL file: {file_path}")
    data = load_jsonl(file_path)
    
    if not data:
        print("No data found in the file.")
        return
    
    print(f"Found {len(data)} records")
    
    # Flatten nested dictionaries if requested
    if flatten:
        data = [flatten_nested_dict(record) for record in data]
    
    # Create DataFrame
    df = pd.DataFrame(data)
    
    # Filter specific columns if requested
    if columns:
        available_columns = [col for col in columns if col in df.columns]
        missing_columns = [col for col in columns if col not in df.columns]
        
        if missing_columns:
            print(f"Warning: Columns not found: {missing_columns}")
        
        if available_columns:
            df = df[available_columns]
        else:
            print("Error: None of the specified columns were found.")
            return
    
    # Limit rows if specified
    if max_rows and len(df) > max_rows:
        df_display = df.head(max_rows)
        print(f"Showing first {max_rows} rows out of {len(df)} total rows")
    else:
        df_display = df
    
    # Limit columns if specified
    if max_columns and len(df_display.columns) > max_columns:
        df_display = df_display.iloc[:, :max_columns]
        print(f"Showing first {max_columns} columns out of {len(df.columns)} total columns")
    
    # Set pandas display options for better viewing
    pd.set_option('display.max_columns', None)
    pd.set_option('display.max_colwidth', 100)
    pd.set_option('display.width', None)
    pd.set_option('display.max_rows', None)
    
    print(f"\nDataFrame Info:")
    print(f"Shape: {df.shape}")
    print(f"Columns: {list(df.columns)}")
    
    print(f"\nData Types:")
    print(df.dtypes)
    
    print(f"\nData Preview:")
    print("=" * 80)
    print(df_display.to_string(index=True, max_cols=max_columns))
    
    # Show summary statistics for numeric columns
    numeric_columns = df.select_dtypes(include=['number']).columns
    if len(numeric_columns) > 0:
        print(f"\nNumeric Column Statistics:")
        print("=" * 40)
        print(df[numeric_columns].describe())


def analyze_jsonl_structure(file_path: str) -> None:
    """
    Analyze the structure of a JSONL file to understand its schema.
    
    Args:
        file_path: Path to the JSONL file
    """
    data = load_jsonl(file_path)
    
    if not data:
        return
    
    print(f"\nStructure Analysis for: {file_path}")
    print("=" * 50)
    
    # Get all unique keys across all records
    all_keys = set()
    key_counts = {}
    
    for record in data:
        if isinstance(record, dict):
            for key in record.keys():
                all_keys.add(key)
                key_counts[key] = key_counts.get(key, 0) + 1
    
    print(f"Total records: {len(data)}")
    print(f"Unique keys found: {len(all_keys)}")
    
    print(f"\nKey frequency analysis:")
    for key, count in sorted(key_counts.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / len(data)) * 100
        print(f"  {key}: {count}/{len(data)} ({percentage:.1f}%)")
    
    # Sample record structure
    if data:
        print(f"\nSample record structure:")
        sample = data[0]
        print(json.dumps(sample, indent=2, default=str)[:500] + "..." if len(str(sample)) > 500 else json.dumps(sample, indent=2, default=str))


def main():
    parser = argparse.ArgumentParser(description='Visualize JSONL files in tabular format')
    parser.add_argument('file_path', help='Path to the JSONL file')
    parser.add_argument('--max-rows', '-r', type=int, help='Maximum number of rows to display')
    parser.add_argument('--max-columns', '-c', type=int, help='Maximum number of columns to display')
    parser.add_argument('--flatten', '-f', action='store_true', help='Flatten nested dictionaries')
    parser.add_argument('--columns', nargs='+', help='Specific columns to display')
    parser.add_argument('--analyze', '-a', action='store_true', help='Analyze file structure only')
    parser.add_argument('--output', '-o', help='Save output to CSV file')
    
    args = parser.parse_args()
    
    # Verify file exists
    if not Path(args.file_path).exists():
        print(f"Error: File '{args.file_path}' does not exist.")
        sys.exit(1)
    
    if args.analyze:
        analyze_jsonl_structure(args.file_path)
    else:
        visualize_jsonl(
            args.file_path,
            max_rows=args.max_rows,
            max_columns=args.max_columns,
            flatten=args.flatten,
            columns=args.columns
        )
        
        # Save to CSV if requested
        if args.output:
            data = load_jsonl(args.file_path)
            if args.flatten:
                data = [flatten_nested_dict(record) for record in data]
            df = pd.DataFrame(data)
            if args.columns:
                available_columns = [col for col in args.columns if col in df.columns]
                if available_columns:
                    df = df[available_columns]
            df.to_csv(args.output, index=False)
            print(f"\nData saved to: {args.output}")


if __name__ == "__main__":
    main()
