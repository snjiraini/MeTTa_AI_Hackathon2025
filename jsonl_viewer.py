"""
Simple JSONL Visualizer for Jupyter Notebooks and Python Scripts
"""

import json
import pandas as pd
from typing import List, Dict, Any, Optional
from pathlib import Path


class JSONLVisualizer:
    """A class to visualize JSONL files in tabular format."""
    
    def __init__(self, file_path: str):
        """
        Initialize with a JSONL file path.
        
        Args:
            file_path: Path to the JSONL file
        """
        self.file_path = file_path
        self.data = self._load_jsonl()
        self.df = None
        
    def _load_jsonl(self) -> List[Dict[str, Any]]:
        """Load JSONL file and return list of dictionaries."""
        data = []
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line:
                        try:
                            data.append(json.loads(line))
                        except json.JSONDecodeError as e:
                            print(f"Warning: Invalid JSON at line {line_num}: {e}")
                            continue
            return data
        except FileNotFoundError:
            print(f"Error: File '{self.file_path}' not found.")
            return []
        except Exception as e:
            print(f"Error reading file: {e}")
            return []
    
    def to_dataframe(self, flatten: bool = False, columns: Optional[List[str]] = None) -> pd.DataFrame:
        """
        Convert JSONL data to pandas DataFrame.
        
        Args:
            flatten: Whether to flatten nested dictionaries
            columns: Specific columns to include
            
        Returns:
            pandas DataFrame
        """
        if not self.data:
            return pd.DataFrame()
        
        data = self.data.copy()
        
        if flatten:
            data = [self._flatten_dict(record) for record in data]
        
        df = pd.DataFrame(data)
        
        if columns:
            available_columns = [col for col in columns if col in df.columns]
            if available_columns:
                df = df[available_columns]
                
        self.df = df
        return df
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
        """Flatten nested dictionaries."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                items.append((new_key, str(v)))
            else:
                items.append((new_key, v))
        return dict(items)
    
    def show(self, max_rows: Optional[int] = 10, 
             max_columns: Optional[int] = None,
             flatten: bool = False,
             columns: Optional[List[str]] = None) -> pd.DataFrame:
        """
        Display the JSONL data in tabular format.
        
        Args:
            max_rows: Maximum number of rows to display
            max_columns: Maximum number of columns to display
            flatten: Whether to flatten nested dictionaries
            columns: Specific columns to display
            
        Returns:
            pandas DataFrame
        """
        df = self.to_dataframe(flatten=flatten, columns=columns)
        
        if df.empty:
            print("No data to display.")
            return df
        
        print(f"Dataset Info:")
        print(f"  File: {self.file_path}")
        print(f"  Total records: {len(self.data)}")
        print(f"  DataFrame shape: {df.shape}")
        print(f"  Columns: {list(df.columns)}")
        
        display_df = df
        if max_rows and len(df) > max_rows:
            display_df = df.head(max_rows)
            print(f"\nShowing first {max_rows} rows:")
        else:
            print(f"\nShowing all {len(df)} rows:")
            
        if max_columns and len(display_df.columns) > max_columns:
            display_df = display_df.iloc[:, :max_columns]
            print(f"(Limited to first {max_columns} columns)")
        
        # Configure pandas display options
        with pd.option_context('display.max_columns', None, 
                             'display.width', None,
                             'display.max_colwidth', 50):
            print("\n" + "="*80)
            print(display_df.to_string(index=True))
        
        return df
    
    def info(self):
        """Display detailed information about the dataset."""
        if not self.data:
            print("No data loaded.")
            return
            
        print(f"File Analysis: {self.file_path}")
        print("="*50)
        print(f"Total records: {len(self.data)}")
        
        # Analyze keys
        all_keys = set()
        key_counts = {}
        
        for record in self.data:
            if isinstance(record, dict):
                for key in record.keys():
                    all_keys.add(key)
                    key_counts[key] = key_counts.get(key, 0) + 1
        
        print(f"Unique keys: {len(all_keys)}")
        print(f"\nKey frequency:")
        for key, count in sorted(key_counts.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / len(self.data)) * 100
            print(f"  {key}: {count}/{len(self.data)} ({percentage:.1f}%)")
        
        # Show sample record
        if self.data:
            print(f"\nSample record:")
            sample = json.dumps(self.data[0], indent=2, default=str)
            if len(sample) > 500:
                sample = sample[:500] + "\n  ..."
            print(sample)
    
    def to_csv(self, output_path: str, **kwargs):
        """Export data to CSV file."""
        if self.df is None:
            df = self.to_dataframe()
        else:
            df = self.df
            
        df.to_csv(output_path, index=False, **kwargs)
        print(f"Data exported to: {output_path}")


def quick_view(file_path: str, max_rows: int = 10, **kwargs) -> pd.DataFrame:
    """
    Quick function to view JSONL file contents.
    
    Args:
        file_path: Path to JSONL file
        max_rows: Maximum rows to display
        **kwargs: Additional arguments for show() method
        
    Returns:
        pandas DataFrame
    """
    visualizer = JSONLVisualizer(file_path)
    return visualizer.show(max_rows=max_rows, **kwargs)


def analyze_structure(file_path: str):
    """
    Quick function to analyze JSONL file structure.
    
    Args:
        file_path: Path to JSONL file
    """
    visualizer = JSONLVisualizer(file_path)
    visualizer.info()


# Example usage:
if __name__ == "__main__":
    # Example with your files
    print("=== Garak Report Analysis ===")
    garak_report = "/home/root/workspace/docs/garak.report.jsonl"
    if Path(garak_report).exists():
        quick_view(garak_report, max_rows=5)
        
    print("\n=== Security Demo Analysis ===")  
    security_demo = "/home/root/workspace/security_demo_7ce74a289ad34d528b12ea96407d8e05.jsonl"
    if Path(security_demo).exists():
        quick_view(security_demo, max_rows=5)
