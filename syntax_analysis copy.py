import json
import re
import logging
from typing import List, Dict, Union
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import pandas as pd
import numpy as np

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SnortRuleValidator:
    """Class to handle Snort rule validation and evaluation."""
    
    SNORT_RULE_PATTERN = r"""
    ^(?P<action>alert|log|pass|drop|reject|sdrop)\s+                # Rule action
    (?P<protocol>tcp|udp|ip|icmp|http)\s+                          # Protocol
    (?P<src_addr>[\$\w\d._/-]+)\s+                                 # Source address/variable
    (?P<src_port>[\[\]\w\d:,]+)\s+                                 # Source port(s)
    ->\s+                                                          # Direction indicator
    (?P<dst_addr>[\$\w\d._/-]+)\s+                                 # Destination address/variable
    (?P<dst_port>[\[\]\w\d:,]+)\s+                                 # Destination port(s)
    \(\s*                                                          # Opening parenthesis
    (?P<rule_options>                                              # Rule options section
      (?:                                                          # Non-capturing group for options
        [^;]+;                                                     # Match everything up to semicolon
        \s*                                                        # Optional whitespace
      )+                                                           # One or more options
    )
    \s*\)                                                          # Closing parenthesis
    """
    
    def __init__(self):
        """Initialize the validator with compiled regex pattern."""
        self.pattern = re.compile(self.SNORT_RULE_PATTERN, re.VERBOSE)
    
    def validate_syntax(self, signature: str) -> bool:
        """Validate the syntax of a single Snort rule."""
        try:
            return bool(self.pattern.match(signature.strip()))
        except (AttributeError, TypeError) as e:
            logger.error(f"Error validating signature: {e}")
            return False
    
    def parse_rule(self, signature: str) -> Dict[str, str]:
        """Parse a Snort rule into its components."""
        match = self.pattern.match(signature.strip())
        if match:
            return match.groupdict()
        return {}

class SignatureEvaluator:
    """Class to evaluate multiple Snort signatures."""
    
    def __init__(self):
        """Initialize the evaluator with a validator instance."""
        self.validator = SnortRuleValidator()
        self.results_data = []
    
    @staticmethod
    def load_signatures(file_path: Union[str, Path]) -> List[str]:
        """Load signatures from a JSON file."""
        try:
            with open(file_path, 'r') as file:
                data = json.load(file)
                if isinstance(data, list):
                    return data
                logger.error("JSON file must contain an array of signatures")
                return []
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.error(f"Error loading signatures: {e}")
            return []
    
    def evaluate_signatures(self, signatures: List[str]) -> Dict[str, Union[int, float]]:
        """Evaluate signatures and collect detailed statistics."""
        if not signatures:
            return {"total": 0, "valid": 0, "accuracy": 0.0}
        
        valid_signatures = [self.validator.validate_syntax(sig) for sig in signatures]
        valid_count = sum(valid_signatures)
        total = len(signatures)
        accuracy = valid_count / total if total > 0 else 0
        
        # Analyze components of valid rules
        components_stats = self._analyze_rule_components(signatures)
        
        results = {
            "total": total,
            "valid": valid_count,
            "invalid": total - valid_count,
            "accuracy": accuracy,
            "components": components_stats
        }
        
        self.results_data.append(results)
        return results
    
    def _analyze_rule_components(self, signatures: List[str]) -> Dict[str, int]:
        """Analyze the components of valid rules."""
        components = {
            "alert": 0, "log": 0, "pass": 0, "drop": 0,
            "tcp": 0, "udp": 0, "ip": 0, "icmp": 0, "http": 0
        }
        
        for sig in signatures:
            parsed = self.validator.parse_rule(sig)
            if parsed:
                action = parsed.get('action', '')
                protocol = parsed.get('protocol', '')
                if action in components:
                    components[action] += 1
                if protocol in components:
                    components[protocol] += 1
        
        return components

class SignatureVisualizer:
    """Class to generate visualizations for signature evaluation results."""
    
    def __init__(self, output_dir: str = "visualization_output"):
        """Initialize visualizer with output directory."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.set_style()
    
    @staticmethod
    def set_style():
        """Set the style for all visualizations."""
        # Use basic matplotlib style with custom modifications
        plt.style.use('default')
        # Apply seaborn-like styling manually
        plt.rcParams['figure.facecolor'] = 'white'
        plt.rcParams['axes.grid'] = True
        plt.rcParams['grid.alpha'] = 0.3
        plt.rcParams['axes.facecolor'] = 'white'
        plt.rcParams['axes.edgecolor'] = '#333333'
        plt.rcParams['axes.labelcolor'] = '#333333'
        plt.rcParams['grid.color'] = '#666666'
        plt.rcParams['font.family'] = 'sans-serif'
    
    def create_validation_summary(self, results: Dict[str, Union[int, float]]):
        """Create a pie chart showing valid vs invalid signatures."""
        plt.figure(figsize=(10, 6))
        sizes = [results['Valid \n Rules'], results['Invalid \n Rules']]
        labels = ['Valid', 'Invalid']
        colors = ['#2ecc71', '#e74c3c']
        
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                startangle=90, shadow=False)
        plt.title('Zero-shot prompt \n Signature Validation Results', pad=20, fontsize=14)
        
        output_path = self.output_dir / f'validation_summary_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png'
        plt.savefig(output_path, bbox_inches='tight', dpi=300)
        plt.close()
        logger.info(f"Saved validation summary to {output_path}")

    # def create_components_analysis(self, results: Dict[str, Union[int, float]]):
    #     """Create bar charts for rule components analysis."""
    #     components = results['components']
        
    #     # Split into actions and protocols
    #     actions = {k: v for k, v in components.items() if k in ['alert', 'log', 'pass', 'drop']}
    #     protocols = {k: v for k, v in components.items() if k in ['tcp', 'udp', 'ip', 'icmp', 'http']}
        
    #     fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))
        
    #     # Actions bar chart
    #     bars1 = ax1.bar(list(actions.keys()), list(actions.values()), color='#3498db')
    #     ax1.set_title('Distribution of Rule Actions', pad=20, fontsize=14)
    #     ax1.set_ylabel('Count')
    #     self._add_value_labels(ax1, bars1)
        
    #     # Protocols bar chart
    #     bars2 = ax2.bar(list(protocols.keys()), list(protocols.values()), color='#2ecc71')
    #     ax2.set_title('Distribution of Protocols', pad=20, fontsize=14)
    #     ax2.set_ylabel('Count')
    #     self._add_value_labels(ax2, bars2)
        
    #     plt.tight_layout()
    #     output_path = self.output_dir / f'components_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png'
    #     plt.savefig(output_path, bbox_inches='tight', dpi=300)
    #     plt.close()
    #     logger.info(f"Saved components analysis to {output_path}")

    # @staticmethod
    # def _add_value_labels(ax, bars):
    #     """Add value labels on top of bars."""
    #     for bar in bars:
    #         height = bar.get_height()
    #         ax.text(bar.get_x() + bar.get_width()/2., height,
    #                f'{int(height)}',
    #                ha='center', va='bottom')

def main(json_file_path: str):
    """Main function to run the evaluation process and generate visualizations."""
    # Initialize classes
    evaluator = SignatureEvaluator()
    visualizer = SignatureVisualizer()
    
    # Load and evaluate signatures
    signatures = evaluator.load_signatures(json_file_path)
    
    if signatures:
        # Evaluate signatures
        results = evaluator.evaluate_signatures(signatures)
        
        # Log results
        logger.info(f"Total signatures: {results['total']}")
        logger.info(f"Valid signatures: {results['valid']}")
        logger.info(f"Accuracy: {results['accuracy']:.2%}")
        
        # Generate visualizations
        visualizer.create_validation_summary(results)
        # visualizer.create_components_analysis(results)
    else:
        logger.error("No signatures found to evaluate")

if __name__ == "__main__":
    # Example usage
    file_path = './output/zero_shots_processed_rule.json'
    main(file_path)