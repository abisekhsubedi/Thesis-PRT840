import json
import re
from typing import List, Dict, Union
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SnortRuleValidator:
    
    SNORT_RULE_PATTERN = r"""
    ^(?P<action>alert|log|pass|drop|reject|sdrop)\s+               
    (?P<protocol>tcp|udp|ip|icmp|http)\s+                          
    (?P<src_addr>[\$\w\d._/-]+)\s+                                 
    (?P<src_port>[\[\]\w\d:,]+)\s+                                 
    ->\s+                                                          
    (?P<dst_addr>[\$\w\d._/-]+)\s+                                
    (?P<dst_port>[\[\]\w\d:,]+)\s+                                
    \(\s*                                                          
    (?P<rule_options>                                              
      (?:                                                         
        [^;]+;                                                    
        \s*                                                       
      )+                                                           
    )
    \s*\)                                                          
    """
    
    def __init__(self):
        self.pattern = re.compile(self.SNORT_RULE_PATTERN, re.VERBOSE)
    
    def validate_syntax(self, signature: str) -> bool:
  
        try:
            return bool(self.pattern.match(signature.strip()))
        except (AttributeError, TypeError) as e:
            logger.error(f"Error validating signature: {e}")
            return False
    
    def parse_rule(self, signature: str) -> Dict[str, str]:

        match = self.pattern.match(signature.strip())
        if match:
            return match.groupdict()
        return {}

class SignatureEvaluator:
    def __init__(self):
        self.validator = SnortRuleValidator()
    
    @staticmethod
    def load_signatures(file_path: Union[str, Path]) -> List[str]:
   
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

        if not signatures:
            return {"total": 0, "valid": 0, "accuracy": 0.0}
        
        valid_signatures = [self.validator.validate_syntax(sig) for sig in signatures]
        valid_count = sum(valid_signatures)
        total = len(signatures)
        accuracy = valid_count / total if total > 0 else 0
        
        return {
            "total": total,
            "valid": valid_count,
            "accuracy": accuracy
        }

def main(json_file_path: str):

    evaluator = SignatureEvaluator()
    signatures = evaluator.load_signatures(json_file_path)
    
    if signatures:
        results = evaluator.evaluate_signatures(signatures)
        print(">>> zero shots >>>>")
        logger.info(f"Total signatures: {results['total']}")
        logger.info(f"Valid signatures: {results['valid']}")
        logger.info(f"Accuracy: {results['accuracy']:.2%}")
    else:
        logger.error("No signatures found to evaluate")

if __name__ == "__main__":
    # Example usage
    file_path = './output/zero_shots_processed_rule.json'
    main(file_path)
    
    # # Single rule validation example
    # validator = SnortRuleValidator()
    # test_rule = 'alert tcp any any -> any any (msg:"Buffer overflow attempt detected"; content:"buffer"; sid:1000049;)'
    # is_valid = validator.validate_syntax(test_rule)
    # logger.info(f"Test rule is valid: {is_valid}")