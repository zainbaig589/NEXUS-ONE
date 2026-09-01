"""Condition evaluators for detection rules."""

import re
from typing import Any, Dict, List


def get_field_value(data: Dict[str, Any], field_path: str) -> Any:
    """Extract value from nested dict using dot notation.
    
    Examples:
        get_field_value({"payload": {"ip": "1.2.3.4"}}, "payload.ip") -> "1.2.3.4"
        get_field_value({"event_type": "login"}, "event_type") -> "login"
    """
    parts = field_path.split(".")
    value = data
    for part in parts:
        if isinstance(value, dict):
            value = value.get(part)
        else:
            return None
    return value


def evaluate_threshold(data: Dict[str, Any], condition: Dict[str, Any]) -> bool:
    """Evaluate threshold condition.
    
    Condition format:
        {
            "field": "payload.failed_attempts",
            "operator": "gt",  # gt, lt, gte, lte, eq, neq
            "value": 10
        }
    """
    field_value = get_field_value(data, condition["field"])
    if field_value is None:
        return False
    
    operator = condition["operator"]
    threshold = condition["value"]
    
    operators = {
        "gt": lambda a, b: a > b,
        "lt": lambda a, b: a < b,
        "gte": lambda a, b: a >= b,
        "lte": lambda a, b: a <= b,
        "eq": lambda a, b: a == b,
        "neq": lambda a, b: a != b,
    }
    
    op_func = operators.get(operator)
    if not op_func:
        return False
    
    return op_func(field_value, threshold)


def evaluate_pattern_match(data: Dict[str, Any], condition: Dict[str, Any]) -> bool:
    """Evaluate pattern match condition.
    
    Condition format:
        {
            "field": "event_type",
            "pattern": "failed_login"  # exact match or regex
        }
    """
    field_value = get_field_value(data, condition["field"])
    if field_value is None:
        return False
    
    pattern = condition["pattern"]
    
    # Try exact match first
    if str(field_value) == pattern:
        return True
    
    # Try regex match
    try:
        return bool(re.match(pattern, str(field_value)))
    except re.error:
        return False


def evaluate_combination(data: Dict[str, Any], condition: Dict[str, Any]) -> bool:
    """Evaluate combination condition (AND/OR logic).
    
    Condition format:
        {
            "logic": "and",  # or "or"
            "conditions": [
                {"type": "threshold", "field": "...", ...},
                {"type": "pattern_match", "field": "...", ...}
            ]
        }
    """
    logic = condition.get("logic", "and")
    conditions = condition.get("conditions", [])
    
    if not conditions:
        return False
    
    evaluator_map = {
        "threshold": evaluate_threshold,
        "pattern_match": evaluate_pattern_match,
        "combination": evaluate_combination,
    }
    
    results = []
    for cond in conditions:
        cond_type = cond.get("type")
        evaluator = evaluator_map.get(cond_type)
        if evaluator:
            results.append(evaluator(data, cond))
        else:
            results.append(False)
    
    if logic == "and":
        return all(results)
    elif logic == "or":
        return any(results)
    
    return False


def evaluate_condition(data: Dict[str, Any], condition: Dict[str, Any]) -> bool:
    """Main entry point for evaluating a condition against event data.
    
    Automatically detects condition type and routes to appropriate evaluator.
    """
    cond_type = condition.get("type")
    
    if cond_type == "threshold":
        return evaluate_threshold(data, condition)
    elif cond_type == "pattern_match":
        return evaluate_pattern_match(data, condition)
    elif cond_type == "combination":
        return evaluate_combination(data, condition)
    
    return False
