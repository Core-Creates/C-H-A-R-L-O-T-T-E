# ******************************************************************************************
# models/action_recommender.py
# Rule-based and ML-augmented system for recommending responses based on attack severity
# ******************************************************************************************

from typing import List

# ==========================================================================================
# FUNCTION: recommend_action
# Simple rule-based mapping of threat findings to course of action
# ==========================================================================================
def recommend_action(stage: str, severity: str, is_remote: bool = True) -> str:
    """
    Determines a recommended course of action based on threat stage and severity.

    Args:
        stage (str): Attack stage label. Examples:
            - "benign", "exploit_attempt", "data_exfil", "persistence"
        severity (str): Predicted severity class. Examples:
            - "Low", "Medium", "High", "Critical"
        is_remote (bool): True if threat was initiated remotely

    Returns:
        str: Recommended action, such as "Isolate Host", "Kill Process", etc.
    """
    stage = stage.lower()
    severity = severity.lower()

    # Critical exfil or exploit from remote = isolate host
    if stage == "data_exfil" and severity in ["high", "critical"]:
        return "Isolate Host"

    if stage == "exploit_attempt" and severity in ["high", "critical"]:
        return "Kill Process and Open Incident Ticket"

    if stage == "persistence" and severity in ["medium", "high"]:
        return "Kill Process and Monitor for Regrowth"

    if stage == "exploit_attempt" and severity == "medium":
        return "Block IP and Monitor Process"

    if stage == "data_exfil" and severity == "medium":
        return "Throttle Outbound Traffic + Alert SOC"

    if stage == "persistence" and severity == "low":
        return "Log and Monitor Registry Key"

    if stage == "benign":
        return "No Action Required"

    # Fallback default
    return "Open SOC Ticket for Review"


# ==========================================================================================
# FUNCTION: batch_recommend_actions
# Vectorized version for multiple predictions
# ==========================================================================================
def batch_recommend_actions(stages: List[str], severities: List[str], is_remote_flags: List[bool] = None) -> List[str]:
    """
    Recommends actions for multiple stage/severity pairs.

    Args:
        stages (List[str]): List of stage strings
        severities (List[str]): List of severity class strings
        is_remote_flags (List[bool], optional): List of remote flags. If None, assume True.

    Returns:
        List[str]: Corresponding actions for each finding
    """
    if is_remote_flags is None:
        is_remote_flags = [True] * len(stages)

    return [
        recommend_action(stage, severity, is_remote)
        for stage, severity, is_remote in zip(stages, severities, is_remote_flags)
    ]
