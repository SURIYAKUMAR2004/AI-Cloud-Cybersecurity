from datetime import datetime


def determine_response(
    risk_score,
    risk_level,
    behavior_status,
    contextual_risk_level,
    attack_severity=None,
    assessment=None
):

    indicators = []

    # ------------------------------------------------
    # CRITICAL ATTACK CHAIN
    # ------------------------------------------------

    if (
        attack_severity == "CRITICAL"
        and risk_score >= 80
    ):

        indicators.append(
            "Critical correlated attack detected"
        )

        response = "BLOCK_AND_ISOLATE"

        priority = "P1"

        reason = (
            "Multiple high-confidence security indicators "
            "were correlated into a critical incident."
        )

    # ------------------------------------------------
    # HIGH RISK
    # ------------------------------------------------

    elif (
        risk_score >= 70
        or risk_level == "HIGH"
        or contextual_risk_level == "HIGH"
    ):

        indicators.append(
            "High security risk"
        )

        if behavior_status == "HIGH_DEVIATION":

            indicators.append(
                "High behavioral deviation"
            )

            response = (
                "RESTRICT_ACCESS_AND_ALERT"
            )

        else:

            response = (
                "ALERT_SECURITY_TEAM_AND_MONITOR"
            )

        priority = "P2"

        reason = (
            "Elevated risk requires security-team "
            "investigation and access control."
        )

    # ------------------------------------------------
    # MEDIUM RISK
    # ------------------------------------------------

    elif (
        risk_score >= 40
        or risk_level == "MEDIUM"
        or contextual_risk_level == "MEDIUM"
    ):

        indicators.append(
            "Moderate security risk"
        )

        response = (
            "ALERT_SECURITY_TEAM"
        )

        priority = "P3"

        reason = (
            "Suspicious activity was detected but "
            "does not currently justify isolation."
        )

    # ------------------------------------------------
    # LOW RISK
    # ------------------------------------------------

    else:

        response = "MONITOR"

        priority = "P4"

        reason = (
            "No significant security indicators "
            "require intervention."
        )

    # ------------------------------------------------
    # SPECIAL ESCALATION
    # ------------------------------------------------

    if (
        assessment == "POSSIBLE_ACCOUNT_COMPROMISE"
        and risk_score >= 80
    ):

        indicators.append(
            "Possible account compromise"
        )

        response = "ESCALATE_SECURITY_INCIDENT"

        priority = "P1"

        reason = (
            "Evidence suggests possible account compromise "
            "and requires immediate security investigation."
        )

    return {
        "timestamp": datetime.now().isoformat(
            timespec="seconds"
        ),
        "response": response,
        "priority": priority,
        "reason": reason,
        "indicators": indicators
    }


if __name__ == "__main__":

    print(
        "\n===== ADAPTIVE RESPONSE ENGINE =====\n"
    )

    test_cases = [

        {
            "name": "Normal Activity",
            "risk_score": 10,
            "risk_level": "LOW",
            "behavior_status": "NORMAL_BEHAVIOR",
            "contextual_risk_level": "LOW"
        },

        {
            "name": "Suspicious Activity",
            "risk_score": 55,
            "risk_level": "MEDIUM",
            "behavior_status": "MODERATE_DEVIATION",
            "contextual_risk_level": "MEDIUM"
        },

        {
            "name": "High Risk",
            "risk_score": 75,
            "risk_level": "HIGH",
            "behavior_status": "HIGH_DEVIATION",
            "contextual_risk_level": "HIGH"
        },

        {
            "name": "Critical Attack",
            "risk_score": 100,
            "risk_level": "CRITICAL",
            "behavior_status": "HIGH_DEVIATION",
            "contextual_risk_level": "CRITICAL",
            "attack_severity": "CRITICAL",
            "assessment": "POSSIBLE_ACCOUNT_COMPROMISE"
        }
    ]

    for case in test_cases:

        result = determine_response(
            risk_score=case["risk_score"],
            risk_level=case["risk_level"],
            behavior_status=case["behavior_status"],
            contextual_risk_level=case[
                "contextual_risk_level"
            ],
            attack_severity=case.get(
                "attack_severity"
            ),
            assessment=case.get(
                "assessment"
            )
        )

        print(
            f"Scenario: {case['name']}"
        )

        print(
            f"Response: {result['response']}"
        )

        print(
            f"Priority: {result['priority']}"
        )

        print(
            f"Reason: {result['reason']}"
        )

        print(
            f"Indicators: {result['indicators']}"
        )

        print("-" * 60)

    print(
        "\n===================================="
    )