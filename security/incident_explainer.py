def explain_incident(incident):

    score = incident["chain_score"]
    severity = incident["severity"]
    assessment = incident["assessment"]
    user = incident["user"]
    events = incident["events_correlated"]
    pattern = incident["attack_pattern"]

    if assessment == "POSSIBLE_ACCOUNT_COMPROMISE":

        explanation = (
            f"User '{user}' generated a correlated sequence "
            f"containing privileged activity, suspicious external "
            f"access and unusually large data transfer. "
            f"The combination of these indicators is consistent "
            f"with possible account compromise."
        )

        investigation = [
            "Verify whether the user initiated the activity.",
            "Review recent authentication events for the account.",
            "Check whether the source IP is expected.",
            "Review recent privilege or role changes.",
            "Inspect accessed cloud resources.",
            "Check for unusual data downloads or transfers."
        ]

        response = (
            "Temporarily restrict the affected identity, "
            "preserve relevant security logs, and escalate "
            "the incident for investigation."
        )

    elif assessment == "POSSIBLE_DATA_EXFILTRATION":

        explanation = (
            f"User '{user}' generated suspicious external "
            f"activity combined with unusually large data "
            f"transfer. This may indicate possible data "
            f"exfiltration."
        )

        investigation = [
            "Identify the transferred resources.",
            "Verify whether the destination is trusted.",
            "Review cloud storage access logs.",
            "Check the user's recent authentication history.",
            "Determine whether sensitive data was accessed."
        ]

        response = (
            "Restrict suspicious access and investigate "
            "the affected cloud resources."
        )

    elif assessment == "SUSPICIOUS_PRIVILEGED_ACTIVITY":

        explanation = (
            f"User '{user}' performed privileged cloud "
            f"operations that require additional verification."
        )

        investigation = [
            "Verify the legitimacy of the privileged operation.",
            "Review IAM role changes.",
            "Check recent authentication activity.",
            "Confirm that the user is authorized."
        ]

        response = (
            "Alert the security team and review privileged "
            "access activity."
        )

    else:

        explanation = (
            f"Suspicious activity involving user '{user}' "
            f"was detected."
        )

        investigation = [
            "Review recent activity for the user.",
            "Check source IP reputation.",
            "Review authentication events."
        ]

        response = (
            "Monitor the activity and investigate if "
            "additional indicators appear."
        )

    return {
        "severity": severity,
        "risk_score": score,
        "assessment": assessment,
        "user": user,
        "events_correlated": events,
        "attack_pattern": pattern,
        "explanation": explanation,
        "investigation_steps": investigation,
        "recommended_response": response
    }


if __name__ == "__main__":

    example = {
        "chain_score": 100,
        "severity": "CRITICAL",
        "assessment": "POSSIBLE_ACCOUNT_COMPROMISE",
        "user": "alice",
        "events_correlated": 15,
        "attack_pattern": (
            "Failed operation → "
            "Privileged cloud operation → "
            "Suspicious external source → "
            "Large data transfer"
        )
    }

    result = explain_incident(
        example
    )

    print("\n===== AI INCIDENT EXPLANATION =====\n")

    print(
        f"Assessment: {result['assessment']}"
    )

    print(
        f"Risk Score: {result['risk_score']}"
    )

    print(
        f"\nExplanation:\n"
        f"{result['explanation']}"
    )

    print(
        "\nInvestigation Steps:"
    )

    for step in result["investigation_steps"]:
        print(f"- {step}")

    print(
        f"\nRecommended Response:\n"
        f"{result['recommended_response']}"
    )

    print(
        "\n===================================\n"
    )