from datetime import datetime


def execute_response(
    response,
    user=None,
    source_ip=None
):
    """
    Safe response simulation.

    This module DOES NOT modify real cloud resources,
    firewall rules, IAM permissions, or network controls.
    """

    timestamp = datetime.now().isoformat(
        timespec="seconds"
    )

    actions = []

    if response == "MONITOR":

        actions = [
            "Continue monitoring activity",
            "Record security event"
        ]

    elif response == "ALERT_SECURITY_TEAM":

        actions = [
            "Create security alert",
            "Notify security team",
            "Continue monitoring activity"
        ]

    elif response == "ALERT_SECURITY_TEAM_AND_MONITOR":

        actions = [
            "Create high-priority security alert",
            "Notify security team",
            "Increase monitoring level"
        ]

    elif response == "RESTRICT_ACCESS_AND_ALERT":

        actions = [
            f"Simulate access restriction for user: {user}",
            f"Simulate security alert for source IP: {source_ip}",
            "Increase monitoring level"
        ]

    elif response == "BLOCK_AND_ISOLATE":

        actions = [
            f"Simulate blocking source IP: {source_ip}",
            f"Simulate isolating user: {user}",
            "Create critical security incident",
            "Preserve security evidence",
            "Notify security team"
        ]

    elif response == "BLOCK_AND_ISOLATE_PRIVILEGED_OPERATION":

        actions = [
            f"Simulate blocking privileged operation "
            f"for user: {user}",
            f"Simulate isolating source IP: {source_ip}",
            "Preserve security evidence",
            "Notify security team"
        ]

    elif response == "ESCALATE_SECURITY_INCIDENT":

        actions = [
            "Create P1 security incident",
            f"Flag user for immediate investigation: {user}",
            f"Flag source IP for investigation: {source_ip}",
            "Preserve security evidence",
            "Notify security team",
            "Escalate to incident response team"
        ]

    else:

        actions = [
            "Unknown response — no action executed"
        ]

    return {
        "timestamp": timestamp,
        "response": response,
        "execution_mode": "SIMULATION",
        "user": user,
        "source_ip": source_ip,
        "actions": actions
    }


if __name__ == "__main__":

    print(
        "\n===== RESPONSE EXECUTION SIMULATOR =====\n"
    )

    test_responses = [
        "MONITOR",
        "ALERT_SECURITY_TEAM",
        "RESTRICT_ACCESS_AND_ALERT",
        "ESCALATE_SECURITY_INCIDENT",
        "BLOCK_AND_ISOLATE"
    ]

    for response in test_responses:

        result = execute_response(
            response=response,
            user="alice",
            source_ip="185.220.101.5"
        )

        print(
            f"\nResponse: {result['response']}"
        )

        print(
            f"Mode: {result['execution_mode']}"
        )

        print("Actions:")

        for action in result["actions"]:

            print(
                f"  → {action}"
            )

    print(
        "\n=========================================="
    )