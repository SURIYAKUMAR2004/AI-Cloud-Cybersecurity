import csv
from pathlib import Path
from datetime import datetime


PROJECT_ROOT = Path(__file__).resolve().parents[1]

INCIDENT_FILE = (
    PROJECT_ROOT
    / "data"
    / "incidents.csv"
)

FIELDS = [
    "incident_id",
    "created_at",
    "user",
    "severity",
    "risk_score",
    "assessment",
    "events_correlated",
    "attack_pattern",
    "status",
    "last_updated"
]


def initialize_incident_store():

    if not INCIDENT_FILE.exists():

        with open(
            INCIDENT_FILE,
            "w",
            newline=""
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=FIELDS
            )

            writer.writeheader()


def generate_incident_id():

    initialize_incident_store()

    with open(
        INCIDENT_FILE,
        "r",
        newline=""
    ) as file:

        rows = list(
            csv.DictReader(file)
        )

    if not rows:
        return "INC-0001"

    numbers = []

    for row in rows:

        try:

            numbers.append(
                int(
                    row["incident_id"]
                    .replace("INC-", "")
                )
            )

        except (ValueError, KeyError):
            continue

    next_number = (
        max(numbers) + 1
        if numbers
        else 1
    )

    return f"INC-{next_number:04d}"


def create_incident(incident):

    initialize_incident_store()

    incident_id = (
        generate_incident_id()
    )

    now = datetime.now().isoformat(
        timespec="seconds"
    )

    record = {
        "incident_id": incident_id,
        "created_at": now,
        "user": incident["user"],
        "severity": incident["severity"],
        "risk_score": incident["chain_score"],
        "assessment": incident["assessment"],
        "events_correlated": incident[
            "events_correlated"
        ],
        "attack_pattern": incident[
            "attack_pattern"
        ],
        "status": "NEW",
        "last_updated": now
    }

    with open(
        INCIDENT_FILE,
        "a",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=FIELDS
        )

        writer.writerow(record)

    return incident_id


def update_incident_status(
    incident_id,
    new_status
):

    initialize_incident_store()

    valid_statuses = {
        "NEW",
        "INVESTIGATING",
        "CONTAINED",
        "RESOLVED"
    }

    if new_status not in valid_statuses:

        raise ValueError(
            f"Invalid status: {new_status}"
        )

    with open(
        INCIDENT_FILE,
        "r",
        newline=""
    ) as file:

        rows = list(
            csv.DictReader(file)
        )

    found = False

    for row in rows:

        if row["incident_id"] == incident_id:

            row["status"] = new_status

            row["last_updated"] = (
                datetime.now().isoformat(
                    timespec="seconds"
                )
            )

            found = True

    if not found:

        return False

    with open(
        INCIDENT_FILE,
        "w",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=FIELDS
        )

        writer.writeheader()
        writer.writerows(rows)

    return True


def load_incidents():

    initialize_incident_store()

    with open(
        INCIDENT_FILE,
        "r",
        newline=""
    ) as file:

        return list(
            csv.DictReader(file)
        )

def incident_exists(
    user,
    assessment
):

    incidents = load_incidents()

    for incident in incidents:

        if (
            incident["user"] == user
            and
            incident["assessment"] == assessment
            and
            incident["status"] != "RESOLVED"
        ):

            return True

    return False

if __name__ == "__main__":

    print(
        "\n===== INCIDENT MANAGEMENT TEST =====\n"
    )

    incidents = load_incidents()

    print(
        f"Existing incidents: {len(incidents)}"
    )

    print(
        f"Incident store: {INCIDENT_FILE}"
    )

    print(
        "\nSupported lifecycle:"
    )

    print("NEW")
    print("INVESTIGATING")
    print("CONTAINED")
    print("RESOLVED")

    print(
        "\n===================================="
    )