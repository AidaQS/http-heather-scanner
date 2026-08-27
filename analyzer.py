from config import SECURITY_HEADERS


def analyze_security_headers(headers):

    results = []

    for name, information in SECURITY_HEADERS.items():

        value = headers.get(name)

        results.append({
            "name": name,
            "present": bool(value),
            "value": value or "",
            "description": information["description"],
            "severity": information["severity"]
        })

    return results


def calculate_score(results):

    if not results:
        return 0

    present = sum(
        1
        for result in results
        if result["present"]
    )

    return round(
        (present / len(results)) * 100
    )


def get_score_color(score):

    if score >= 80:
        return "#20C997"

    if score >= 50:
        return "#FFB020"

    return "#FF5C6C"


def get_score_text(score):

    if score >= 80:
        return "Good security configuration"

    if score >= 50:
        return "Security configuration could be improved"

    return "Weak security configuration"