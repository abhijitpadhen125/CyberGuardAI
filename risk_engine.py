def calculate_risk(findings):

    score = 0

    for finding in findings:

        severity = finding["severity"]

        if severity == "Critical":
            score += 40

        elif severity == "High":
            score += 25

        elif severity == "Medium":
            score += 15

        elif severity == "Low":
            score += 5

    # Maximum score
    if score > 100:
        score = 100

    # Risk level
    if score >= 80:
        level = "CRITICAL"

    elif score >= 60:
        level = "HIGH"

    elif score >= 30:
        level = "MEDIUM"

    else:
        level = "LOW"

    return score, level