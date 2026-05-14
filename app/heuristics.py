import json


CATEGORY_WEIGHTS = {
    "anti_debug": 25,
    "memory_injection": 35,
    "process_execution": 20,
    "network": 25,
    "string_validation": 8
}


def load_rules():
    with open("rules/suspicious_apis.json", "r") as f:
        return json.load(f)


def analyze_imports(imports):
    rules = load_rules()

    findings = []

    imported_apis = [imp["api"] for imp in imports]

    for category, api_list in rules.items():

        matched = []

        for api in api_list:
            if api in imported_apis:
                matched.append(api)

        if matched:
            findings.append({
                "category": category,
                "matched": matched,
                "weight": CATEGORY_WEIGHTS.get(category, 5)
            })

    return findings


def calculate_score(findings):
    score = 0

    for finding in findings:
        score += finding.get("weight", 5)

        if len(finding["matched"]) > 1:
            score += min(len(finding["matched"]) * 3, 15)

    return min(score, 100)


def get_priority(score):

    if score >= 70:
        return "High"

    if score >= 35:
        return "Medium"

    return "Low"