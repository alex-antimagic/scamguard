from analysis.models import Finding, Severity, SEVERITY_SCORES


def compute_score(findings: list[Finding]) -> tuple[int, str]:
    """Compute aggregate risk score and verdict from findings.

    Returns (score 0-100, verdict string).
    """
    if not findings:
        return 0, 'safe'

    # Check for blocklist critical hit — short-circuit to 90+
    for f in findings:
        if f.check == 'google_web_risk' and f.severity == Severity.CRITICAL:
            return 95, 'malicious'

    # Weighted additive scoring
    score = 0
    analyzer_scores = {}

    for f in findings:
        points = SEVERITY_SCORES.get(f.severity, 0)
        analyzer = f.analyzer

        # Track per-analyzer contribution
        analyzer_scores[analyzer] = analyzer_scores.get(analyzer, 0) + points

    # Cap individual analyzer contributions at 70 (except blocklist)
    for analyzer, analyzer_score in analyzer_scores.items():
        if analyzer != 'blocklist':
            analyzer_score = min(analyzer_score, 70)
        score += analyzer_score

    score = min(score, 100)

    # Determine verdict
    if score <= 20:
        verdict = 'safe'
    elif score <= 50:
        verdict = 'suspicious'
    elif score <= 80:
        verdict = 'dangerous'
    else:
        verdict = 'malicious'

    return score, verdict
