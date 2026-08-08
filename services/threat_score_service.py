from models.attack_log_model import AttackLog

THREAT_SCORES = {
    "Brute Force": 30,
    "Credential Stuffing": 35,
    "Password Spraying": 35,
    "Account Enumeration": 20,
    "SQL Injection": 50,
    "XSS Attack": 45,
    "Honeypot Access": 60
}


def calculate_threat_score():

    attacks = AttackLog.query.all()

    total_score = 0

    for attack in attacks:
        total_score += THREAT_SCORES.get(attack.attack_type, 0)

    return total_score