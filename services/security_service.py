from sqlalchemy import func

from extensions import db

from models.login_log_model import LoginLog
from models.attack_log_model import AttackLog
from models.blocked_ip_model import BlockedIP
from models.incident_model import Incident
from models.security_log_model import SecurityLog
from services.geoip_services import get_location
from services.threat_score_service import calculate_threat_score

from services.email_service import send_security_alert


# ---------------------------------------------------
# Security Log Creator
# ---------------------------------------------------
def create_security_log(event_type, severity, ip_address, description):

    log = SecurityLog(
        event_type=event_type,
        severity=severity,
        ip_address=ip_address,
        description=description
    )

    db.session.add(log)
    db.session.commit()


# ---------------------------------------------------
# Brute Force Detection
# ---------------------------------------------------
# ---------------------------------------------------
# Brute Force Detection
# ---------------------------------------------------
def check_brute_force(ip_address):

    print("=" * 40)
    print("BRUTE FORCE FUNCTION CALLED")
    print("IP:", ip_address)

    failed_attempts = LoginLog.query.filter_by(
        ip_address=ip_address,
        status="FAILED"
    ).count()

    print("FAILED ATTEMPTS:", failed_attempts)

    if failed_attempts >= 5:

        print("INSIDE IF BLOCK")

        

        location = get_location(ip_address)
        attack = AttackLog(
    ip_address=ip_address,
    attack_type="Brute Force",
    severity="High",
    description="Multiple failed login attempts detected.",
    country=location["country"],
    city=location["city"],
    latitude=location["latitude"],
    longitude=location["longitude"]
)

        incident = Incident(
            title="Brute Force Attack Detected",
            severity="High"
        )

        db.session.add(attack)
        db.session.add(incident)

        if not BlockedIP.query.filter_by(ip_address=ip_address).first():

            blocked = BlockedIP(
                ip_address=ip_address,
                reason="Brute Force Attack"
            )

            db.session.add(blocked)

        print("Before Commit")
        db.session.commit()
        print("After Commit")

        score = calculate_threat_score()

        send_security_alert(
            subject="Brute Force Attack Detected",
            message="Multiple failed login attempts detected.",
            severity="High",
            ip_address=ip_address,
            location="Localhost (127.0.0.1)",
            browser="Unknown",
            device="Unknown",
            threat_score=score
        )

        print("Email Sent")

        create_security_log(
            event_type="Brute Force",
            severity="High",
            ip_address=ip_address,
            description="Multiple failed login attempts detected."
        )

        print("Security Log Created")
# ---------------------------------------------------
# Credential Stuffing Detection
# ---------------------------------------------------
# ---------------------------------------------------
# Credential Stuffing Detection
# ---------------------------------------------------
def check_credential_stuffing(ip_address):

    usernames = db.session.query(LoginLog.email).filter(
        LoginLog.ip_address == ip_address,
        LoginLog.status == "FAILED"
    ).distinct().count()

    if usernames >= 3:
        location = get_location(ip_address)
        attack = AttackLog(
    ip_address=ip_address,
    attack_type="Credential Stuffing",
    severity="High",
    description="Multiple usernames attempted from the same IP.",
    country=location["country"],
    city=location["city"],
    latitude=location["latitude"],
    longitude=location["longitude"]
)

        incident = Incident(
            title="Credential Stuffing Detected",
            severity="High"
        )

        db.session.add(attack)
        db.session.add(incident)
        db.session.commit()

        create_security_log(
            event_type="Credential Stuffing",
            severity="High",
            ip_address=ip_address,
            description="Multiple usernames attempted from same IP."
        )


# ---------------------------------------------------
# Password Spraying Detection
# ---------------------------------------------------
def check_password_spraying(ip_address):

    results = (
        db.session.query(
            LoginLog.attempted_password,
            func.count(func.distinct(LoginLog.email))
        )
        .filter(
            LoginLog.ip_address == ip_address,
            LoginLog.status == "FAILED"
        )
        .group_by(LoginLog.attempted_password)
        .all()
    )

    for password, account_count in results:

        if account_count >= 3:
            location = get_location(ip_address)
            attack = AttackLog(
    ip_address=ip_address,
    attack_type="Password Spraying",
    severity="High",
    description="Same password attempted on multiple accounts.",
    country=location["country"],
    city=location["city"],
    latitude=location["latitude"],
    longitude=location["longitude"]
)

            incident = Incident(
                    title="Password Spraying Detected",
                    severity="High"
                )

            db.session.add(attack)
            db.session.add(incident)
            db.session.commit()

            create_security_log(
                    event_type="Password Spraying",
                    severity="High",
                    ip_address=ip_address,
                    description="Same password attempted on multiple accounts."
                )


# ---------------------------------------------------
# Account Enumeration Detection
# ---------------------------------------------------
def check_account_enumeration(ip_address):

    unknown_accounts = (
        db.session.query(LoginLog.email)
        .filter(
            LoginLog.ip_address == ip_address,
            LoginLog.status == "FAILED",
            LoginLog.user_id.is_(None)
        )
        .distinct()
        .count()
    )

    if unknown_accounts >= 5:

        location = get_location(ip_address)

        attack = AttackLog(
                ip_address=ip_address,
                attack_type="Account Enumeration",
                severity="Medium",
                description="Multiple invalid usernames detected from same IP.",
                country=location["country"],
                city=location["city"],
                latitude=location["latitude"],
                longitude=location["longitude"]
            )

        incident = Incident(
                title="Account Enumeration Detected",
                severity="Medium"
            )

        db.session.add(attack)
        db.session.add(incident)
        db.session.commit()

        create_security_log(
                event_type="Account Enumeration",
                severity="Medium",
                ip_address=ip_address,
                description="Multiple invalid usernames detected."
            )


# ---------------------------------------------------
# SQL Injection Detection
# ---------------------------------------------------
def detect_sql_injection(input_text, ip_address):

    sql_patterns = [
        "' OR",
        "\" OR",
        "--",
        ";",
        "UNION",
        "SELECT",
        "DROP",
        "INSERT",
        "DELETE",
        "UPDATE",
        "ALTER",
        "EXEC",
        "XP_"
    ]

    text = input_text.upper()

    for pattern in sql_patterns:

        if pattern.upper() in text:
            print("SQL PATTERN MATCHED:", pattern)


            location = get_location(ip_address)

            attack = AttackLog(
                    ip_address=ip_address,
                    attack_type="SQL Injection",
                    severity="Critical",
                    description="SQL Injection payload detected.",
                    country=location["country"],
                    city=location["city"],
                    latitude=location["latitude"],
                    longitude=location["longitude"]
                )

            incident = Incident(
                    title="SQL Injection Detected",
                    severity="Critical"
                )

            db.session.add(attack)
            db.session.add(incident)
            db.session.commit()

            score = calculate_threat_score()
            print("Sending SQL Email...")

            send_security_alert(
                    subject="SQL Injection Detected",
                    message="Critical SQL Injection payload blocked.",
                    severity="Critical",
                    ip_address=ip_address,
                    location="Localhost (127.0.0.1)",
                    browser="Unknown",
                    device="Unknown",
                    threat_score=score
                )
            
            print("SQL Email Sent")
            create_security_log(
                    event_type="SQL Injection",
                    severity="Critical",
                    ip_address=ip_address,
                    description="SQL Injection payload blocked."
                )
            print("Returning True")

            return True

    return False

# ---------------------------------------------------
# XSS Detection
# ---------------------------------------------------
def detect_xss(input_text, ip_address):

    xss_patterns = [
        "<script",
        "</script>",
        "javascript:",
        "onerror=",
        "onload=",
        "<img",
        "<svg",
        "<iframe",
        "alert(",
        "document.cookie"
    ]

    text = input_text.lower()

    for pattern in xss_patterns:

        if pattern in text:
            location = get_location(ip_address)
            attack = AttackLog(
    ip_address=ip_address,
    attack_type="XSS Attack",
    severity="Critical",
    description="Cross Site Scripting payload detected.",
    country=location["country"],
    city=location["city"],
    latitude=location["latitude"],
    longitude=location["longitude"]
)
            incident = Incident(
                title="XSS Attack Detected",
                severity="Critical"
            )

            db.session.add(attack)
            db.session.add(incident)
            db.session.commit()

            score = calculate_threat_score()

            send_security_alert(
                subject="Cross Site Scripting Detected",
                message="Cross Site Scripting payload detected.",
                severity="Critical",
                ip_address=ip_address,
                location="Localhost (127.0.0.1)",
                browser="Unknown",
                device="Unknown",
                threat_score=score
            )
            print("XSS  Email Sent")

            create_security_log(
                event_type="XSS Attack",
                severity="Critical",
                ip_address=ip_address,
                description="Cross Site Scripting payload detected."
            )

            return True

    return False