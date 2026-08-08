print("Loaded dashboard_routes.py")

from flask import (
    Blueprint,
    render_template,
    jsonify,
    send_file,
    Response
)

from flask_login import login_required, current_user

from sqlalchemy import func

from datetime import datetime, timedelta

import psutil
import csv
import os

from io import StringIO

from reportlab.pdfgen import canvas

from extensions import db

from models.login_log_model import LoginLog
from models.attack_log_model import AttackLog


dashboard = Blueprint("dashboard", __name__)


# ============================================================
# LANDING PAGE
# ============================================================

@dashboard.route("/")
def landing():

    return render_template("landing.html")


# ============================================================
# USER DASHBOARD
# ============================================================

@dashboard.route("/dashboard")
@login_required
def dashboard_home():

    print("dashboard_home route loaded")

    # --------------------------------------------------------
    # LOGIN COUNT
    # --------------------------------------------------------

    login_count = LoginLog.query.filter_by(
        user_id=current_user.id,
        status="SUCCESS"
    ).count()


    # --------------------------------------------------------
    # ALL ATTACKS
    # --------------------------------------------------------

    attack_logs = (
        AttackLog.query
        .order_by(AttackLog.detected_at.desc())
        .all()
    )


    # --------------------------------------------------------
    # TOTAL ATTACKS
    # --------------------------------------------------------

    total_attacks = len(attack_logs)

    threat_count = total_attacks


    # --------------------------------------------------------
    # ATTACK TYPES
    # --------------------------------------------------------

    attack_types = {}

    for attack in attack_logs:

        attack_type = attack.attack_type

        if attack_type not in attack_types:

            attack_types[attack_type] = 0

        attack_types[attack_type] += 1


    # --------------------------------------------------------
    # SEVERITY COUNTS
    # --------------------------------------------------------

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for attack in attack_logs:

        severity = attack.severity.upper()

        if severity == "CRITICAL":

            critical_count += 1

        elif severity == "HIGH":

            high_count += 1

        elif severity == "MEDIUM":

            medium_count += 1

        elif severity == "LOW":

            low_count += 1


    # --------------------------------------------------------
    # SECURITY SCORE
    # --------------------------------------------------------

    security_score = (
        100
        - (critical_count * 15)
        - (high_count * 8)
        - (medium_count * 4)
        - (low_count * 2)
    )

    security_score = max(
        0,
        min(100, security_score)
    )


    # --------------------------------------------------------
    # SYSTEM STATUS
    # --------------------------------------------------------

    if critical_count > 0 or high_count > 0:

        system_status = "Under Attack"

    elif medium_count > 0:

        system_status = "Warning"

    else:

        system_status = "Secure"


    # --------------------------------------------------------
    # RECENT ATTACKS
    # --------------------------------------------------------

    recent_attacks = attack_logs[:5]


    # --------------------------------------------------------
    # ATTACK TREND - LAST 7 DAYS
    # --------------------------------------------------------

    last_7_days = (
        datetime.utcnow()
        - timedelta(days=7)
    )


    trend = (
        db.session.query(
            func.date(AttackLog.detected_at),
            func.count(AttackLog.id)
        )
        .filter(
            AttackLog.detected_at >= last_7_days
        )
        .group_by(
            func.date(AttackLog.detected_at)
        )
        .order_by(
            func.date(AttackLog.detected_at)
        )
        .all()
    )


    trend_labels = [
        str(row[0])
        for row in trend
    ]

    trend_values = [
        int(row[1])
        for row in trend
    ]


    # --------------------------------------------------------
    # SYSTEM INFORMATION
    # --------------------------------------------------------

    cpu_usage = psutil.cpu_percent(
        interval=0
    )

    memory_usage = psutil.virtual_memory().percent

    server_status = "Online"

    database_status = "Connected"

    last_scan = "Just Now"


    # --------------------------------------------------------
    # TOP ATTACKERS
    # --------------------------------------------------------

    top_attackers = (
        db.session.query(
            AttackLog.ip_address,
            func.count(AttackLog.id).label("total")
        )
        .group_by(
            AttackLog.ip_address
        )
        .order_by(
            func.count(AttackLog.id).desc()
        )
        .limit(5)
        .all()
    )


    # --------------------------------------------------------
    # RENDER DASHBOARD
    # --------------------------------------------------------

    return render_template(

        "dashboard/user_dashboard.html",

        user=current_user,

        security_score=security_score,

        login_count=login_count,

        threat_count=threat_count,

        total_attacks=total_attacks,

        system_status=system_status,

        attack_types=attack_types,

        recent_attacks=recent_attacks,

        trend_labels=trend_labels,

        trend_values=trend_values,

        top_attackers=top_attackers,

        critical_count=critical_count,

        high_count=high_count,

        medium_count=medium_count,

        low_count=low_count,

        cpu_usage=cpu_usage,

        memory_usage=memory_usage,

        server_status=server_status,

        database_status=database_status,

        last_scan=last_scan
    )


# ============================================================
# LIVE DASHBOARD DATA
# ============================================================

@dashboard.route("/dashboard-data")
@login_required
def dashboard_data():

    # --------------------------------------------------------
    # LOGIN COUNT
    # --------------------------------------------------------

    login_count = LoginLog.query.filter_by(
        user_id=current_user.id,
        status="SUCCESS"
    ).count()


    # --------------------------------------------------------
    # GET ALL ATTACKS
    # --------------------------------------------------------

    attack_logs = (
        AttackLog.query
        .order_by(
            AttackLog.detected_at.desc()
        )
        .all()
    )


    # --------------------------------------------------------
    # TOTAL ATTACKS
    # --------------------------------------------------------

    total_attacks = len(attack_logs)

    threat_count = total_attacks


    # --------------------------------------------------------
    # ATTACK TYPES
    # --------------------------------------------------------

    attack_types = {}

    for attack in attack_logs:

        attack_type = attack.attack_type

        if attack_type not in attack_types:

            attack_types[attack_type] = 0

        attack_types[attack_type] += 1


    # --------------------------------------------------------
    # SEVERITY COUNTS
    # --------------------------------------------------------

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for attack in attack_logs:

        severity = attack.severity.upper()

        if severity == "CRITICAL":

            critical_count += 1

        elif severity == "HIGH":

            high_count += 1

        elif severity == "MEDIUM":

            medium_count += 1

        elif severity == "LOW":

            low_count += 1


    # --------------------------------------------------------
    # SECURITY SCORE
    # --------------------------------------------------------

    security_score = (
        100
        - (critical_count * 15)
        - (high_count * 8)
        - (medium_count * 4)
        - (low_count * 2)
    )

    security_score = max(
        0,
        min(100, security_score)
    )


    # --------------------------------------------------------
    # SYSTEM STATUS
    # --------------------------------------------------------

    if critical_count > 0 or high_count > 0:

        system_status = "Under Attack"

    elif medium_count > 0:

        system_status = "Warning"

    else:

        system_status = "Secure"


    # --------------------------------------------------------
    # TREND - LAST 7 DAYS
    # --------------------------------------------------------

    last_7_days = (
        datetime.utcnow()
        - timedelta(days=7)
    )


    trend = (
        db.session.query(
            func.date(AttackLog.detected_at),
            func.count(AttackLog.id)
        )
        .filter(
            AttackLog.detected_at >= last_7_days
        )
        .group_by(
            func.date(AttackLog.detected_at)
        )
        .order_by(
            func.date(AttackLog.detected_at)
        )
        .all()
    )


    trend_labels = [
        str(row[0])
        for row in trend
    ]

    trend_values = [
        int(row[1])
        for row in trend
    ]


    # --------------------------------------------------------
    # LATEST ATTACK
    # --------------------------------------------------------

    latest_attack = None

    if attack_logs:

        latest_attack = attack_logs[0]


    if latest_attack:

        latest_time = (
            latest_attack.detected_at.isoformat()
        )

        latest_attack_type = (
            latest_attack.attack_type
        )

    else:

        latest_time = ""

        latest_attack_type = ""


    # --------------------------------------------------------
    # SYSTEM INFORMATION
    # --------------------------------------------------------

    cpu_usage = psutil.cpu_percent(
        interval=0
    )

    memory_usage = (
        psutil.virtual_memory().percent
    )


    # --------------------------------------------------------
    # RECENT ATTACKS
    # --------------------------------------------------------

    recent_attacks = []


    for attack in attack_logs[:5]:

        severity = attack.severity.upper()


        if severity == "CRITICAL":

            risk_score = 95

        elif severity == "HIGH":

            risk_score = 70

        elif severity == "MEDIUM":

            risk_score = 50

        else:

            risk_score = 20


        # --------------------------------------------
        # Recommendations
        # --------------------------------------------

        if attack.attack_type == "SQL Injection":

            recommendation = [

                "Block Source IP",

                "Enable Prepared Statements",

                "Review Database Logs",

                "Check Authentication Logs"

            ]

        elif attack.attack_type == "XSS Attack":

            recommendation = [

                "Sanitize User Input",

                "Enable Content Security Policy (CSP)",

                "Validate Output Encoding",

                "Review Browser Logs"

            ]

        elif attack.attack_type == "Brute Force":

            recommendation = [

                "Block Source IP",

                "Enable Account Lockout",

                "Reset User Password",

                "Enable Multi-Factor Authentication"

            ]

        else:

            recommendation = [

                "Investigate Logs",

                "Notify Security Team",

                "Monitor Suspicious Activity"

            ]


        recent_attacks.append({

            "time": (
                attack.detected_at.strftime(
                    "%d-%m-%Y %H:%M:%S"
                )
                if attack.detected_at
                else ""
            ),

            "attack_type": attack.attack_type,

            "ip_address": attack.ip_address,

            "severity": attack.severity,

            "description": attack.description,

            "status": "Blocked",

            "risk_score": risk_score,

            "source": "Web Application Firewall",

            "country": (
                attack.country
                if attack.country
                else "India"
            ),

            "hostname": "localhost",

            "recommendation": recommendation

        })


    # --------------------------------------------------------
    # JSON RESPONSE
    # --------------------------------------------------------

    return jsonify({

        "login_count": int(login_count),

        "threat_count": int(threat_count),

        "total_attacks": int(total_attacks),

        "system_status": system_status,

        "attack_types": attack_types,

        "critical_count": int(critical_count),

        "high_count": int(high_count),

        "medium_count": int(medium_count),

        "low_count": int(low_count),

        "security_score": int(security_score),

        "trend_labels": trend_labels,

        "trend_values": trend_values,

        "cpu_usage": cpu_usage,

        "memory_usage": memory_usage,

        "latest_attack": latest_attack_type,

        "latest_time": latest_time,

        "recent_attacks": recent_attacks

    })


# ============================================================
# DOWNLOAD CSV
# ============================================================

@dashboard.route("/download/csv")
@login_required
def download_csv():

    attacks = (
        AttackLog.query
        .order_by(
            AttackLog.detected_at.desc()
        )
        .all()
    )


    output = StringIO()

    writer = csv.writer(output)


    writer.writerow([

        "Time",
        "IP Address",
        "Attack Type",
        "Severity",
        "Description"

    ])


    for attack in attacks:

        writer.writerow([

            attack.detected_at,

            attack.ip_address,

            attack.attack_type,

            attack.severity,

            attack.description

        ])


    return Response(

        output.getvalue(),

        mimetype="text/csv",

        headers={

            "Content-Disposition":
            "attachment; filename=attack_report.csv"

        }

    )


# ============================================================
# DOWNLOAD PDF
# ============================================================

@dashboard.route("/download/pdf")
@login_required
def download_pdf():

    attacks = (
        AttackLog.query
        .order_by(
            AttackLog.detected_at.desc()
        )
        .all()
    )


    if not os.path.exists("reports"):

        os.makedirs("reports")


    pdf_path = (
        "reports/attack_report.pdf"
    )


    pdf = canvas.Canvas(pdf_path)


    pdf.setFont(
        "Helvetica-Bold",
        16
    )


    pdf.drawString(
        180,
        810,
        "Cyber Sentinel XDR"
    )


    pdf.setFont(
        "Helvetica",
        12
    )


    y = 780


    for attack in attacks:

        pdf.drawString(

            40,

            y,

            f"{attack.detected_at} | "
            f"{attack.attack_type} | "
            f"{attack.severity} | "
            f"{attack.ip_address}"

        )


        y -= 20


        if y < 40:

            pdf.showPage()

            y = 800


    pdf.save()


    return send_file(

        pdf_path,

        as_attachment=True

    )


# ============================================================
# ATTACK HISTORY
# ============================================================

@dashboard.route("/attack-history")
@login_required
def attack_history():

    attacks = (
        AttackLog.query
        .order_by(
            AttackLog.detected_at.desc()
        )
        .all()
    )


    return render_template(

        "dashboard/attack_history.html",

        attacks=attacks

    )