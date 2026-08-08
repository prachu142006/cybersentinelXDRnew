

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import psutil

from extensions import bcrypt
from sqlalchemy import func, or_


from extensions import db
from flask import jsonify



from models.blocked_ip_model import BlockedIP
from flask import flash, redirect, url_for

from flask import send_file
from reportlab.platypus import SimpleDocTemplate, Table
from reportlab.lib import colors
import csv
import os

from models.admin_model import Admin
from models.user_model import User
from models.attack_log_model import AttackLog
from models.blocked_ip_model import BlockedIP
from services.geoip_services import get_location
from services.threat_score_service import calculate_threat_score
from models.incident_model import Incident
admin = Blueprint("admin", __name__)


@admin.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        admin_user = Admin.query.filter_by(username=username).first()

        if admin_user and bcrypt.check_password_hash(admin_user.password, password):

            session["admin_id"] = admin_user.id

            flash("Admin Login Successful", "success")

            return redirect(url_for("admin.admin_dashboard"))

        flash("Invalid Username or Password", "danger")

    return render_template("auth/admin_login.html")


@admin.route("/admin/dashboard")
def admin_dashboard():

    if "admin_id" not in session:
        return redirect(url_for("admin.admin_login"))

    # Dashboard Counts
    total_users = User.query.count()
    total_attacks = AttackLog.query.count()
    total_blocked = BlockedIP.query.count()
    total_incidents = Incident.query.count()

    # Threat Score
    threat_score = calculate_threat_score()

    # -----------------------------
    # Attack Type Chart Data
    # -----------------------------
    attack_data = db.session.query(
        AttackLog.attack_type,
        func.count(AttackLog.id)
    ).group_by(
        AttackLog.attack_type
    ).all()

    attack_labels = [item[0] for item in attack_data]
    attack_counts = [item[1] for item in attack_data]

    # -----------------------------
    # Severity Chart Data
    # -----------------------------
    severity_data = db.session.query(
        AttackLog.severity,
        func.count(AttackLog.id)
    ).group_by(
        AttackLog.severity
    ).all()

    severity_labels = [item[0] for item in severity_data]
    severity_counts = [item[1] for item in severity_data]

    # Latest 10 Attack Logs
    recent_attacks = AttackLog.query.order_by(
    AttackLog.detected_at.desc()
    ).limit(10).all()
    cpu_usage = psutil.cpu_percent(interval=1)

    memory_usage = psutil.virtual_memory().percent

    server_status = "Online"

    database_status = "Connected"



    return render_template(
        "dashboard/admin_dashboard.html",

        total_users=total_users,
        total_attacks=total_attacks,
        total_blocked=total_blocked,
        total_incidents=total_incidents,
        threat_score=threat_score,

        attack_labels=attack_labels,
        attack_counts=attack_counts,

        severity_labels=severity_labels,
        severity_counts=severity_counts,

        recent_attacks=recent_attacks,
         cpu_usage=cpu_usage,
    memory_usage=memory_usage,
    server_status=server_status,
    database_status=database_status
    )

@admin.route("/admin/logout")
def admin_logout():

    session.pop("admin_id", None)

    flash("Admin Logged Out", "success")

    return redirect(url_for("admin.admin_login"))

@admin.route("/admin/unblock-all", methods=["POST"])
def unblock_all_ips():

    if "admin_id" not in session:
        return redirect(url_for("admin.admin_login"))

    BlockedIP.query.delete()
    db.session.commit()

    flash("All Blocked IPs have been removed successfully.", "success")

    return redirect(url_for("admin.admin_dashboard"))


from extensions import db
from flask import request, abort

@admin.route("/admin/report/csv")
def download_csv():

    if "admin_id" not in session:
        return redirect(url_for("admin.admin_login"))

    attacks = AttackLog.query.all()

    os.makedirs("reports", exist_ok=True)

    filename = "reports/attack_report.csv"

    with open(filename, "w", newline="", encoding="utf-8") as file:

        writer = csv.writer(file)

        writer.writerow([
            "ID",
            "IP Address",
            "Attack Type",
            "Severity",
            "Description",
            "Date"
        ])

        for attack in attacks:

            writer.writerow([
                attack.id,
                attack.ip_address,
                attack.attack_type,
                attack.severity,
                attack.description,
                attack.detected_at
            ])

    return send_file(filename, as_attachment=True)

@admin.route("/admin/report/pdf")
def download_pdf():

    if "admin_id" not in session:
        return redirect(url_for("admin.admin_login"))

    attacks = AttackLog.query.all()

    os.makedirs("reports", exist_ok=True)

    filename = "reports/attack_report.pdf"

    pdf = SimpleDocTemplate(filename)

    data = [[
        "ID",
        "IP",
        "Attack",
        "Severity",
        "Date"
    ]]

    for attack in attacks:

        data.append([
            attack.id,
            attack.ip_address,
            attack.attack_type,
            attack.severity,
            str(attack.detected_at)
        ])

    table = Table(data)

    table.setStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.grey),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), 1, colors.black),
        ("BACKGROUND", (0,1), (-1,-1), colors.beige)
    ])

    pdf.build([table])

    return send_file(filename, as_attachment=True)

@admin.route("/secret-admin")
def secret_admin():

    print("SECRET ADMIN HIT")

    ip_address = request.headers.get(
        "X-Forwarded-For",
        request.remote_addr
    ).split(",")[0].strip()

    print("IP:", ip_address)

    location = get_location(ip_address)

    print("LOCATION:", location)

    exists = AttackLog.query.filter_by(
        ip_address=ip_address,
        attack_type="Honeypot Access"
    ).first()

    if not exists:

        attack = AttackLog(
            ip_address=ip_address,
            attack_type="Honeypot Access",
            severity="Critical",
            description="Unauthorized access to hidden admin page.",
            country=location["country"],
            city=location["city"],
            latitude=location["latitude"],
            longitude=location["longitude"]
        )

        incident = Incident(
            title="Honeypot Access Detected",
            severity="Critical"
        )

        db.session.add(attack)
        db.session.add(incident)
        db.session.commit()

    abort(404)
# @admin.route("/secret-admin")
# def secret_admin():

#     ip_address = request.remote_addr

#     exists = AttackLog.query.filter_by(
#         ip_address=ip_address,
#         attack_type="Honeypot Access"
#     ).first()

#     if not exists:

#         location = get_location(ip_address)
#         print(location)
#         attack = AttackLog(
#             ip_address=ip_address,
#             attack_type="Honeypot Access",
#             severity="Critical",
#             description="Unauthorized access to hidden admin page.",
#             country=location["country"],
#             city=location["city"],
#             latitude=location["latitude"],
#             longitude=location["longitude"]
#         )

#         incident = Incident(
#             title="Honeypot Access Detected",
#             severity="Critical"
#         )

#         db.session.add(attack)
#         db.session.add(incident)
#         db.session.commit()

#     abort(404)
   

# @admin.route("/admin/live-attacks")
# def live_attacks():

#     if "admin_id" not in session:
#         return jsonify([])

#     ip = request.args.get("ip", "").strip()
#     attack = request.args.get("attack", "").strip()
#     severity = request.args.get("severity", "").strip()
    
#     query = AttackLog.query

#     if ip:
#         query = query.filter(AttackLog.ip_address.ilike(f"%{ip}%"))
#     if attack:
#         query = query.filter(AttackLog.attack_type.ilike(f"%{attack}%"))
#     if severity:
#         query = query.filter(AttackLog.severity.ilike(f"%{severity}%"))

#     attacks = (
#         query
#         .order_by(AttackLog.detected_at.desc())
#         .limit(10)
#         .all()
#     )

#     attack_list = []

#     for attack in attacks:

#         attack_list.append({

#             "id": attack.id,
#             "ip_address": attack.ip_address,
#             "attack_type": attack.attack_type,
#             "severity": attack.severity,
#             "country": attack.country,
#             "city": attack.city,
#             "detected_at": attack.detected_at.strftime("%d %b %Y %H:%M")

#         })

#     return jsonify(attack_list)

@admin.route("/admin/live-attacks")
def live_attacks():

    try:

        if "admin_id" not in session:
            return jsonify([])

        ip = request.args.get("ip", "").strip()
        attack = request.args.get("attack", "").strip()
        severity = request.args.get("severity", "").strip()

        print(ip, attack, severity)

        query = AttackLog.query

        if ip:
            query = query.filter(AttackLog.ip_address.ilike(f"%{ip}%"))

        if attack:
            query = query.filter(AttackLog.attack_type.ilike(f"%{attack}%"))

        if severity:
            query = query.filter(AttackLog.severity.ilike(f"%{severity}%"))

        attacks = query.order_by(
            AttackLog.detected_at.desc()
        ).limit(10).all()

        attack_list = []

        for item in attacks:

            attack_list.append({
                "id": item.id,
                "ip_address": item.ip_address,
                "attack_type": item.attack_type,
                "severity": item.severity,
                "country": item.country,
                "city": item.city,
                "detected_at": item.detected_at.strftime("%d %b %Y %H:%M")
            })

        return jsonify(attack_list)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
    
@admin.route("/admin/all-attacks")
def all_attacks():

    if "admin_id" not in session:
        return redirect(url_for("admin.login"))

    attacks = AttackLog.query.order_by(
        AttackLog.detected_at.desc()
    ).all()

    return render_template(
        "dashboard/all_attacks.html",
        attacks=attacks
        )
@admin.route("/admin/live-dashboard")
def live_dashboard():

    if "admin_id" not in session:
        return jsonify({"error": "Unauthorized"})

    total_users = User.query.count()

    total_attacks = AttackLog.query.count()

    total_blocked = BlockedIP.query.count()

    total_incidents = Incident.query.count()

    threat_score = calculate_threat_score()

    attack_data = db.session.query(
        AttackLog.attack_type,
        func.count(AttackLog.id)
    ).group_by(
        AttackLog.attack_type
    ).all()

    attack_labels = [x[0] for x in attack_data]

    attack_counts = [x[1] for x in attack_data]

    severity_data = db.session.query(
        AttackLog.severity,
        func.count(AttackLog.id)
    ).group_by(
        AttackLog.severity
    ).all()

    severity_labels = [x[0] for x in severity_data]

    severity_counts = [x[1] for x in severity_data]

    return jsonify({

        "total_users": total_users,

        "total_attacks": total_attacks,

        "total_blocked": total_blocked,

        "total_incidents": total_incidents,

        "threat_score": threat_score,

        "attack_labels": attack_labels,

        "attack_counts": attack_counts,

        "severity_labels": severity_labels,

        "severity_counts": severity_counts

    })



@admin.route("/admin/attack-map")
def attack_map():

    if "admin_id" not in session:
        return jsonify([])

    attacks = AttackLog.query.filter(
        AttackLog.latitude.isnot(None),
        AttackLog.longitude.isnot(None)
    ).all()

    data = []

    for attack in attacks:

        data.append({

            "ip": attack.ip_address,
            "country": attack.country,
            "city": attack.city,
            "lat": attack.latitude,
            "lng": attack.longitude,
            "type": attack.attack_type,
            "severity": attack.severity

        })

    return jsonify(data)