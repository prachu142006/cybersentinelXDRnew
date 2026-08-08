

from ipaddress import ip_address

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required

from extensions import db, bcrypt
from models.user_model import User
from flask import current_app
from models.login_log_model import LoginLog
from models.blocked_ip_model import BlockedIP


from services.security_service import (
    check_brute_force,
    check_credential_stuffing,
    check_password_spraying,
    check_account_enumeration,
    detect_sql_injection,
    detect_xss,
    create_security_log
)

auth = Blueprint("auth", __name__)

# ----------------------------
# Landing Page
# ----------------------------
@auth.route("/")
def home():
    return render_template("landing.html")
# ----------------------------
# User Registration
# ----------------------------
@auth.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        full_name = request.form.get("full_name")
        email = request.form.get("email")
        password = request.form.get("password")

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash("Email already registered.", "danger")
            return redirect(url_for("auth.register"))

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        new_user = User(
            full_name=full_name,
            email=email,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Registration Successful. Please Login.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")



# ----------------------------
# User Login
# ----------------------------
@auth.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email")
        password = request.form.get("password")

        # Get Real Client IP (Deployment Ready)
        ip_address = request.headers.get(
            "X-Forwarded-For",
            request.remote_addr
        ).split(",")[0].strip()

        # -----------------------------
        # Check if IP is blocked
        # -----------------------------
        blocked_ip = BlockedIP.query.filter_by(
            ip_address=ip_address
        ).first()

        if blocked_ip:
            flash(
                "🚫 Your IP Address has been blocked due to suspicious activity.",
                "danger"
            )
            return redirect(url_for("auth.login"))

        # -----------------------------
        # SQL Injection Detection
        # -----------------------------
        if detect_sql_injection(email, ip_address):
            flash("SQL Injection Attempt Detected.", "danger")
            return redirect(url_for("auth.login"))

        if detect_sql_injection(password, ip_address):
            flash("SQL Injection Attempt Detected.", "danger")
            return redirect(url_for("auth.login"))

        # -----------------------------
        # XSS Detection
        # -----------------------------
        if detect_xss(email, ip_address):
            flash("XSS Attack Detected.", "danger")
            return redirect(url_for("auth.login"))

        if detect_xss(password, ip_address):
            flash("XSS Attack Detected.", "danger")
            return redirect(url_for("auth.login"))

        # -----------------------------
        # Find User
        # -----------------------------
        user = User.query.filter_by(email=email).first()

        # -----------------------------
        # SUCCESS LOGIN
        # -----------------------------
        if user and bcrypt.check_password_hash(user.password, password):

            login_user(user)

            create_security_log(
                event_type="User Login",
                severity="Low",
                ip_address=ip_address,
                description="User logged into the system."
            )

            login_log = LoginLog(
                user_id=user.id,
                email=user.email,
                ip_address=ip_address,
                attempted_password=None,
                status="SUCCESS"
            )

            db.session.add(login_log)
            db.session.commit()

            flash("Login Successful.", "success")

            print("LOGIN SUCCESS")
            print(url_for("dashboard.dashboard_home"))
            print(current_app.url_map)

            return redirect(url_for("dashboard.dashboard_home"))

        # -----------------------------
        # FAILED LOGIN
        # -----------------------------
        failed_log = LoginLog(
            user_id=user.id if user else None,
            email=email,
            ip_address=ip_address,
            attempted_password=password,
            status="FAILED"
        )

        db.session.add(failed_log)
        db.session.commit()

        create_security_log(
            event_type="Failed Login",
            severity="Medium",
            ip_address=ip_address,
            description="Failed login attempt detected."
        )

        # -----------------------------
        # Attack Detection
        # -----------------------------
        check_brute_force(ip_address)
        check_credential_stuffing(ip_address)
        check_password_spraying(ip_address)
        check_account_enumeration(ip_address)

        flash("Invalid Email or Password", "danger")

        return redirect(url_for("auth.login"))

    return render_template("auth/login.html")
# ----------------------------
# Logout
# ----------------------------
@auth.route("/logout")
@login_required
def logout():

    logout_user()

    flash("Logged Out Successfully", "success")

    return redirect(url_for("auth.login"))