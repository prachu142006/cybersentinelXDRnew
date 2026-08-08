from flask import Flask, render_template
from config import Config
from flask_mail import Message

from extensions import db, bcrypt, login_manager,mail

# Models
from models.user_model import User
from models.admin_model import Admin
from models.login_log_model import LoginLog
from models.attack_log_model import AttackLog
from models.blocked_ip_model import BlockedIP
from models.incident_model import Incident
from models.security_log_model import SecurityLog

# Routes
from routes.auth_routes import auth
from routes.dashboard_routes import dashboard
from routes.admin_routes import admin

app = Flask(__name__)

app.config.from_object(Config)

db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)
mail.init_app(app)
app.register_blueprint(auth)
app.register_blueprint(dashboard, url_prefix="")
app.register_blueprint(admin)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route("/test-email")
def test_email():

    msg = Message(
        subject="Cyber Sentinel XDR Test",
        recipients=["prachitivartak123@gmail.com"],
        body="Email service is working successfully."
    )

    mail.send(msg)

    return "Email Sent Successfully!"

if __name__ == "__main__":
    app.run(debug=True)

    from flask_mail import Message
from extensions import mail

@app.route("/")
def home():
  return render_template("index.html")