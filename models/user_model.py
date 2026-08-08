from flask_login import UserMixin
from extensions import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    full_name = db.Column(db.String(100), nullable=False)

    email = db.Column(db.String(120), unique=True, nullable=False)

    password = db.Column(db.String(255), nullable=False)

    security_score = db.Column(db.Integer, default=100)

    created_at = db.Column(db.DateTime, server_default=db.func.now())

    login_logs = db.relationship(
        "LoginLog",
        backref="user",
        cascade="all, delete-orphan"
    )

    
    # security_logs = db.relationship(
    #     "SecurityLog",
    #     backref="user",
    #     passive_deletes=True
    # )

    def get_id(self):
        return str(self.id)