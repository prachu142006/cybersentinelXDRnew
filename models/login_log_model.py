from extensions import db


class LoginLog(db.Model):

    __tablename__ = "login_logs"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True
    )

    email = db.Column(
        db.String(120)
    )

    ip_address = db.Column(
        db.String(45),
        nullable=False
    )

    attempted_password = db.Column(
        db.String(255)
    )

    status = db.Column(
        db.String(20),
        nullable=False
    )

    login_time = db.Column(
        db.DateTime,
        server_default=db.func.now()
    )