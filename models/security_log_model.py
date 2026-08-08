from extensions import db


class SecurityLog(db.Model):
    __tablename__ = "security_logs"

    id = db.Column(db.Integer, primary_key=True)

    event_type = db.Column(
        db.String(100),
        nullable=False
    )

    severity = db.Column(
        db.String(20),
        nullable=False
    )

    ip_address = db.Column(
        db.String(45),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        server_default=db.func.now()
    )