from extensions import db


class BlockedIP(db.Model):
    __tablename__ = "blocked_ips"

    id = db.Column(db.Integer, primary_key=True)

    ip_address = db.Column(
        db.String(45),
        unique=True,
        nullable=False
    )

    reason = db.Column(
        db.String(200),
        nullable=False
    )

    blocked_at = db.Column(
        db.DateTime,
        server_default=db.func.now()
    )