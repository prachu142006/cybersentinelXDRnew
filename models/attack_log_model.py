from extensions import db


class AttackLog(db.Model):

    __tablename__ = "attack_logs"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    ip_address = db.Column(
        db.String(45),
        nullable=False
    )

    attack_type = db.Column(
        db.String(100),
        nullable=False
    )

    severity = db.Column(
        db.String(20),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=False
    )

    detected_at = db.Column(
        db.DateTime,
        server_default=db.func.now()
    )

    # GeoIP Information

    country = db.Column(
        db.String(100)
    )

    city = db.Column(
        db.String(100)
    )

    latitude = db.Column(
        db.Float
    )

    longitude = db.Column(
        db.Float
    )