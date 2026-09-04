import os


class Config:

    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "dev-secret-key"
    )

    DATABASE_URL = os.getenv("DATABASE_URL")

    if DATABASE_URL:
        # SQLAlchemy ko PyMySQL driver use karwana hai
        DATABASE_URL = DATABASE_URL.replace(
            "mysql://",
            "mysql+pymysql://",
            1
        )

        # Aiven ka ssl-mode parameter PyMySQL accept nahi karta
        DATABASE_URL = DATABASE_URL.replace(
            "?ssl-mode=REQUIRED",
            ""
        )

    SQLALCHEMY_DATABASE_URI = DATABASE_URL

    SQLALCHEMY_ENGINE_OPTIONS = {
        "connect_args": {
            "ssl": {}
        }
    }

    SQLALCHEMY_TRACK_MODIFICATIONS = False


    # ---------------- MAIL SETTINGS ----------------

    MAIL_SERVER = os.getenv(
        "MAIL_SERVER",
        "smtp.gmail.com"
    )

    MAIL_PORT = int(
        os.getenv("MAIL_PORT", "587")
    )

    MAIL_USE_TLS = True
    MAIL_USE_SSL = False

    MAIL_USERNAME = os.getenv(
        "MAIL_USERNAME"
    )

    MAIL_PASSWORD = os.getenv(
        "MAIL_PASSWORD"
    )

    MAIL_DEFAULT_SENDER = os.getenv(
        "MAIL_DEFAULT_SENDER",
        "Cyber Sentinel XDR"
    )
