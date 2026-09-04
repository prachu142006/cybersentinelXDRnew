import os


class Config:

    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "dev-secret-key"
    )

    DATABASE_URL = os.getenv("DATABASE_URL")

    if DATABASE_URL and DATABASE_URL.startswith("mysql://"):
        DATABASE_URL = DATABASE_URL.replace(
            "mysql://",
            "mysql+pymysql://",
            1
        )

    SQLALCHEMY_DATABASE_URI = DATABASE_URL

    SQLALCHEMY_ENGINE_OPTIONS = {
        "connect_args": {
            "ssl": {}
        }
    }

    SQLALCHEMY_TRACK_MODIFICATIONS = False

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
