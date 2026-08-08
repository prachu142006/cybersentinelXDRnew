import os

class Config:

    SECRET_KEY = "your-secret-key"

    SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:14%40prachu%232006@localhost/cybersentinel"

    SQLALCHEMY_TRACK_MODIFICATIONS = False


    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False

    MAIL_USERNAME = "prachitivartak123@gmail.com"
    MAIL_PASSWORD = "wzpb yxaa bbeh biuy"

    MAIL_DEFAULT_SENDER = "Cyber Sentinel XDR <prachitivartak123@gmail.com>"
