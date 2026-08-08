from flask_mail import Message
from extensions import mail
from flask import current_app
from datetime import datetime


def send_security_alert(
    subject,
    message,
    severity="High",
    ip_address="Unknown",
    location="Unknown",
    browser="Unknown",
    device="Unknown",
    threat_score=0
):

    if severity.lower() == "critical":
        severity_color = "#dc3545"      # Red
    elif severity.lower() == "high":
        severity_color = "#fd7e14"      # Orange
    elif severity.lower() == "medium":
        severity_color = "#ffc107"      # Yellow
    else:
        severity_color = "#198754"      # Green

    msg = Message(
        subject=f"🚨 {subject}",
        sender=current_app.config["MAIL_USERNAME"],
        recipients=[current_app.config["MAIL_USERNAME"]]
    )

    current_time = datetime.now().strftime("%d-%m-%Y %I:%M:%S %p")

    msg.html = f"""
<!DOCTYPE html>

<html>

<body style="font-family:Arial;background:#f4f4f4;padding:30px;">

<div style="
max-width:700px;
margin:auto;
background:white;
border-radius:10px;
overflow:hidden;
box-shadow:0 0 10px rgba(0,0,0,.2);
">

<div style="
background:#0d6efd;
color:white;
padding:20px;
text-align:center;
">

<h2>🛡 Cyber Sentinel XDR</h2>

<h4>Security Alert Notification</h4>

</div>

<div style="padding:30px;">

<h2 style="color:{severity_color};">
{subject}
</h2>

<table style="
width:100%;
border-collapse:collapse;
font-size:15px;
">

<tr>
<td><b>IP Address</b></td>
<td>{ip_address}</td>
</tr>

<tr>
<td><b>Severity</b></td>
<td style="color:{severity_color};">
{severity}
</td>
</tr>

<tr>
<td><b>Threat Score</b></td>
<td>{threat_score}</td>
</tr>

<tr>
<td><b>Location</b></td>
<td>{location}</td>
</tr>

<tr>
<td><b>Browser</b></td>
<td>{browser}</td>
</tr>

<tr>
<td><b>Device</b></td>
<td>{device}</td>
</tr>

<tr>
<td><b>Timestamp</b></td>
<td>{current_time}</td>
</tr>

</table>

<hr>

<pre style="
background:#f8f9fa;
padding:15px;
border-left:6px solid {severity_color};
white-space:pre-wrap;
font-size:15px;
">

{message}

</pre>

<p>

<strong>Status:</strong>

<span style="
background:{severity_color};
color:white;
padding:6px 12px;
border-radius:5px;
">

ACTIVE THREAT

</span>

</p>

</div>

<div style="
background:#212529;
color:white;
padding:15px;
text-align:center;
">

Cyber Sentinel XDR © 2026

</div>

</div>

</body>

</html>
"""

    mail.send(msg)