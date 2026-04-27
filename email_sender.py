"""Email utility for sending 2FA verification codes via Gmail SMTP."""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import EMAIL_SENDER, EMAIL_APP_PASSWORD, SMTP_HOST, SMTP_PORT, TWO_FA_EXPIRY_MINUTES


def send_2fa_code(recipient_email, code):
    """Send a 2FA verification code to the user's email. Returns True on success."""
    if not EMAIL_APP_PASSWORD:
        print(f"[WARNING] EMAIL_APP_PASSWORD not set. 2FA code for {recipient_email}: {code}")
        return False

    subject = "SecureApp - Your Verification Code"

    html_body = f"""
    <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 480px; margin: 0 auto;
                background: #0a0a0f; color: #e0e0f0; padding: 40px 30px; border-radius: 12px;
                border: 1px solid rgba(0,240,255,0.15);">
        <h2 style="text-align: center; color: #00f0ff; font-size: 18px; letter-spacing: 3px;
                   margin-bottom: 8px;">SECUREAPP</h2>
        <p style="text-align: center; color: #8888aa; font-size: 13px; letter-spacing: 1px;
                  margin-bottom: 30px;">TWO-FACTOR VERIFICATION</p>
        <div style="text-align: center; background: rgba(0,240,255,0.05); border: 1px solid rgba(0,240,255,0.15);
                    border-radius: 8px; padding: 25px; margin: 20px 0;">
            <p style="color: #8888aa; font-size: 12px; letter-spacing: 2px; margin: 0 0 10px 0;">YOUR CODE</p>
            <h1 style="font-family: 'Courier New', monospace; font-size: 42px; letter-spacing: 12px;
                       color: #00f0ff; margin: 0; text-shadow: 0 0 20px rgba(0,240,255,0.3);">{code}</h1>
        </div>
        <p style="text-align: center; color: #555577; font-size: 13px; margin-top: 20px;">
            This code expires in <strong style="color: #ffdd00;">{TWO_FA_EXPIRY_MINUTES} minutes</strong>.
        </p>
        <p style="text-align: center; color: #555577; font-size: 12px; margin-top: 15px;">
            If you didn't request this, ignore this email.
        </p>
        <hr style="border: none; border-top: 1px solid rgba(0,240,255,0.1); margin: 25px 0 15px 0;">
        <p style="text-align: center; color: #333355; font-size: 11px; letter-spacing: 1px;">
            RSA &middot; ECC &middot; SHA-256 &middot; HMAC &mdash; All encryption from scratch
        </p>
    </div>
    """

    plain_body = f"Your SecureApp verification code is: {code}\nIt expires in {TWO_FA_EXPIRY_MINUTES} minutes."

    msg = MIMEMultipart('alternative')
    msg['From'] = EMAIL_SENDER
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(plain_body, 'plain'))
    msg.attach(MIMEText(html_body, 'html'))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(EMAIL_SENDER, EMAIL_APP_PASSWORD)
            server.sendmail(EMAIL_SENDER, recipient_email, msg.as_string())
        return True
    except Exception as e:
        print(f"[ERROR] Failed to send 2FA email to {recipient_email}: {e}")
        return False
