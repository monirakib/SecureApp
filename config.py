"""Application configuration."""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE_DIR, 'keys')
DB_PATH = os.path.join(BASE_DIR, 'app.db')

# Flask secret key (used only for flash messages, not for session crypto)
FLASK_SECRET = os.environ.get('FLASK_SECRET', os.urandom(32).hex())

# Session duration in hours
SESSION_DURATION_HOURS = 24

# 2FA code expiry in minutes
TWO_FA_EXPIRY_MINUTES = 5

# RSA key size in bits
RSA_KEY_BITS = 1024

# Email configuration (Gmail SMTP)
EMAIL_SENDER = 'secureappproj@gmail.com'
EMAIL_APP_PASSWORD = os.environ.get('EMAIL_APP_PASSWORD', '')
SMTP_HOST = 'smtp.gmail.com'
SMTP_PORT = 587

# Upload configuration
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
MAX_UPLOAD_SIZE = 2 * 1024 * 1024  # 2MB

# Report categories
CATEGORIES = ['corruption', 'fraud', 'safety', 'harassment', 'environmental', 'corporate', 'government', 'other']

# Urgency levels
URGENCY_LEVELS = ['critical', 'high', 'medium', 'low']
