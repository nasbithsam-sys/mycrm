from app import db, app, User
from werkzeug.security import generate_password_hash
import pyotp

with app.app_context():
    db.create_all()

    # Add default admin if not exists
    if not User.query.filter_by(username="admin").first():
        admin = User(
            username="admin",
            password=generate_password_hash("admin123", method="pbkdf2:sha256"),
            role="admin",
            otp_secret=pyotp.random_base32(),
            otp_verified=False
        )
        db.session.add(admin)
        db.session.commit()
        print(f"✅ Admin user created with username=admin, password=admin123, otp_secret={admin.otp_secret}")
    else:
        print("⚠️ Admin already exists, skipped.")
