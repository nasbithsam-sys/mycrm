import os
import csv
import io
import uuid
import re
import time
import pyotp
from datetime import datetime, date, timedelta
from functools import wraps
from collections import Counter

from flask import (
    Flask, render_template, redirect, url_for, request, flash,
    send_from_directory, Response, make_response, session
)
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
load_dotenv()  # ✅ This loads .env file automatically
import cloudinary
import cloudinary.uploader

cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME", "dgj1mf0ca"),
    api_key=os.getenv("CLOUDINARY_API_KEY", "688872972948856"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET", "HQF4ljVl-zF4etc9Og0WZiYE1Tw")
)

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from dateutil.relativedelta import relativedelta
from sqlalchemy import cast, Date, extract
from sqlalchemy.orm import joinedload

# ---------------------------
# App Config
# ---------------------------
app = Flask(__name__)
import secrets

# ✅ Secure secret key
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(16))
app.config["SESSION_PERMANENT"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)  # auto logout after 30 mins

# ---------------------------
# Database Config
# ---------------------------
db_url = os.environ.get("DATABASE_URL", "sqlite:///crm.db").replace("postgres://", "postgresql://")

# ✅ Add SSL mode if using Postgres (for Render/Supabase)
if "sslmode" not in db_url and db_url.startswith("postgresql"):
    db_url += "?sslmode=require"

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ---------------------------
# File Upload Config
# ---------------------------
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}

# ---------------------------
# SQLAlchemy Engine (Render-safe)
# ---------------------------
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

# ✅ Connection-stable engine (avoids Render idle disconnects)
engine = create_engine(
    app.config["SQLALCHEMY_DATABASE_URI"],
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=2
)

db = SQLAlchemy()
db.session = scoped_session(sessionmaker(bind=engine))
db.init_app(app)

# ---------------------------
# Login Manager
# ---------------------------
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"

os.makedirs('uploads', exist_ok=True)

# ---------------------------
# Helpers
# ---------------------------
DEPARTMENTS = [
    "Facebook lead",
    "ND Inbound",
    "ND Tech & Old Customer Reference",
    "ND General"
]

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def normalize_phone(num: str) -> str:
    digits = re.sub(r'\D+', '', num)
    if digits.startswith('92'):
        return '+' + digits
    if digits.startswith('0'):
        return '+92' + digits[1:]
    if not digits.startswith('+'):
        return '+' + digits
    return digits

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            flash("❌ Access denied. Admins only.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped

# ---------------------------
# Models
# ---------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="user")  # admin / user
    otp_secret = db.Column(db.String(32), nullable=True)  # per-user TOTP secret
    otp_verified = db.Column(db.Boolean, default=False)   # per-login verified flag
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    department = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), default="New Lead")
    sub_status = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", foreign_keys=[user_id], backref=db.backref("leads", lazy=True))

    assigned_to = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    assignee = db.relationship("User", foreign_keys=[assigned_to], backref=db.backref("assigned_leads", lazy=True))

    customer_name = db.Column(db.String(150), nullable=False)
    customer_number = db.Column(db.String(20), nullable=False)
    context_service = db.Column(db.Text, nullable=False)
    main_area = db.Column(db.String(100), nullable=False)
    second_main_area = db.Column(db.String(100))
    sub_location = db.Column(db.String(100))
    attachment_filename = db.Column(db.String(200))
    added_by = db.Column(db.String(100), nullable=False)

    closed_at = db.Column(db.DateTime, nullable=True)
    closed_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    closed_by_user = db.relationship("User", foreign_keys=[closed_by], backref="closed_leads")
    archived = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------------------
# OTP Enforcement
# ---------------------------
@app.before_request
def enforce_otp():
    # allow static and error handlers
    if request.endpoint in ("static", None):
        return

    # not logged in → must go to login
    if not current_user.is_authenticated:
        if request.endpoint not in ("login", "register"):
            return redirect(url_for("login"))
        return

    # logged in but not OTP verified → must go to verify_otp
    if current_user.is_authenticated and not current_user.otp_verified:
        if request.endpoint not in ("verify_otp", "logout", "login"):
            return redirect(url_for("verify_otp"))

# ---------------------------
# Auth & User Routes
# ---------------------------
@app.route("/")
def home():
    return redirect(url_for("dashboard")) if current_user.is_authenticated else redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
@login_required
@admin_required
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        role = request.form.get("role", "user")

        if User.query.filter_by(username=username).first():
            flash("⚠️ Username already exists.", "warning")
            return redirect(url_for("register"))

        # Generate OTP secret for this user
        secret = pyotp.random_base32()

        new_user = User(
            username=username,
            password=generate_password_hash(password, method="pbkdf2:sha256"),
            role=role,
            otp_secret=secret,
            otp_verified=False
        )
        db.session.add(new_user)
        db.session.commit()

        # Show OTP secret so user can add it to WinAuth (PC)
        flash(f"✅ User '{username}' created successfully! OTP Secret: {secret}", "info")
        return redirect(url_for("users"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated and current_user.otp_verified:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password, password):
            flash("❌ Invalid username or password.", "danger")
            return redirect(url_for("login"))

        # Reset OTP on every login
        user.otp_verified = False
        db.session.commit()

        # Login without "remember"
        login_user(user, remember=False, fresh=True)

        # ✅ Always go to OTP page right after login
        return redirect(url_for("verify_otp"))

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    # reset OTP verification every logout
    current_user.otp_verified = False
    db.session.commit()

    logout_user()
    flash("👋 You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/verify_otp", methods=["GET", "POST"])
@login_required
def verify_otp():
    # Safety: ensure the user actually has a secret
    if not current_user.otp_secret:
        current_user.otp_secret = pyotp.random_base32()
        db.session.commit()
        flash(f"ℹ️ OTP Secret generated for '{current_user.username}': {current_user.otp_secret}", "info")

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        totp = pyotp.TOTP(current_user.otp_secret)

        # Allow 1-step clock drift (valid_window=1) to avoid time skew issues
        if totp.verify(code, valid_window=1):
            current_user.otp_verified = True
            db.session.commit()
            flash("✅ OTP verified, welcome!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("❌ Invalid OTP", "danger")

    return render_template("verify_otp.html")

@app.route("/users")
@login_required
@admin_required
def users():
    return render_template("users.html", users=User.query.all(), title="Users Management")

@app.route("/add_lead")
@login_required
def add_lead():
    return render_template("add_lead.html", departments=DEPARTMENTS)

# ---------------------------
# Leads (Create & List)
# ---------------------------
@app.route("/leads", methods=["GET", "POST"])
@login_required
def leads():
    if request.method == "POST":
        customer_name = request.form["customer_name"].strip()
        customer_number = normalize_phone(request.form["customer_number"].strip())
        context_service = request.form["context_service"].strip()
        department = request.form["department"]
        main_area = request.form["main_area"]
        second_main_area = request.form.get("second_main_area", "")
        sub_location = request.form.get("sub_location", "")
        added_by = request.form["added_by"].strip()

        # ✅ Create new lead object
        new_lead = Lead(
            department=department,
            status="New Lead",
            user_id=current_user.id,
            customer_name=customer_name,
            customer_number=customer_number,
            context_service=context_service,
            main_area=main_area,
            second_main_area=second_main_area,
            sub_location=sub_location,
            added_by=added_by
        )

        # ✅ Handle file upload (to Cloudinary)
        uploaded_file = request.files.get('attachment')
        if uploaded_file and uploaded_file.filename.strip() != '':
            if allowed_file(uploaded_file.filename):
                try:
                    upload_result = cloudinary.uploader.upload(
                        uploaded_file,
                        folder="leads",        # folder in Cloudinary
                        resource_type="auto"   # handles images, pdfs, docs, etc.
                    )
                    # Save secure Cloudinary URL in database
                    new_lead.attachment_filename = upload_result["secure_url"]
                    flash("✅ File uploaded to Cloudinary successfully!", "success")

                except Exception as e:
                    flash(f"❌ Cloud upload failed: {str(e)}", "danger")
            else:
                flash("⚠️ Invalid file type.", "warning")
        else:
            flash("ℹ️ No attachment uploaded.", "info")

        # ✅ Commit lead to database
        db.session.add(new_lead)
        db.session.commit()
        flash("✅ Lead added successfully!", "success")
        return redirect(url_for("leads"))

    # ✅ Show all leads depending on user role
    initial_statuses = ["New Lead", "Issue in Lead", "Updated"]
    if current_user.role == "admin":
        leads_list = Lead.query.filter(Lead.status.in_(initial_statuses)).all()
    else:
        leads_list = Lead.query.filter_by(user_id=current_user.id).filter(
            Lead.status.in_(initial_statuses)
        ).all()

    return render_template("leads.html", leads=leads_list, departments=DEPARTMENTS)

# ---------------------------
# Leads (Admin View & Edit)
# ---------------------------
@app.route("/view_leads")
@login_required
@admin_required
def view_leads():
    status_filter = request.args.get('status', 'all')
    department_filter = request.args.get('department', 'all')

    query = Lead.query
    if status_filter != 'all':
        query = query.filter(Lead.status == status_filter)
    else:
        active_statuses = ["Pending Outreach", "Texted / Call Done", "In Progress"]
        query = query.filter(Lead.status.in_(active_statuses))
    if department_filter != 'all':
        query = query.filter(Lead.department == department_filter)

    leads_data = query.all()
    return render_template("view_leads.html", leads=leads_data, departments=DEPARTMENTS)

@app.route("/edit_lead/<int:lead_id>", methods=["GET", "POST"])
@login_required
def edit_lead(lead_id):
    lead = Lead.query.get_or_404(lead_id)

    if current_user.role != "admin" and lead.user_id != current_user.id:
        flash("⚠️ You can only edit your own leads.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        old_values = {
            "customer_name": lead.customer_name,
            "customer_number": lead.customer_number,
            "context_service": lead.context_service,
            "department": lead.department,
            "main_area": lead.main_area,
            "second_main_area": lead.second_main_area,
            "sub_location": lead.sub_location,
        }

        lead.customer_name = request.form.get("customer_name", lead.customer_name)
        lead.customer_number = normalize_phone(request.form.get("customer_number", lead.customer_number))
        lead.context_service = request.form.get("context_service", lead.context_service)
        lead.department = request.form.get("department", lead.department)
        lead.main_area = request.form.get("main_area", lead.main_area)
        lead.second_main_area = request.form.get("second_main_area", lead.second_main_area)
        lead.sub_location = request.form.get("sub_location", lead.sub_location)

        changes_made = any(getattr(lead, k) != v for k, v in old_values.items())

        if changes_made:
            lead.status = "Updated"
            flash("✏️ Lead updated successfully and status changed to 'Updated'.", "success")
        else:
            flash("✏️ Lead information saved (no changes detected).", "info")

        db.session.commit()
        return redirect(url_for("dashboard"))

    return render_template("edit_lead.html", lead=lead, departments=DEPARTMENTS)

@app.route("/resolve_lead/<int:lead_id>", methods=["POST"])
@login_required
def resolve_lead(lead_id):
    lead = Lead.query.get_or_404(lead_id)

    if current_user.role != "admin" and lead.user_id != current_user.id:
        flash("⚠️ You can only resolve your own issue leads.", "danger")
        return redirect(url_for("dashboard"))

    lead.status = "Updated"
    db.session.commit()
    flash("✅ Lead resolved successfully! Status changed to 'Updated'.", "success")
    return redirect(url_for("dashboard"))

@app.route("/update_status/<int:lead_id>", methods=["POST"])
@login_required
def update_status(lead_id):
    lead = Lead.query.get_or_404(lead_id)

    if current_user.role != "admin":
        flash("⚠️ You are not allowed to update this lead.", "danger")
        return redirect(request.referrer or url_for("dashboard"))

    new_status = request.form.get("status", "").strip()
    origin = request.form.get("origin", "").strip()

    if origin == "my_leads":
        allowed = {"New Lead", "Issue in Lead", "Updated", "Done"}
        if new_status not in allowed:
            flash("⚠️ Invalid status for this page.", "warning")
            return redirect(url_for("leads"))

        if new_status == "Done":
            lead.status = "Pending Outreach"
            lead.closed_at = None
            lead.closed_by = None
            lead.sub_status = None
        else:
            lead.status = new_status
            lead.closed_at = None
            lead.closed_by = None
            lead.sub_status = None
        db.session.commit()
        flash("✅ Lead status updated.", "success")
        return redirect(url_for("leads"))

    if origin == "all_leads":
        allowed = {"Pending Outreach", "Texted / Call Done", "In Progress", "Done"}
        if new_status not in allowed:
            flash("⚠️ Invalid status for this page.", "warning")
            return redirect(url_for("view_leads"))

        if new_status == "Done":
            lead.status = "Done"
            lead.closed_at = datetime.utcnow()
            lead.closed_by = current_user.id
            lead.sub_status = None
        else:
            lead.status = new_status
            lead.closed_at = None
            lead.closed_by = None
            lead.sub_status = None
        db.session.commit()
        flash("✅ Lead status updated.", "success")
        return redirect(url_for("view_leads"))

    flash("⚠️ Missing origin. Please update from My Leads or All Leads.", "warning")
    return redirect(request.referrer or url_for("dashboard"))

# ---------------------------
# Closed Leads
# ---------------------------
@app.route("/closed_leads")
@login_required
def closed_leads():
    closed = Lead.query.options(joinedload(Lead.closed_by_user)).filter_by(status="Done").all()
    total_leads = len(closed)

    user_counts = Counter(lead.closed_by_user.username if lead.closed_by_user else "Unknown" for lead in closed)
    top_labels = list(user_counts.keys())
    top_data = list(user_counts.values())

    date_counts = Counter(lead.closed_at.date() for lead in closed if lead.closed_at)
    trend_labels = sorted([d.strftime("%Y-%m-%d") for d in date_counts.keys()])
    trend_data = [date_counts[datetime.strptime(d, "%Y-%m-%d").date()] for d in trend_labels]

    return render_template(
        "closed_leads.html",
        closed_leads=closed,
        total_leads=total_leads,
        now=datetime.now(),
        departments=DEPARTMENTS,
        top_labels=top_labels,
        top_data=top_data,
        trend_labels=trend_labels,
        trend_data=trend_data
    )

# ---------------------------
# Dashboard
# ---------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    today = date.today()

    if current_user.role == "admin":
        total_leads = Lead.query.count()
        my_leads = Lead.query.filter_by(user_id=current_user.id).count()
        new_today = Lead.query.filter(cast(Lead.created_at, Date) == today).count()

        dept_stats = db.session.query(Lead.department, db.func.count(Lead.id)).group_by(Lead.department).all()
        dept_labels = [d[0] for d in dept_stats]
        dept_counts = [d[1] for d in dept_stats]

        return render_template(
            "dashboard.html",
            total_leads=total_leads,
            my_leads=my_leads,
            new_today=new_today,
            dept_labels=dept_labels,
            dept_counts=dept_counts,
            now=datetime.now(),
            is_admin=True
        )
    else:
        today_leads = Lead.query.filter(
            Lead.user_id == current_user.id,
            cast(Lead.created_at, Date) == today
        ).count()

        issue_leads = Lead.query.filter(
            Lead.user_id == current_user.id,
            Lead.status == 'Issue in Lead'
        ).count()

        resolved_today = Lead.query.filter(
            Lead.user_id == current_user.id,
            cast(Lead.created_at, Date) == today,
            Lead.status.in_(['Done', 'Texted / Call Done', 'Connected', 'Completed'])
        ).count()

        today_leads_list = Lead.query.filter(
            Lead.user_id == current_user.id,
            cast(Lead.created_at, Date) == today
        ).order_by(Lead.created_at.desc()).all()

        issue_leads_list = Lead.query.filter(
            Lead.user_id == current_user.id,
            Lead.status == 'Issue in Lead'
        ).order_by(Lead.created_at.desc()).all()

        recent_leads = Lead.query.filter_by(user_id=current_user.id).order_by(Lead.created_at.desc()).limit(5).all()

        return render_template(
            "dashboard.html",
            today_leads=today_leads,
            issue_leads=issue_leads,
            resolved_today=resolved_today,
            today_leads_list=today_leads_list,
            issue_leads_list=issue_leads_list,
            recent_leads=recent_leads,
            now=datetime.now(),
            is_admin=False
        )

# ---------------------------
# Analytics
# ---------------------------
@app.route("/analytics")
@login_required
@admin_required
def analytics():
    today = date.today()

    today_leads = Lead.query.filter(cast(Lead.created_at, Date) == today).count()

    week_leads, week_labels = [], []
    for i in range(4):
        week_start = today - timedelta(days=today.weekday() + (3 - i) * 7)
        week_end = week_start + timedelta(days=6)
        week_count = Lead.query.filter(
            Lead.created_at >= week_start,
            Lead.created_at <= week_end
        ).count()
        week_leads.append(week_count)
        week_labels.append(week_start.strftime('%b %d'))

    month_leads, month_labels = [], []
    for i in range(6):
        month_date = today - relativedelta(months=(5 - i))
        year, month = month_date.year, month_date.month
        month_count = Lead.query.filter(
            extract('year', Lead.created_at) == year,
            extract('month', Lead.created_at) == month
        ).count()
        month_leads.append(month_count)
        month_labels.append(month_date.strftime('%b %Y'))

    dept_stats = db.session.query(Lead.department, db.func.count(Lead.id)).group_by(Lead.department).all()
    confirmed_dept_stats = db.session.query(Lead.department, db.func.count(Lead.id)).filter_by(status="Done").group_by(Lead.department).all()
    status_stats = db.session.query(Lead.status, db.func.count(Lead.id)).group_by(Lead.status).all()

    return render_template(
        "analytics.html",
        today_leads=today_leads,
        week_leads=week_leads,
        week_labels=week_labels,
        month_leads=month_leads,
        month_labels=month_labels,
        dept_stats=dept_stats,
        confirmed_dept_stats=confirmed_dept_stats,
        status_stats=status_stats,
        now=datetime.now()
    )

# ---------------------------
# File Uploads
# ---------------------------
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ---------------------------
# Export Routes
# ---------------------------
@app.route("/export_leads")
@login_required
@admin_required
def export_leads():
    leads = Lead.query.all()

    def generate():
        data = [['ID', 'Customer Name', 'Customer Number', 'Department',
                 'Status', 'Sub Status', 'Main Area', 'Second Area', 'Sub Location',
                 'Context Service', 'Added By', 'Created Date']]
        for lead in leads:
            data.append([
                lead.id,
                lead.customer_name,
                lead.customer_number,
                lead.department,
                lead.status,
                lead.sub_status or '',
                lead.main_area,
                lead.second_main_area or '',
                lead.sub_location or '',
                lead.context_service,
                lead.added_by,
                lead.created_at.strftime('%Y-%m-%d %H:%M')
            ])
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerows(data)
        return output.getvalue()

    response = Response(generate(), mimetype='text/csv')
    response.headers.set("Content-Disposition", "attachment", filename=f"leads_export_{datetime.now().strftime('%Y%m%d')}.csv")
    return response

@app.route("/export_closed_leads")
@login_required
@admin_required
def export_closed_leads():
    closed_leads = Lead.query.filter_by(status="Done").all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Customer Name", "Customer Number", "Department", "Sub Status",
                     "Main Area", "Second Area", "Sub Location", "Context Service", "Added By",
                     "Created Date", "Closed At", "Closed By"])
    for lead in closed_leads:
        writer.writerow([
            lead.id,
            lead.customer_name,
            lead.customer_number,
            lead.department,
            lead.sub_status or '',
            lead.main_area or '',
            lead.second_main_area or '',
            lead.sub_location or '',
            lead.context_service or '',
            lead.added_by or '',
            lead.created_at.strftime('%Y-%m-%d %H:%M') if lead.created_at else '',
            lead.closed_at.strftime('%Y-%m-%d %H:%M') if lead.closed_at else '',
            (lead.closed_by_user.username if lead.closed_by_user else '')
        ])
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename=closed_leads_{datetime.now().strftime('%Y%m%d')}.csv"
    response.headers["Content-type"] = "text/csv"
    return response

# ---------------------------
# Archive / Delete / Reopen
# ---------------------------
@app.route("/archive_all_closed", methods=["POST"])
@login_required
@admin_required
def archive_all_closed():
    closed_leads = Lead.query.filter_by(status="Done", archived=False).all()
    for lead in closed_leads:
        lead.archived = True
    db.session.commit()
    flash("📦 All closed leads archived.", "success")
    return redirect(url_for("closed_leads"))

@app.route("/reopen_lead/<int:lead_id>", methods=["POST"])
@login_required
def reopen_lead(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    if lead.status != "Done":
        flash("⚠️ Lead is not closed.", "warning")
        return redirect(url_for("closed_leads"))
    lead.status = "New Lead"
    lead.closed_at = None
    lead.closed_by = None
    lead.archived = False
    db.session.commit()
    flash("✅ Lead reopened.", "success")
    return redirect(url_for("closed_leads"))

@app.route("/delete_lead_permanent/<int:lead_id>", methods=["POST"])
@login_required
@admin_required
def delete_lead_permanent(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    if lead.attachment_filename:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], lead.attachment_filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    db.session.delete(lead)
    db.session.commit()
    flash("🗑️ Lead permanently deleted.", "success")
    return redirect(url_for("closed_leads"))

@app.route("/delete_lead/<int:lead_id>", methods=["POST"])
@login_required
@admin_required
def delete_lead(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    if lead.attachment_filename:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], lead.attachment_filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    db.session.delete(lead)
    db.session.commit()
    flash("🗑️ Lead deleted successfully.", "success")
    return redirect(url_for("view_leads"))

@app.route("/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    if current_user.role == "admin":
        if current_user.id == user_to_delete.id:
            flash("⚠️ Admins cannot delete their own account.", "warning")
            return redirect(url_for("users"))
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f"🗑️ User {user_to_delete.username} deleted successfully.", "success")
        return redirect(url_for("users"))
    else:
        if current_user.id == user_to_delete.id:
            db.session.delete(user_to_delete)
            db.session.commit()
            logout_user()
            flash("🗑️ Your account has been deleted.", "info")
            return redirect(url_for("login"))
        else:
            flash("❌ You are not allowed to delete this user.", "danger")
            return redirect(url_for("users"))

# ---------------------------
# Error Handlers
# ---------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500

@app.errorhandler(401)
def unauthorized(e):
    flash("🔒 Please log in to access this page.", "warning")
    return redirect(url_for('login'))

# ---------------------------
# Template Filters
# ---------------------------
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    return value.strftime(format) if value else ""

@app.template_filter('timedelta')
def timedelta_filter(value):
    if value is None:
        return ""
    diff = datetime.now() - value
    if diff.days > 0:
        return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    else:
        return "Just now"

# ---------------------------
# Database Initialization
# ---------------------------
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin_user = User(
            username='admin',
            password=generate_password_hash('admin123', method="pbkdf2:sha256"),
            role='admin',
            otp_secret=pyotp.random_base32(),
            otp_verified=False
        )
        db.session.add(admin_user)
        db.session.commit()
        print(f"✅ Admin user created in database. OTP secret: {admin_user.otp_secret}")

# ---------------------------
# App Entry Point
# ---------------------------
if __name__ == '__main__':
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
