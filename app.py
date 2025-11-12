import os
import csv
import io
import pyotp
from datetime import datetime, date, timedelta
from functools import wraps
from sqlalchemy import func, desc
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


from flask import (
    Flask, render_template, redirect, url_for, request, flash,
    send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
load_dotenv()  # ✅ This loads .env file automatically
import cloudinary
import cloudinary.uploader

required = ["CLOUDINARY_CLOUD_NAME", "CLOUDINARY_API_KEY", "CLOUDINARY_API_SECRET"]
missing = [k for k in required if not os.getenv(k)]
if missing:
    raise RuntimeError(f"Missing Cloudinary envs: {', '.join(missing)}")
cloudinary.config(
    cloud_name=os.environ["CLOUDINARY_CLOUD_NAME"],
    api_key=os.environ["CLOUDINARY_API_KEY"],
    api_secret=os.environ["CLOUDINARY_API_SECRET"],
)

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
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
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=3)  # auto logout after 3 hours

# ---------------------------
# Database Config
# ---------------------------
db_url = os.environ.get("DATABASE_URL", "sqlite:///crm.db").replace("postgres://", "postgresql://")

# ✅ Add SSL mode if using Postgres (for Render/Supabase), preserving existing query params
if db_url.startswith("postgresql") and "sslmode=" not in db_url:
    u = urlsplit(db_url)
    q = dict(parse_qsl(u.query))
    q["sslmode"] = "require"
    db_url = urlunsplit((u.scheme, u.netloc, u.path, urlencode(q), u.fragment))


app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ---------------------------
# File Upload Config
# ---------------------------
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}

# SQLAlchemy (Render-safe)
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_size": 5,
    "max_overflow": 2,
    "pool_recycle": 300,
}
db = SQLAlchemy(app)

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
    """Preserve formatting but keep DB-safe length (VARCHAR(20))."""
    return num.strip()[:20]

def processor_or_admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ["admin", "processor"]:
            flash("❌ Access denied.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped

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
    role = db.Column(db.String(20), default="user")  # admin / user / processor
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
        # ----------------------------
        # 1️⃣ Collect form data
        # ----------------------------
        customer_name = request.form["customer_name"].strip()
        customer_number = normalize_phone(request.form["customer_number"].strip())
        context_service = request.form["context_service"].strip()
        department = request.form["department"]
        main_area = request.form["main_area"]
        second_main_area = request.form.get("second_main_area", "")
        sub_location = request.form.get("sub_location", "")
        added_by = current_user.username  # enforce server-side; ignore spoofed form value

        # ----------------------------
        # 2️⃣ Create new lead instance
        # ----------------------------
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

        # ----------------------------
        # 3️⃣ Handle file upload (Cloudinary)
        # ----------------------------
        uploaded_file = request.files.get("attachment")

        if uploaded_file and uploaded_file.filename.strip() != "":
            if allowed_file(uploaded_file.filename):
                try:
                    # Reset pointer so file reads once only
                    uploaded_file.seek(0)

                    # Upload to Cloudinary
                    upload_result = cloudinary.uploader.upload(
                        uploaded_file,
                        folder="leads",        # Cloudinary folder name
                        resource_type="auto",  # handles images, PDFs, docs
                        unique_filename=True,  # avoid duplicate uploads
                        overwrite=False
                    )

                    # Save public URL in database
                    new_lead.attachment_filename = upload_result["secure_url"]
                    flash("✅ File uploaded to Cloudinary successfully!", "success")

                except Exception as e:
                    flash(f"❌ Cloud upload failed: {str(e)}", "danger")

            else:
                flash("⚠️ Invalid file type.", "warning")
        else:
            flash("ℹ️ No attachment uploaded.", "info")

        # ----------------------------
        # 4️⃣ Commit lead to database
        # ----------------------------
        db.session.add(new_lead)
        db.session.commit()
        flash("✅ Lead added successfully!", "success")

        # Redirect prevents re-POSTing on refresh
        return redirect(url_for("leads"))

    # ----------------------------
    # 5️⃣ Display existing leads
    # ----------------------------
    initial_statuses = ["New Lead", "Issue in Lead", "Updated"]

    if current_user.role in ("admin", "processor"):
       leads_list = (
           Lead.query.filter(Lead.status.in_(["New Lead", "Issue in Lead", "Updated"]))
           .order_by(Lead.created_at.desc())  # ✅ only sort by created_at
           .all()
        )
    else:
       leads_list = (
           Lead.query.filter_by(user_id=current_user.id)
           .filter(Lead.status.in_(["New Lead", "Issue in Lead", "Updated"]))
           .order_by(Lead.created_at.desc())  # ✅ only sort by created_at
           .all()
        )


    STATUSES_MY_LEADS = ["New Lead", "Issue in Lead", "Updated", "Done"]
    STATUSES_PIPELINE = ["Pending Outreach", "Texted / Call Done", "In Progress", "Done"]

    return render_template(
        "leads.html",
         leads=leads_list,
         departments=DEPARTMENTS,
         statuses_my_leads=STATUSES_MY_LEADS,
         statuses_pipeline=STATUSES_PIPELINE,
         triage_mode=(current_user.role in ["admin", "processor"]),
         can_add=(current_user.role != "processor")
)

# ---------------------------
# Leads (Admin + Processor)
# ---------------------------
@app.route("/view_leads")
@login_required
@processor_or_admin_required
def view_leads():
    status_filter = request.args.get('status', 'all')
    department_filter = request.args.get('department', 'all')

    query = Lead.query

    # Default visible statuses
    if status_filter != 'all':
        query = query.filter(Lead.status == status_filter)
    else:
        active_statuses = ["Pending Outreach", "Texted / Call Done", "In Progress"]
        query = query.filter(Lead.status.in_(active_statuses))

    if department_filter != 'all':
        query = query.filter(Lead.department == department_filter)

    leads_data = query.all()

    # ✅ Add this line
    STATUSES_PIPELINE = ["Pending Outreach", "Texted / Call Done", "In Progress", "Done"]

    return render_template(
        "view_leads.html",
        leads=leads_data,
        departments=DEPARTMENTS,
        statuses_pipeline=STATUSES_PIPELINE   # ✅ Pass it here
    )

@app.route("/edit_lead/<int:lead_id>", methods=["GET", "POST"])
@login_required
def edit_lead(lead_id):
    lead = Lead.query.get_or_404(lead_id)

    # Restrict editing: user can edit their own leads or admin can edit all
    if current_user.role != "admin" and lead.user_id != current_user.id:
        flash("⚠️ You can only edit your own leads.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        # Update editable fields
        lead.customer_name = request.form.get("customer_name", lead.customer_name).strip()
        lead.customer_number = request.form.get("customer_number", lead.customer_number).strip()
        lead.department = request.form.get("department", lead.department)
        lead.context_service = request.form.get("context_service", lead.context_service).strip()
        lead.main_area = request.form.get("main_area", lead.main_area).strip()
        lead.second_main_area = request.form.get("second_main_area", lead.second_main_area).strip()
        lead.sub_location = request.form.get("sub_location", lead.sub_location).strip()

        # Handle optional new attachment upload
        uploaded_file = request.files.get("attachment")
        if uploaded_file and uploaded_file.filename.strip() != "":
            from cloudinary.uploader import upload
            try:
                uploaded_file.seek(0)
                upload_result = upload(
                    uploaded_file,
                    folder="leads",
                    resource_type="auto",
                    unique_filename=True,
                    overwrite=False
                )
                lead.attachment_filename = upload_result["secure_url"]
                flash("✅ New attachment uploaded successfully!", "success")
            except Exception as e:
                flash(f"⚠️ Attachment upload failed: {str(e)}", "danger")

        # Always mark status as "Updated" after edit
        lead.status = "Updated"
        print(f"DEBUG: Lead {lead.id} updated by {current_user.username}, new status = {lead.status}")
        db.session.commit()

        flash("✅ Lead updated successfully and marked as 'Updated'.", "success")
        return redirect(url_for("leads"))

    return render_template("edit_lead.html", lead=lead, departments=DEPARTMENTS)

# ---------------------------
# Export All Active Leads (CSV)
# ---------------------------
@app.route("/export_leads")
@login_required
@admin_required
def export_leads():
    leads = Lead.query.filter(Lead.status.in_([
        "Pending Outreach", "Texted / Call Done", "In Progress"
    ])).all()

    if not leads:
        flash("⚠️ No active leads found to export.", "warning")
        return redirect(url_for("view_leads"))

    data = [
        {
            "ID": l.id,
            "Customer Name": l.customer_name,
            "Number": l.customer_number,
            "Department": l.department,
            "Service": l.context_service,
            "Main Area": l.main_area,
            "Second Area": l.second_main_area or "",
            "Sub Location": l.sub_location or "",
            "Added By": l.added_by,
            "Status": l.status,
            "Created At": l.created_at.strftime("%Y-%m-%d %H:%M") if l.created_at else ""
        }
        for l in leads
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=data[0].keys())
    writer.writeheader()
    writer.writerows(data)
    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="active_leads.csv"
    )


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

@app.route("/update_status/<int:lead_id>", methods=["POST", "GET"])
@login_required
def update_status(lead_id):
    lead = Lead.query.get_or_404(lead_id)

    # Only Admin or Processor can update lead status
    if current_user.role not in ["admin", "processor"]:
        flash("⚠️ You are not allowed to update this lead.", "danger")
        return redirect(request.referrer or url_for("dashboard"))

    # Accept both POST (forms) and GET (quick links)
    if request.method == "POST":
        new_status = (request.form.get("status") or "").strip()
        origin     = (request.form.get("origin") or "").strip()
    else:
        new_status = (request.args.get("status") or "").strip()
        origin     = (request.args.get("origin") or "").strip()

    # If origin not provided, guess from referrer (default to my_leads)
    if not origin:
       ref = (request.referrer or "").lower()
       origin = "all_leads" if "/view_leads" in ref else "my_leads"


    # ---------------------------
    # From "My Leads" Page
    # ---------------------------
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
            flash("✅ Lead triaged and moved to All Leads (Pending Outreach).", "success")
        else:
            lead.status = new_status
            lead.closed_at = None
            lead.closed_by = None
            lead.sub_status = None
            flash(f"✅ Lead status changed to '{new_status}'.", "success")

        db.session.commit()
        return redirect(url_for("leads"))

    # ---------------------------
    # From "All Leads" Page
    # ---------------------------
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
            flash("✅ Lead marked as Done and moved to Closed Leads.", "success")
        else:
            lead.status = new_status
            lead.closed_at = None
            lead.closed_by = None
            lead.sub_status = None
            flash(f"✅ Lead status updated to '{new_status}'.", "success")

        db.session.commit()
        return redirect(url_for("view_leads"))

    # ---------------------------
    # Fallback (if missing origin)
    # ---------------------------
    flash("⚠️ Missing origin info. Update from My Leads or All Leads page.", "warning")
    return redirect(request.referrer or url_for("dashboard"))


# ---------------------------
# Closed Leads
# ---------------------------
from flask import request, send_file
import io
import csv

@app.route("/bulk_update_status", methods=["POST"])
@login_required
@admin_required
def bulk_update_status():
    lead_ids = request.form.getlist("lead_ids")
    new_status = request.form.get("new_status")

    if not lead_ids:
        flash("⚠️ No leads selected.", "warning")
        return redirect(request.referrer)

    if not new_status:
        flash("⚠️ Please select a status.", "warning")
        return redirect(request.referrer)

    leads = Lead.query.filter(Lead.id.in_(lead_ids)).all()
    for lead in leads:
        lead.status = new_status
        if new_status == "Done":
            lead.status = "Pending Outreach"
            lead.closed_at = None
            lead.closed_by = None
            lead.sub_status = None
            flash("✅ Lead triaged and moved to All Leads (Pending Outreach).", "success")
        else:
            lead.status = new_status
            lead.closed_at = None
            lead.closed_by = None
            lead.sub_status = None
            flash(f"✅ Lead status changed to '{new_status}'.", "success")

    db.session.commit()
    flash(f"✅ {len(leads)} leads updated to '{new_status}' successfully!", "success")
    return redirect(request.referrer)


@app.route("/closed_leads")
@login_required
@admin_required
def closed_leads():
    from datetime import datetime, timedelta

    # Get date filters (optional)
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    # If no range selected → show last 7 days by default
    if not start_date or not end_date:
        end_date = datetime.now().strftime("%Y-%m-%d")
        start_date = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")

    # Build query for closed leads
    query = Lead.query.options(joinedload(Lead.closed_by_user)).filter_by(status="Done")

    start = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
    query = query.filter(Lead.closed_at >= start, Lead.closed_at < end)

    closed = query.all()
    total_leads = len(closed)

    return render_template(
        "closed_leads.html",
        closed_leads=closed,
        total_leads=total_leads,
        now=datetime.now(),
        start_date=start_date,
        end_date=end_date,
        departments=DEPARTMENTS
    )

# ---------------------------
# Dashboard
# ---------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    # Show correct dashboard per role
    now = datetime.now()

    # --- Admin Dashboard ---
    if current_user.role == 'admin':
        total_leads = Lead.query.count()
        my_leads = Lead.query.filter_by(added_by=current_user.username).count()
        new_today = Lead.query.filter(db.func.date(Lead.created_at) == date.today()).count()

        # Chart data
        dept_labels = [dept for dept in DEPARTMENTS]
        dept_counts = [Lead.query.filter_by(department=dept).count() for dept in DEPARTMENTS]

        return render_template(
            "dashboard.html",
            now=now,
            is_admin=True,
            total_leads=total_leads,
            my_leads=my_leads,
            new_today=new_today,
            dept_labels=dept_labels,
            dept_counts=dept_counts
        )

    # --- Processor Dashboard ---
    elif current_user.role == 'processor':
        leads = Lead.query.filter(Lead.status.in_(['Pending Outreach', 'Texted / Call Done', 'In Progress'])).all()
        total_new = len(leads)
        my_leads = Lead.query.filter_by(assigned_to=current_user.id).count()
        new_today = Lead.query.filter(db.func.date(Lead.created_at) == date.today()).count()

        return render_template(
            "dashboard_processor.html",
            now=now,
            leads=leads,
            total_new=total_new,
            my_leads=my_leads,
            new_today=new_today
        )

    # --- Standard User Dashboard ---
    else:
        my_leads = Lead.query.filter_by(added_by=current_user.username).all()
        issue_leads_list = Lead.query.filter_by(status='Issue in Lead', added_by=current_user.username).all()
        issue_leads = len(issue_leads_list)
        today_leads = Lead.query.filter(
            db.func.date(Lead.created_at) == date.today(),
            Lead.added_by == current_user.username
        ).count()
        resolved_today = Lead.query.filter(
            Lead.status == 'Done',
            db.func.date(Lead.closed_at) == date.today(),
            Lead.added_by == current_user.username
        ).count()

        return render_template(
            "dashboard.html",
            now=now,
            issue_leads=issue_leads,
            today_leads=today_leads,
            resolved_today=resolved_today,
            issue_leads_list=issue_leads_list
        )
    
# ---------------------------
# Analytics (Admin - One-Go)
# ---------------------------
@app.route("/analytics")
@login_required
@admin_required
def analytics():
    """
    Admin analytics with filters:
      - start_date / end_date (YYYY-MM-DD)
      - granularity: day | week | month
      - department: specific or 'all'
    """
    now = datetime.now()
    today = date.today()

    # ---- Read filters from query string
    start_date_str = request.args.get("start_date")
    end_date_str   = request.args.get("end_date")
    granularity    = (request.args.get("granularity") or "month").lower()
    department     = request.args.get("department", "all")

    # Defaults: current month
    if not start_date_str or not end_date_str:
        month_start = today.replace(day=1)
        next_month  = month_start + relativedelta(months=1)
        start_date  = month_start
        end_date    = next_month - timedelta(days=1)
        start_date_str = start_date.strftime("%Y-%m-%d")
        end_date_str   = end_date.strftime("%Y-%m-%d")
    else:
        start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
        end_date   = datetime.strptime(end_date_str, "%Y-%m-%d").date()

    # Window bounds (inclusive start, exclusive end)
    start_inclusive = datetime.combine(start_date, datetime.min.time())
    end_exclusive   = datetime.combine(end_date + timedelta(days=1), datetime.min.time())

    # ---- Base filtered query (by date and department)
    base = Lead.query.filter(Lead.created_at >= start_inclusive,
                             Lead.created_at < end_exclusive)
    if department != "all":
        base = base.filter(Lead.department == department)

    # Project to a subquery so we can reference subq.c.* safely (no cartesian products)
    subq = base.with_entities(
        Lead.id.label('id'),
        Lead.created_at.label('created_at'),
        Lead.department.label('department'),
        Lead.added_by.label('added_by'),
        Lead.status.label('status'),
        Lead.customer_number.label('customer_number')
    ).subquery()

    # ---- Robust dialect detection (Flask-SQLAlchemy 3.x safe)
    bind = db.session.get_bind()
    engine = bind or db.engine
    dialect = engine.dialect.name  # 'sqlite' or 'postgresql'

    if granularity not in {"day", "week", "month"}:
        granularity = "month"

    # ---- Time-series bucketing
    if dialect == "postgresql":
        if granularity == "day":
            bucket = func.date_trunc('day', subq.c.created_at)
        elif granularity == "week":
            bucket = func.date_trunc('week', subq.c.created_at)
        else:
            bucket = func.date_trunc('month', subq.c.created_at)

        bucket_q = (
            db.session.query(bucket.label("bucket"), func.count(subq.c.id))
            .select_from(subq)
            .group_by(bucket)
            .order_by(bucket.asc())
        )
        timeseries = bucket_q.all()
        ts_labels, ts_values = [], []
        for b, c in timeseries:
            if granularity == "day":
                ts_labels.append(b.date().isoformat())
            else:
                # week/month → label with bucket start date
                ts_labels.append(b.strftime("%Y-%m-%d"))
            ts_values.append(c)
    else:
        # SQLite
        if granularity == "day":
            fmt = "%Y-%m-%d"
        elif granularity == "week":
            fmt = "%Y-W%W"  # year-week
        else:
            fmt = "%Y-%m"

        bucket = func.strftime(fmt, subq.c.created_at)
        bucket_q = (
            db.session.query(bucket.label("bucket"), func.count(subq.c.id))
            .select_from(subq)
            .group_by("bucket")
            .order_by("bucket")
        )
        timeseries = bucket_q.all()
        ts_labels = [b for (b, _) in timeseries]
        ts_values = [c for (_, c) in timeseries]

    # ---- Aggregations
    dept_rows = (
        db.session.query(subq.c.department, func.count(subq.c.id))
        .select_from(subq)
        .group_by(subq.c.department)
        .order_by(desc(func.count(subq.c.id)))
        .all()
    )
    user_rows = (
        db.session.query(subq.c.added_by, func.count(subq.c.id))
        .select_from(subq)
        .group_by(subq.c.added_by)
        .order_by(desc(func.count(subq.c.id)))
        .all()
    )
    dept_user_rows = (
        db.session.query(subq.c.department, subq.c.added_by, func.count(subq.c.id))
        .select_from(subq)
        .group_by(subq.c.department, subq.c.added_by)
        .order_by(subq.c.department.asc(), desc(func.count(subq.c.id)))
        .all()
    )
    status_rows = (
        db.session.query(subq.c.status, func.count(subq.c.id))
        .select_from(subq)
        .group_by(subq.c.status)
        .order_by(desc(func.count(subq.c.id)))
        .all()
    )

    # Heatmap
    if dialect == "postgresql":
        wd_col = func.extract('dow', subq.c.created_at)  # 0=Sun
        hr_col = func.extract('hour', subq.c.created_at)
    else:
        wd_col = func.strftime('%w', subq.c.created_at)  # 0=Sun
        hr_col = func.strftime('%H', subq.c.created_at)
    heat_rows = (
        db.session.query(wd_col.label('wd'), hr_col.label('hr'), func.count(subq.c.id))
        .select_from(subq)
        .group_by('wd', 'hr')
        .all()
    )

    # Duplicates
    dupe_rows = (
        db.session.query(subq.c.customer_number, func.count(subq.c.id).label('c'))
        .select_from(subq)
        .group_by(subq.c.customer_number)
        .having(func.count(subq.c.id) > 1)
        .order_by(desc('c'))
        .limit(50)
        .all()
    )

    # Pivot: user × department
    user_dept_rows = (
        db.session.query(subq.c.added_by, subq.c.department, func.count(subq.c.id))
        .select_from(subq)
        .group_by(subq.c.added_by, subq.c.department)
        .order_by(subq.c.added_by.asc(), subq.c.department.asc())
        .all()
    )

    # ---- Simple KPIs
    total_in_range = sum(count for _, count in dept_rows)
    today_leads = Lead.query.filter(func.date(Lead.created_at) == today).count()

    dept_labels = [d for (d, _) in dept_rows]
    dept_counts = [c for (_, c) in dept_rows]
    user_labels = [u or "Unknown" for (u, _) in user_rows]
    user_counts = [c for (_, c) in user_rows]

    drilldown = {}
    for d, u, c in dept_user_rows:
        drilldown.setdefault(d, []).append({"user": u or "Unknown", "count": c})

    funnel_labels = [s or "Unknown" for (s, _) in status_rows]
    funnel_counts = [c for (_, c) in status_rows]

    # Heatmap matrix
    heatmap = [[0]*24 for _ in range(7)]
    for wd, hr, cnt in heat_rows:
        wd_i = int(wd)
        hr_i = int(hr)
        if 0 <= wd_i <= 6 and 0 <= hr_i <= 23:
            heatmap[wd_i][hr_i] = int(cnt)
    weekday_labels = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat']
    hour_labels = [f'{h:02d}:00' for h in range(24)]

    # Previous period delta & avg/day
    days_in_window = (end_date - start_date).days + 1
    prev_start = start_date - timedelta(days=days_in_window)
    prev_end   = start_date - timedelta(days=1)
    prev_inclusive = datetime.combine(prev_start, datetime.min.time())
    prev_exclusive = datetime.combine(prev_end + timedelta(days=1), datetime.min.time())

    prev_base = Lead.query.filter(Lead.created_at >= prev_inclusive,
                                  Lead.created_at < prev_exclusive)
    if department != "all":
        prev_base = prev_base.filter(Lead.department == department)
    prev_total = prev_base.count()

    def pct_change(curr, prev):
        if prev == 0:
            return None
        return round((curr - prev) * 100.0 / prev, 1)

    total_delta_pct = pct_change(total_in_range, prev_total)
    avg_per_day = round(total_in_range / max(days_in_window, 1), 2)

    # Avg close time (hours) for leads closed in range
    closed_q = Lead.query.filter(
        Lead.closed_at.isnot(None),
        Lead.closed_at >= start_inclusive,
        Lead.closed_at < end_exclusive
    )
    if department != "all":
        closed_q = closed_q.filter(Lead.department == department)
    closed_rows = closed_q.with_entities(Lead.created_at, Lead.closed_at).all()
    cycle_hours = []
    for c_at, cl_at in closed_rows:
        if c_at and cl_at and cl_at > c_at:
            cycle_hours.append((cl_at - c_at).total_seconds() / 3600.0)
    avg_cycle_hours = round(sum(cycle_hours)/len(cycle_hours), 1) if cycle_hours else None

    # Confirmed leads by department (for your sidebar block)
    confirmed_dept_stats = (
        db.session.query(Lead.department, func.count(Lead.id))
        .filter(Lead.status == "Done")
        .group_by(Lead.department)
        .all()
    )

    # Quick preset strings for template (avoid using timedelta in Jinja)
    today_str        = now.strftime('%Y-%m-%d')
    last7_start_str  = (now - timedelta(days=6)).strftime('%Y-%m-%d')
    month_start_str  = now.replace(day=1).strftime('%Y-%m-%d')

    return render_template(
        "analytics.html",
        # filters + selections
        start_date=start_date_str,
        end_date=end_date_str,
        granularity=granularity,
        selected_department=department,
        departments=DEPARTMENTS,

        # headline stats
        today_leads=today_leads,
        total_in_range=total_in_range,
        total_delta_pct=total_delta_pct,
        avg_per_day=avg_per_day,
        avg_cycle_hours=avg_cycle_hours,
        now=now,

        # charts
        ts_labels=ts_labels, ts_values=ts_values,
        dept_labels=dept_labels, dept_counts=dept_counts,
        user_labels=user_labels, user_counts=user_counts,

        # drilldown
        drilldown=drilldown,

        # extras
        funnel_labels=funnel_labels, funnel_counts=funnel_counts,
        heatmap=heatmap, weekday_labels=weekday_labels, hour_labels=hour_labels,
        dupe_rows=dupe_rows,
        user_dept={ (u or "Unknown"): {} for u, _, _ in user_dept_rows },  # init; will fill below
        confirmed_dept_stats=confirmed_dept_stats,

        # quick presets
        today_str=today_str,
        last7_start_str=last7_start_str,
        month_start_str=month_start_str
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
@app.route("/export_closed_leads")
@login_required
@admin_required
def export_closed_leads():
    from datetime import datetime
    import io, csv, pandas as pd
    from reportlab.pdfgen import canvas

    # Get parameters
    file_type = request.args.get("type", "csv")
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    # If missing → default last 7 days
    if not start_date or not end_date:
        end_date = datetime.now().strftime("%Y-%m-%d")
        start_date = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")

    start = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)

    # Query leads that were closed in that period
    query = Lead.query.options(joinedload(Lead.closed_by_user)).filter_by(status="Done", archived=False)
    query = query.filter(Lead.closed_at.between(start, end))
    leads = query.all()

    # 🧩 Build dataset
    data = [
        {
            "ID": lead.id,
            "Customer Name": lead.customer_name,
            "Number": lead.customer_number,
            "Department": lead.department,
            "Service": lead.context_service,
            "Main Area": lead.main_area,
            "Second Area": lead.second_main_area or "",
            "Sub Location": lead.sub_location or "",
            "Added By": lead.added_by,
            "Closed At": lead.closed_at.strftime("%Y-%m-%d %H:%M") if lead.closed_at else "",
            "Closed By": getattr(lead.closed_by_user, "username", "Unknown"),
            "Attachment": lead.attachment_filename or "-",
            "Status": lead.status,
        }
        for lead in leads
    ]

    # 🛑 If nothing found
    if not data:
        flash("⚠️ No closed leads found in selected range.", "warning")
        return redirect(url_for("closed_leads", start_date=start_date, end_date=end_date))

    # ---------------- CSV Export ----------------
    if file_type == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode()),
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"closed_leads_{start_date}_to_{end_date}.csv"
        )

    # ---------------- Excel Export ----------------
    elif file_type == "xlsx":
        df = pd.DataFrame(data)
        output = io.BytesIO()
        df.to_excel(output, index=False)
        output.seek(0)
        return send_file(
            output,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name=f"closed_leads_{start_date}_to_{end_date}.xlsx"
        )

    # ---------------- PDF Export ----------------
    elif file_type == "pdf":
        output = io.BytesIO()
        p = canvas.Canvas(output)
        y = 800
        for row in data:
            line = (
                f"{row['ID']} | {row['Customer Name']} | {row['Number']} | "
                f"{row['Department']} | {row['Service']} | {row['Main Area']} | "
                f"{row['Closed By']} | {row['Closed At']}"
            )
            p.drawString(30, y, line[:180])  # limit text width
            y -= 20
            if y < 50:
                p.showPage()
                y = 800
        p.save()
        output.seek(0)
        return send_file(
            output,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"closed_leads_{start_date}_to_{end_date}.pdf"
        )

    # ---------------- Invalid format ----------------
    else:
        flash("⚠️ Invalid export format selected.", "danger")
        return redirect(url_for("closed_leads", start_date=start_date, end_date=end_date))
    
# ---------------------------
# Archive All Closed Leads
# ---------------------------
@app.route("/archive_all_closed", methods=["POST"])
@login_required
@admin_required
def archive_all_closed():
    closed_leads = Lead.query.filter_by(status="Done", archived=False).all()
    for lead in closed_leads:
        lead.archived = False
    db.session.commit()
    flash("📦 All closed leads have been archived successfully!", "success")
    return redirect(url_for("closed_leads"))

@app.route("/reopen_lead/<int:lead_id>", methods=["POST"])
@login_required
@admin_required
def reopen_lead(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    lead.status = "In Progress"
    lead.closed_at = None
    lead.closed_by = None
    db.session.commit()
    flash("✅ Lead reopened successfully.", "success")
    return redirect(url_for("closed_leads"))
    

@app.route("/delete_lead_permanent/<int:lead_id>", methods=["POST"])
@login_required
@admin_required
def delete_lead_permanent(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    if lead.attachment_filename and not lead.attachment_filename.startswith("http"):
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
    if lead.attachment_filename and not lead.attachment_filename.startswith("http"):
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
    # Prevent deleting users with linked leads (avoids FK errors)
    linked = Lead.query.filter(
        (Lead.user_id == user_to_delete.id) |
        (Lead.assigned_to == user_to_delete.id) |
        (Lead.closed_by == user_to_delete.id)
    ).limit(1).count()
    if linked:
        flash("⚠️ Cannot delete user with linked leads. Reassign or archive their leads first.", "warning")
        return redirect(url_for("users"))
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
# Safe DB init + Nhost keepalive
# ---------------------------
import threading, time, requests

# from env (add these to your Render/Nhost env vars)
NHOST_GRAPHQL = os.getenv("NHOST_GRAPHQL")            # e.g. https://<sub>.nhost.run/v1/graphql
NHOST_ADMIN_SECRET = os.getenv("NHOST_ADMIN_SECRET")  # your admin secret

def _ping_nhost():
    if not (NHOST_GRAPHQL and NHOST_ADMIN_SECRET):
        return
    try:
        requests.post(
            NHOST_GRAPHQL,
            headers={
                "Content-Type": "application/json",
                "x-hasura-admin-secret": NHOST_ADMIN_SECRET,
            },
            json={"query": "query { __typename }"},
            timeout=5,
        )
    except Exception:
        pass

def start_nhost_keepalive(interval_sec: int = 600):
    """Ping Nhost every `interval_sec` seconds (daemon thread)."""
    if not (NHOST_GRAPHQL and NHOST_ADMIN_SECRET):
        print("ℹ️ Keep-alive disabled: NHOST envs missing.")
        return

    def loop():
        _ping_nhost()  # immediate
        while True:
            time.sleep(interval_sec)
            _ping_nhost()

    t = threading.Thread(target=loop, name="nhost-keepalive", daemon=True)
    t.start()

def init_db_with_retry(max_tries=5, delay=2):
    """Create tables / seed admin with short retries so boot doesn’t crash."""
    from sqlalchemy.exc import OperationalError
    tries = 0
    while tries < max_tries:
        try:
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
                    print(f"✅ Admin user created. OTP secret: {admin_user.otp_secret}")
            print("✅ DB init OK")
            return
        except OperationalError as e:
            tries += 1
            print(f"⏳ DB init attempt {tries}/{max_tries} failed: {e}")
            time.sleep(delay)
    print("⚠️ DB init skipped after retries. Will try again on first request.")

# ---- Run startup tasks once per worker (Flask 3.x safe) ----
from threading import Lock

_bootstrap_lock = Lock()
_bootstrapped = False

@app.before_request
def _bootstrap_once_per_worker():
    global _bootstrapped
    if not _bootstrapped:
        print("🔥 bootstrap running in this worker")
        with _bootstrap_lock:
            if not _bootstrapped:
                init_db_with_retry()
                start_nhost_keepalive()
                _bootstrapped = True


# ---------------------------
# App Entry Point
# ---------------------------
if __name__ == '__main__':
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))  # <-- this line is key
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
