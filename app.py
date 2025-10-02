import os
import csv
import io
from datetime import datetime, date, timedelta
from werkzeug.utils import secure_filename
from flask import (
    Flask, render_template, redirect, url_for, request, flash,
    abort, send_from_directory, Response, make_response
)
from flask_sqlalchemy import SQLAlchemy
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

# ---------------------------
# App Config
# ---------------------------
app = Flask(__name__)

# Use environment variable for secret key with fallback
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")

# Use PostgreSQL in production, SQLite locally
if os.environ.get("DATABASE_URL"):
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL").replace("postgres://", "postgresql://")
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///crm.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# File upload configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"

# Create uploads folder if it doesn't exist
os.makedirs('uploads', exist_ok=True)

# Your department names
DEPARTMENTS = [
    "Facebook lead",
    "ND Inbound",
    "ND Tech & Old Customer Reference",
    "ND General"
]

# ---------------------------
# Models
# ---------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="user")  # admin / user
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), default="New Lead")
    sub_status = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Main user who created the lead
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship(
        "User",
        foreign_keys=[user_id],
        backref=db.backref("leads", lazy=True)
    )

    # If you have another FK like "assigned_to"
    assigned_to = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    assignee = db.relationship(
        "User",
        foreign_keys=[assigned_to],
        backref=db.backref("assigned_leads", lazy=True)
    )


    # New fields for your requirements
    customer_name = db.Column(db.String(150), nullable=False)
    customer_number = db.Column(db.String(20), nullable=False)
    context_service = db.Column(db.Text, nullable=False)
    main_area = db.Column(db.String(100), nullable=False)
    second_main_area = db.Column(db.String(100))
    sub_location = db.Column(db.String(100))
    attachment_filename = db.Column(db.String(200))
    added_by = db.Column(db.String(100), nullable=False)

    # Closed/archiving fields
    closed_at = db.Column(db.DateTime, nullable=True)
    closed_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    closed_by_user = db.relationship("User", foreign_keys=[closed_by], backref="closed_leads")
    archived = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# ---------------------------
# Routes
# ---------------------------
@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    else:
        return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        role = request.form.get("role", "user")

        if User.query.filter_by(username=username).first():
            flash("⚠️ Username already exists.", "warning")
            return redirect(url_for("register"))

        new_user = User(
            username=username,
            password=generate_password_hash(password, method="pbkdf2:sha256"),
            role=role,
        )
        db.session.add(new_user)
        db.session.commit()
        flash("✅ Registration successful. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash("❌ Invalid username or password.", "danger")
            return redirect(url_for("login"))

        login_user(user)
        flash(f"👋 Welcome back, {user.username}!", "success")
        next_page = request.args.get('next')
        return redirect(next_page) if next_page else redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("👋 You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/users")
@login_required
def users():
    if current_user.role != "admin":
        flash("❌ Access denied. Admins only.", "danger")
        return redirect(url_for("dashboard"))

    users_list = User.query.all()
    return render_template("users.html", users=users_list, title="Users Management")

# Add Lead route
@app.route("/add_lead")
@login_required
def add_lead():
    return render_template("add_lead.html", departments=DEPARTMENTS)

@app.route("/leads", methods=["GET", "POST"])
@login_required
def leads():
    if request.method == "POST":
        customer_name = request.form["customer_name"].strip()
        customer_number = request.form["customer_number"].strip()
        context_service = request.form["context_service"].strip()
        department = request.form["department"]
        main_area = request.form["main_area"]
        second_main_area = request.form.get("second_main_area", "")
        sub_location = request.form.get("sub_location", "")
        added_by = request.form["added_by"].strip()

        # Check if lead with this customer number already exists
        if Lead.query.filter_by(customer_number=customer_number).first():
            flash("⚠️ Lead with this customer number already exists.", "warning")
            return redirect(url_for("leads"))

        # Generate a unique email from customer number
        email = f"customer_{customer_number.replace(' ', '_')}@example.com"

        new_lead = Lead(
            name=customer_name,
            email=email,
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

        # Handle file attachment
        if 'attachment' in request.files:
            file = request.files['attachment']
            if file and file.filename != '':
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"{timestamp}_{filename}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    new_lead.attachment_filename = filename
                    flash("✅ File uploaded successfully!", "success")
                else:
                    flash("⚠️ Invalid file type. Allowed: images, PDF, DOC", "warning")

        db.session.add(new_lead)
        db.session.commit()
        flash("✅ Lead added successfully!", "success")
        return redirect(url_for("leads"))

    # Filter: Show only initial phase leads (New Lead, Issue in Lead, Updated)
    initial_statuses = ["New Lead", "Issue in Lead", "Updated"]
    if current_user.role == "admin":
        leads = Lead.query.filter(Lead.status.in_(initial_statuses)).all()
    else:
        leads = Lead.query.filter_by(user_id=current_user.id).filter(Lead.status.in_(initial_statuses)).all()

    return render_template("leads.html", leads=leads, departments=DEPARTMENTS)

@app.route("/view_leads")
@login_required
def view_leads():
    if current_user.role != "admin":
        flash("❌ Only admins can view this page.", "danger")
        return redirect(url_for("dashboard"))

    # Get filter parameters
    status_filter = request.args.get('status', 'all')
    department_filter = request.args.get('department', 'all')

    # Base query
    query = Lead.query

    # Apply filters
    if status_filter != 'all':
        query = query.filter(Lead.status == status_filter)
    else:
        # Default: Show second phase leads INCLUDING "Done" status
        second_phase_statuses = ["Pending Outreach", "Texted / Call Done", "In Progress", "Done"]
        query = query.filter(Lead.status.in_(second_phase_statuses))

    if department_filter != 'all':
        query = query.filter(Lead.department == department_filter)

    leads = query.all()

    return render_template("view_leads.html", leads=leads, departments=DEPARTMENTS)

@app.route("/edit_lead/<int:lead_id>", methods=["GET", "POST"])
@login_required
def edit_lead(lead_id):
    lead = Lead.query.get_or_404(lead_id)

    # Check if user is allowed to edit this lead
    # Users can only edit their own leads (regardless of status)
    if current_user.role != "admin" and lead.user_id != current_user.id:
        flash("⚠️ You can only edit your own leads.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        # Store old values for comparison
        old_customer_name = lead.customer_name
        old_customer_number = lead.customer_number
        old_context_service = lead.context_service
        old_department = lead.department
        old_main_area = lead.main_area
        old_second_main_area = lead.second_main_area
        old_sub_location = lead.sub_location

        # Update lead fields
        lead.customer_name = request.form.get("customer_name", lead.customer_name)
        lead.customer_number = request.form.get("customer_number", lead.customer_number)
        lead.context_service = request.form.get("context_service", lead.context_service)
        lead.department = request.form.get("department", lead.department)
        lead.main_area = request.form.get("main_area", lead.main_area)
        lead.second_main_area = request.form.get("second_main_area", lead.second_main_area)
        lead.sub_location = request.form.get("sub_location", lead.sub_location)

        # Check if any changes were made
        changes_made = (
            lead.customer_name != old_customer_name or
            lead.customer_number != old_customer_number or
            lead.context_service != old_context_service or
            lead.department != old_department or
            lead.main_area != old_main_area or
            lead.second_main_area != old_second_main_area or
            lead.sub_location != old_sub_location
        )

        # Auto-update status to "Updated" if changes were made
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

    # Check if user is allowed to resolve this lead
    # Users can only resolve their own issue leads
    if current_user.role != "admin" and lead.user_id != current_user.id:
        flash("⚠️ You can only resolve your own issue leads.", "danger")
        return redirect(url_for("dashboard"))

    # Update status to "Updated" when resolved
    lead.status = "Updated"
    db.session.commit()

    flash("✅ Lead resolved successfully! Status changed to 'Updated'.", "success")
    return redirect(url_for("dashboard"))

@app.route("/update_status/<int:lead_id>", methods=["POST"])
@login_required
def update_status(lead_id):
    lead = Lead.query.get_or_404(lead_id)

    if current_user.role == "admin":
        new_status = request.form["status"]

        # Validate allowed statuses
        allowed_statuses = ["New Lead", "Issue in Lead", "Updated", "Pending Outreach", "Texted / Call Done", "In Progress", "Done"]
        if new_status not in allowed_statuses:
            flash("⚠️ Invalid status for this lead.", "warning")
            return redirect(request.referrer or url_for("view_leads"))

        old_status = lead.status
        
        # Update lead status
        lead.status = new_status
        
        # When admin marks Done -> set closed info
        if new_status == "Done":
            lead.sub_status = request.form.get("sub_status")
            lead.closed_at = datetime.utcnow()
            lead.closed_by = current_user.id
            flash("✅ Lead marked as Done.", "success")
        else:
            # reset close metadata if moving away from Done
            if old_status == "Done":
                lead.closed_at = None
                lead.closed_by = None
            lead.sub_status = request.form.get("sub_status") if new_status == "Updated" else None
            flash("✅ Lead status updated.", "success")

        db.session.commit()
    else:
        flash("⚠️ You are not allowed to update this lead.", "danger")

    # Redirect based on current status (not new_status, as it's already updated)
    if lead.status in ["New Lead", "Issue in Lead", "Updated"]:
        return redirect(url_for("leads"))
    elif lead.status in ["Pending Outreach", "Texted / Call Done", "In Progress", "Done"]:
        return redirect(url_for("view_leads"))
    else:
        return redirect(url_for("closed_leads"))

from collections import Counter
from datetime import datetime

@app.route("/closed_leads")
@login_required
def closed_leads():
    # Filter by "Done" status instead of "Closed"
    closed = Lead.query.filter_by(status="Done").all()
    total_leads = len(closed)

    # --- Top Performers ---
    # Count closed leads by user
    user_counts = Counter(lead.closed_by_user.username if lead.closed_by_user else "Unknown" for lead in closed)
    top_labels = list(user_counts.keys())
    top_data = list(user_counts.values())

    # --- Closure Trends ---
    # Count closed leads per day
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


@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "admin":
        # Admin dashboard
        total_leads = Lead.query.count()
        my_leads = Lead.query.filter_by(user_id=current_user.id).count()

        # Count leads created today
        today = date.today()
        new_today = Lead.query.filter(db.func.date(Lead.created_at) == today).count()

        # Leads per department
        dept_stats = db.session.query(Lead.department, db.func.count(Lead.id))\
            .group_by(Lead.department)\
            .all()

        dept_labels = [d[0] for d in dept_stats] if dept_stats else []
        dept_counts = [d[1] for d in dept_stats] if dept_stats else []

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
        # USER DASHBOARD - CORRECTED VERSION
        today = date.today()

        # Today's leads count (only leads created today for this user)
        today_leads = Lead.query.filter(
            Lead.user_id == current_user.id,
            db.func.date(Lead.created_at) == today
        ).count()

        # Issue leads count (all time issue leads for this user)
        issue_leads = Lead.query.filter(
            Lead.user_id == current_user.id,
            Lead.status == 'Issue in Lead'
        ).count()

        # Resolved today count (leads marked as done today)
        resolved_today = Lead.query.filter(
            Lead.user_id == current_user.id,
            db.func.date(Lead.created_at) == today,
            Lead.status.in_(['Done', 'Texted / Call Done', 'Connected', 'Completed'])
        ).count()

        # Today's leads list (only leads created today)
        today_leads_list = Lead.query.filter(
            Lead.user_id == current_user.id,
            db.func.date(Lead.created_at) == today
        ).order_by(Lead.created_at.desc()).all()

        # Issue leads list (all issue leads for this user)
        issue_leads_list = Lead.query.filter(
            Lead.user_id == current_user.id,
            Lead.status == 'Issue in Lead'
        ).order_by(Lead.created_at.desc()).all()

        # Recent leads for user (last 5 leads)
        recent_leads = Lead.query.filter_by(user_id=current_user.id)\
            .order_by(Lead.created_at.desc())\
            .limit(5)\
            .all()

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

@app.route("/analytics")
@login_required
def analytics():
    if current_user.role != "admin":
        flash("❌ Only admins can view analytics.", "danger")
        return redirect(url_for("dashboard"))

    # Real data calculations
    today = date.today()

    # Today's leads
    today_leads = Lead.query.filter(db.func.date(Lead.created_at) == today).count()

    # Weekly stats (real data for last 4 weeks)
    week_leads = []
    week_labels = []
    for i in range(4):
        week_start = today - timedelta(weeks=(3-i), days=today.weekday())
        week_end = week_start + timedelta(days=6)
        week_count = Lead.query.filter(
            Lead.created_at >= week_start,
            Lead.created_at <= week_end
        ).count()
        week_leads.append(week_count)
        week_labels.append(week_start.strftime('%b %d'))

    # Monthly stats (real data for last 6 months)
    month_leads = []
    month_labels = []
    for i in range(6):
        month_date = today - relativedelta(months=(5-i))
        month_count = Lead.query.filter(
            db.func.strftime('%Y-%m', Lead.created_at) == month_date.strftime('%Y-%m')
        ).count()
        month_leads.append(month_count)
        month_labels.append(month_date.strftime('%b %Y'))

    # Department stats (real data)
    all_dept_stats = db.session.query(Lead.department, db.func.count(Lead.id))\
        .group_by(Lead.department)\
        .all()

    confirmed_dept_stats = db.session.query(Lead.department, db.func.count(Lead.id))\
        .filter_by(status="Done")\
        .group_by(Lead.department)\
        .all()

    # Status distribution
    status_stats = db.session.query(Lead.status, db.func.count(Lead.id))\
        .group_by(Lead.status)\
        .all()

    return render_template(
        "analytics.html",
        today_leads=today_leads,
        week_leads=week_leads,
        week_labels=week_labels,
        month_leads=month_leads,
        month_labels=month_labels,
        dept_stats=all_dept_stats,
        confirmed_dept_stats=confirmed_dept_stats,
        status_stats=status_stats,
        now=datetime.now()
    )

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Export routes for CSV
@app.route("/export_leads")
@login_required
def export_leads():
    if current_user.role != "admin":
        flash("❌ Only admins can export leads.", "danger")
        return redirect(url_for("dashboard"))

    leads = Lead.query.all()

    def generate():
        data = []
        data.append(['ID', 'Customer Name', 'Customer Number', 'Email', 'Department',
                     'Status', 'Sub Status', 'Main Area', 'Second Area', 'Sub Location',
                     'Context Service', 'Added By', 'Created Date'])

        for lead in leads:
            data.append([
                lead.id,
                lead.customer_name,
                lead.customer_number,
                lead.email,
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
def export_closed_leads():
    # Only admins can export
    if current_user.role != "admin":
        flash("❌ Only admins can export reports.", "danger")
        return redirect(url_for("closed_leads"))

    closed_leads = Lead.query.filter_by(status="Done").all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Customer Name", "Customer Number", "Email", "Department", "Sub Status",
                     "Main Area", "Second Area", "Sub Location", "Context Service", "Added By",
                     "Created Date", "Closed At", "Closed By"])
    for lead in closed_leads:
        writer.writerow([
            lead.id,
            lead.customer_name,
            lead.customer_number,
            lead.email,
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

@app.route("/archive_all_closed", methods=["POST"])
@login_required
def archive_all_closed():
    if current_user.role != "admin":
        flash("❌ Only admins can archive leads.", "danger")
        return redirect(url_for("closed_leads"))

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

    # reopen: set status back to a sensible one (New Lead). Adjust as needed.
    lead.status = "New Lead"
    lead.closed_at = None
    lead.closed_by = None
    lead.archived = False
    db.session.commit()
    flash("✅ Lead reopened.", "success")
    return redirect(url_for("closed_leads"))

@app.route("/view_notes/<int:lead_id>")
@login_required
def view_notes(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    # You don't have a Notes model — render a template where you can add notes UI later.
    return render_template("notes.html", lead=lead)

@app.route("/delete_lead_permanent/<int:lead_id>", methods=["POST"])
@login_required
def delete_lead_permanent(lead_id):
    if current_user.role != "admin":
        flash("❌ Only admins can permanently delete leads.", "danger")
        return redirect(url_for("closed_leads"))

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
def delete_lead(lead_id):
    if current_user.role != "admin":
        flash("❌ Only admins can delete leads.", "danger")
        return redirect(url_for("view_leads"))

    lead = Lead.query.get_or_404(lead_id)

    # Delete attached file if exists
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
    if not current_user.is_authenticated:
        flash("🔒 Please log in.", "warning")
        return redirect(url_for("login"))

    user_to_delete = User.query.get_or_404(user_id)

    if current_user.role == "admin":
        if current_user.id == user_to_delete.id:
            flash("⚠️ Admins cannot delete their own account.", "warning")
            return redirect(url_for("users"))
        else:
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
    if value is None:
        return ""
    return value.strftime(format)

@app.template_filter('timedelta')
def timedelta_filter(value):
    if value is None:
        return ""
    now = datetime.now()
    diff = now - value
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
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin_user = User(
            username='admin',
            password=generate_password_hash('admin123', method="pbkdf2:sha256"),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()
        print("✅ Admin user created in database")

# ---------------------------
# App Entry Point
# ---------------------------
if __name__ == '__main__':
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
