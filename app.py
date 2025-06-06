import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pandas as pd
from io import StringIO
from io import BytesIO
import requests
import threading
from flask import Response, stream_with_context
import time
import json


clients = []
clients_lock = threading.Lock()


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///leads.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_ip = db.Column(db.String(50))
    domain = db.Column(db.String(100))
    name = db.Column(db.String(100))
    mobile = db.Column(db.String(20))
    email = db.Column(db.String(100))
    email_status = db.Column(db.String(20))  # 'done' or 'failed'
    webhook_status = db.Column(db.String(20))  # 'done' or 'failed'
    project_id = db.Column(db.String(50))
    project_name = db.Column(db.String(100))
    page_url = db.Column(db.String(200))

# Create tables
with app.app_context():
    db.create_all()

# Login Manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def dashboard():
    leads = Lead.query.order_by(Lead.timestamp.desc()).limit(50).all()
    return render_template('dashboard.html', leads=leads, user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/api/handle_submmision', methods=['POST'])
def handle_submmision():
    data = request.get_json()
    print(data)
    print("geting req")

    if not data:
        return jsonify({'status': 'error', 'message': 'No data received'}), 400

    # Honeypot bot detection
    if data.get('menorwomen'):
        msg = f"{request.host}\n=> Bot submission\n=> Details: {{ Name: {data.get('fname')} | Email: {data.get('email')} | Mobile: {data.get('modal_my_mobile2')} }}"
        requests.post(url_for('err_log', _external=True), json={"message": msg})
        return jsonify({'status': 'error', 'message': 'Bot submission detected'}), 400

    # Extract dynamic fields
    name = data.get('name')
    email = data.get('email')
    mobile = data.get('mobile')
    domain = data.get('domain')
    page_url = request.referrer or 'unknown'
    account=data.get('account')
    project_name = data.get('project_name')
    project_id = data.get('project_id')
    send_to_email = data.get('send_to_email')
    user_ip = data.get('user_ip') 
    


    # Validation
    if not all([name, email, mobile, project_name, project_id]) or not send_to_email:
        return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
    if '@' not in email or not all('@' in e for e in send_to_email):
        return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400


    # Submit to internal lead API with initial failed status
    flask_api_url = url_for('submit_lead', _external=True)
    lead_payload = {
        'domain': domain,
        'name': name,
        'mobile': mobile,
        'email': email,
        'email_status': 'failed',
        'webhook_status': 'failed',
        'project_id': project_id,
        'project_name': project_name,
        'page_url': page_url,
        'user_ip':user_ip
    }
    # try:
    #     requests.post(flask_api_url, json=lead_payload)
    # except Exception as e:
    #     print(f"Initial API error: {e}")

    # === Send Email ===
    email_status = 'failed'
    try:
        from smtplib import SMTP
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.utils import formataddr

        smtp_host = 'smtp.elasticemail.com'
        smtp_port = 2525
        smtp_user = 'leads@valuepropertiesleads.in'
        smtp_pass = 'C9A95225AC8473D18A333D3132DAA0426B89'

        msg = MIMEMultipart()
        msg['From'] = formataddr((project_name, smtp_user))


        msg['To'] = ", ".join(send_to_email)
        msg['Subject'] = f'New Inquiry: {project_name}'

        html = f"""
        <strong>New Inquiry</strong><br>
        Project: {project_name}<br>
        Domain: {domain}<br>
        Name: {name}<br>
        Email: {email}<br>
        Mobile: {mobile}<br>
        Project ID: {project_id}<br>
        {account}
        """
        msg.attach(MIMEText(html, 'html'))

        with SMTP(smtp_host, smtp_port) as server:
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, send_to_email, msg.as_string())
            email_status = 'done'
    except Exception as e:
        err_msg = f"{domain}\nEmail Error: {e}\nLead: {{Name: {name}, Email: {email}, Mobile: {mobile}}}"
        requests.post(url_for('err_log', _external=True)
                      , json={"message": err_msg})

    # === Webhook ===
    webhook_status = 'failed'
    try:
        webhook_url = 'https://valueproperties.tranquilcrmone.in/wordpresswebhook'
        webhook_data = {
            'country_code': '91',
            'mobile': mobile,
            'form_name': 'Lead Inquiry',
            'name': name,
            'email': email,
            'project_name': project_id
        }
        resp = requests.post(webhook_url, data=webhook_data)
        if resp.ok:
            webhook_status = 'done'
        else:
            raise Exception(resp.text)
    except Exception as e:
        err_msg = f"{domain}\nWebhook Error: {e}\nLead: {{Name: {name}, Email: {email}, Mobile: {mobile}}}"
        requests.post("http://d48o0ws0so0wcgkgkk4cskgg.147.93.110.147.sslip.io/send-message", json={"message": err_msg})

    # === Final lead update ===
    lead_payload['email_status'] = email_status
    lead_payload['webhook_status'] = webhook_status
    try:
        requests.post(flask_api_url, json=lead_payload)
    except Exception as e:
        print(f"Final API update failed: {e}")

    return jsonify({
        'status': 'success',
        'message': 'Lead submitted',
        'email_status': email_status,
        'webhook_status': webhook_status
    })


# API to send a message
@app.route('/err_log', methods=['POST'])
def err_log():
    data = request.get_json()
    message_text = data.get('message', '').strip()
    if not message_text:
        return jsonify({'error': 'Message cannot be empty'}), 400
    
    msg = Message(text=message_text)
    db.session.add(msg)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': {
            'id': msg.id,
            'text': msg.text,
            'timestamp': msg.timestamp.isoformat()
        }
    })

# API to get last 50 messages
@app.route('/get-err')
@login_required
def get_err():
    messages = Message.query.order_by(Message.timestamp.desc()).limit(50).all()
    messages_data = [
        {
            'id': m.id,
            'text': m.text,
            'timestamp': m.timestamp.isoformat()
        } for m in reversed(messages)
    ]
    return jsonify(messages_data)

# Routes for rendering sender and receiver pages
@app.route('/sender')
def sender():
    return render_template('sender.html')

@app.route('/receiver')
@login_required
def receiver():
    return render_template('err_log.html')
@app.route('/api/submit_lead', methods=['POST'])
def submit_lead():
    data = request.get_json()
    
    if not data:
        return jsonify({'status': 'error', 'message': 'No data received'}), 400
    
    # Get user IP
    user_ip = data.get('user_ip') or request.remote_addr
    
    # Create new lead
    new_lead = Lead(
        user_ip=user_ip,
        domain=data.get('domain'),
        name=data.get('name'),
        mobile=data.get('mobile'),
        email=data.get('email'),
        email_status=data.get('email_status', 'pending'),
        webhook_status=data.get('webhook_status', 'pending'),
        project_id=data.get('project_id'),
        project_name=data.get('project_name'),
        page_url=data.get('page_url')
    )
    
    db.session.add(new_lead)
    db.session.commit()
    
    return jsonify({'status': 'success', 'message': 'Lead recorded'})

@app.route('/leads/filter', methods=['GET'])
@login_required
def filter_leads():
    # Get filter parameters
    project_id = request.args.get('project_id')
    project_name = request.args.get('project_name')
    email_status = request.args.get('email_status')
    webhook_status = request.args.get('webhook_status')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    page_url = request.args.get('page_url')  # NEW
    
    query = Lead.query
    
    if project_id:
        query = query.filter(Lead.project_id == project_id)
    if project_name:
        query = query.filter(Lead.project_name.contains(project_name))
    if email_status:
        query = query.filter(Lead.email_status == email_status)
    if webhook_status:
        query = query.filter(Lead.webhook_status == webhook_status)
    if start_date:
        query = query.filter(Lead.timestamp >= datetime.strptime(start_date, '%Y-%m-%d'))
    if end_date:
        query = query.filter(Lead.timestamp <= datetime.strptime(end_date, '%Y-%m-%d'))
    if page_url:
        query = query.filter(Lead.page_url.contains(page_url))  # NEW
    leads = query.order_by(Lead.timestamp.desc()).all()
    
    return render_template('leads_table.html', leads=leads)

@app.route('/leads/export', methods=['GET'])
@login_required
def export_leads():
    # Get filter parameters
    project_id = request.args.get('project_id')
    project_name = request.args.get('project_name')
    email_status = request.args.get('email_status')
    webhook_status = request.args.get('webhook_status')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    page_url = request.args.get('page_url')  # NEW
    
    query = Lead.query
    
    if project_id:
        query = query.filter(Lead.project_id == project_id)
    if project_name:
        query = query.filter(Lead.project_name.contains(project_name))
    if email_status:
        query = query.filter(Lead.email_status == email_status)
    if webhook_status:
        query = query.filter(Lead.webhook_status == webhook_status)
    if start_date:
        query = query.filter(Lead.timestamp >= datetime.strptime(start_date, '%Y-%m-%d'))
    if end_date:
        query = query.filter(Lead.timestamp <= datetime.strptime(end_date, '%Y-%m-%d'))
    if page_url:
        query = query.filter(Lead.page_url.contains(page_url))  # NEW    
    
    leads = query.order_by(Lead.timestamp.desc()).all()
    
    # Convert to DataFrame
    data = []
    for lead in leads:
        data.append({
            'Timestamp': lead.timestamp,
            'IP Address': lead.user_ip,
            'Domain': lead.domain,
            'Name': lead.name,
            'Mobile': lead.mobile,
            'Email': lead.email,
            'Email Status': lead.email_status,
            'Webhook Status': lead.webhook_status,
            'Project ID': lead.project_id,
            'Project Name': lead.project_name,
            'Page URL': lead.page_url
        })
    
    df = pd.DataFrame(data)
    
    # Create CSV in memory as bytes
    output = BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name='leads_export.csv'
    )
@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if not current_user.username == 'admin':
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not password:
            return render_template('create_user.html', error='Username and password are required')
        
        if password != confirm_password:
            return render_template('create_user.html', error='Passwords do not match')
        
        if User.query.filter_by(username=username).first():
            return render_template('create_user.html', error='Username already exists')
        
        # Create user
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password)
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('user_list'))
    
    return render_template('create_user.html')

@app.route('/admin/users/list')
@login_required
def user_list():
    if not current_user.username == 'admin':
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('user_list.html', users=users)
@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if not current_user.username == 'admin':  # Only allow admin to create users
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            return render_template('create_user.html', error='Username already exists')
        
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password)
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('dashboard'))
    
    return render_template('create_user.html')

# Templates would go here in a real app, but we'll define basic ones for functionality
@app.route('/leads/edit/<int:lead_id>', methods=['GET', 'POST'])
@login_required
def edit_lead(lead_id):
    lead = Lead.query.get_or_404(lead_id)

    if request.method == 'POST':
        lead.domain = request.form.get('domain')
        lead.name = request.form.get('name')
        lead.mobile = request.form.get('mobile')
        lead.email = request.form.get('email')
        lead.email_status = request.form.get('email_status')
        lead.webhook_status = request.form.get('webhook_status')
        lead.project_id = request.form.get('project_id')
        lead.project_name = request.form.get('project_name')
        lead.page_url = request.form.get('page_url')

        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template('edit_lead.html', lead=lead)
@app.route('/leads/delete/<int:lead_id>', methods=['POST'])
@login_required
def delete_lead(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    db.session.delete(lead)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/templates/<template_name>')
def serve_template(template_name):
    # In a real app, you'd have proper template files in a templates folder
    return f"Template {template_name} would be served here"

if __name__ == '__main__':
    # Create admin user if not exists
    with app.app_context():
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password_hash=generate_password_hash('admin123')
            )
            db.session.add(admin)
            db.session.commit()
    
    app.run(host='0.0.0.0',debug=True)

with app.app_context():
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password_hash=generate_password_hash('master@admin789@#')
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created.")    
