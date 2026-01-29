import os
from datetime import datetime, timedelta # ضفنا timedelta هنا
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import arrow
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-123')

# إعداد قاعدة البيانات
uri = os.environ.get('DATABASE_URL', 'sqlite:///anonymous_app.db')
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_premium = db.Column(db.Boolean, default=False)
    messages = db.relationship('Message', backref='receiver', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    hint = db.Column(db.String(100)) # التلميح
    sender_name = db.Column(db.String(100)) # الاسم الحقيقي
    reveal_time = db.Column(db.DateTime) # وقت كشف الاسم
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    device_info = db.Column(db.String(100))
    location_info = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/')
def index():
    return redirect(url_for('dashboard')) if current_user.is_authenticated else redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').lower().strip()
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect(url_for('register'))
        new_user = User(username=username, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('auth.html', type='Register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').lower().strip()
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid login details')
    return render_template('auth.html', type='Login')

@app.route('/upgrade')
@login_required
def upgrade():
    return render_template('upgrade.html')

@app.route('/dashboard')
@login_required
def dashboard():
    messages = Message.query.filter_by(user_id=current_user.id).order_by(Message.timestamp.desc()).all()
    # بنبعت datetime.utcnow عشان التايمر يحسب الفرق في الصفحة
    return render_template('dashboard.html', messages=messages, count=len(messages), now=datetime.utcnow())

@app.route('/user/<username>', methods=['GET', 'POST'])
def send_message(username):
    user = User.query.filter_by(username=username).first_or_404()
    if request.method == 'POST':
        content = request.form.get('content')
        hint = request.form.get('hint') # استلام التلميح
        sender_name = request.form.get('sender_name') # استلام الاسم
        reveal_delay = int(request.form.get('reveal_delay', 0)) # استلام الساعات
        
        # حساب وقت الكشف
        reveal_date = None
        if sender_name and reveal_delay > 0:
            reveal_date = datetime.utcnow() + timedelta(hours=reveal_delay)

        # تحديد الجهاز
        agent = request.headers.get('User-Agent', '')
        device = "iPhone" if "iPhone" in agent else "Android" if "Android" in agent else "PC"

        # تحديد اللوكيشن
        location = "Unknown City"
        try:
            ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
            geo_res = requests.get(f'http://ip-api.com/json/{ip_addr}', timeout=3).json()
            if geo_res.get('status') == 'success':
                location = f"{geo_res.get('city')}, {geo_res.get('country')}"
        except:
            location = "Location Unavailable"

        if content:
            new_msg = Message(
                content=content, 
                user_id=user.id, 
                device_info=device, 
                location_info=location,
                hint=hint,
                sender_name=sender_name,
                reveal_time=reveal_date
            )
            db.session.add(new_msg)
            db.session.commit()
            return "<h1>Sent Successfully!</h1><a href='/'>Back</a>"
            
    return render_template('send_msg.html', user=user)

@app.route('/be-pro')
@login_required
def be_pro():
    current_user.is_premium = True
    db.session.commit()
    flash("You are now a Premium user! 🚀")
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:msg_id>', methods=['POST'])
@login_required
def delete_message(msg_id):
    msg = Message.query.get_or_404(msg_id)
    if msg.user_id == current_user.id:
        db.session.delete(msg)
        db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.context_processor
def utility_processor():
    def format_date(date):
        return arrow.get(date).humanize()
    return dict(format_date=format_date)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)



