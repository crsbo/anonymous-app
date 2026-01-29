import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- إعدادات الأمان وقاعدة البيانات ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-123')

# التعديل لربط PostgreSQL في ريلواي لضمان عدم مسح البيانات
uri = os.environ.get('DATABASE_URL', 'sqlite:///anonymous_app.db')
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Models (الجداول بعد التحديث) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_premium = db.Column(db.Boolean, default=False) # ميزة البريميوم
    
    # ربط الرسايل (المرسلة والمستقبلة)
    received_messages = db.relationship('Message', foreign_keys='Message.user_id', backref='receiver_user', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # المستلم
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # الراسل (مخفي)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- المسارات (Routes) ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username').lower().strip()
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect(url_for('register'))
        
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template('auth.html', type='Register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').lower().strip()
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('auth.html', type='Login')

@app.route('/dashboard')
@login_required
def dashboard():
    # جلب رسايل اليوزر الحالي
    messages = Message.query.filter_by(user_id=current_user.id).order_by(Message.timestamp.desc()).all()
    # نحتاج نمرر موديل الـ User للـ template عشان نعرض اسم الراسل للبريميوم
    return render_template('dashboard.html', messages=messages, count=len(messages), User=User)

@app.route('/user/<username>', methods=['GET', 'POST'])
def send_message(username):
    user = User.query.filter_by(username=username).first_or_404()
    if request.method == 'POST':
        msg_content = request.form.get('content')
        if msg_content:
            # لو اللي بيبعت مسجل دخول، بنسجل الـ id بتاعه في صمت
            s_id = current_user.id if current_user.is_authenticated else None
            new_msg = Message(content=msg_content, user_id=user.id, sender_id=s_id)
            db.session.add(new_msg)
            db.session.commit()
            return "<h1>Message Sent!</h1><a href='/'>Go to App</a>"
    return render_template('send_msg.html', user=user)

# مسار الرد المجهول (Reply)
@app.route('/reply/<int:msg_id>', methods=['GET', 'POST'])
@login_required
def reply(msg_id):
    original_msg = Message.query.get_or_404(msg_id)
    if original_msg.user_id != current_user.id or not original_msg.sender_id:
        flash("You cannot reply to this message.")
        return redirect(url_for('dashboard'))
    
    recipient = User.query.get(original_msg.sender_id)
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            new_reply = Message(content=content, user_id=recipient.id, sender_id=current_user.id)
            db.session.add(new_reply)
            db.session.commit()
            flash('Your anonymous reply has been sent!')
            return redirect(url_for('dashboard'))
    return render_template('send_msg.html', user=recipient, is_reply=True)

@app.route('/delete/<int:msg_id>', methods=['POST'])
@login_required
def delete_message(msg_id):
    msg = Message.query.get_or_404(msg_id)
    if msg.user_id == current_user.id:
        db.session.delete(msg)
        db.session.commit()
        flash('Message deleted!')
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
