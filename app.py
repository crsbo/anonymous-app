import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- إعدادات الأمان وقاعدة البيانات ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-123')

# التوصيل بـ PostgreSQL في ريلواي أو SQLite محلياً
uri = os.environ.get('DATABASE_URL', 'sqlite:///anonymous_app.db')
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Models (الجداول المعدلة) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_premium = db.Column(db.Boolean, default=False) # خاصية الاشتراك
    
    # علاقات الرسائل
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver_user', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # مجهول لو مش مسجل

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes (المسارات) ---

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
            flash('الاسم مستخدم بالفعل!')
            return redirect(url_for('register'))
        
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('تم التسجيل بنجاح! سجل دخولك الآن.')
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
        flash('خطأ في الاسم أو كلمة المرور')
    return render_template('auth.html', type='Login')

@app.route('/dashboard')
@login_required
def dashboard():
    # جلب الرسائل اللي وصلت لليوزر الحالي
    messages = Message.query.filter_by(receiver_id=current_user.id).order_by(Message.timestamp.desc()).all()
    return render_template('dashboard.html', messages=messages, count=len(messages))

@app.route('/user/<username>', methods=['GET', 'POST'])
def send_message(username):
    user = User.query.filter_by(username=username).first_or_404()
    if request.method == 'POST':
        msg_content = request.form.get('content')
        if msg_content:
            # بنسجل الـ sender_id لو اللي بيبعت مسجل دخول، عشان صاحب الرسالة يعرف يرد عليه مجهول
            s_id = current_user.id if current_user.is_authenticated else None
            new_msg = Message(content=msg_content, receiver_id=user.id, sender_id=s_id)
            db.session.add(new_msg)
            db.session.commit()
            return "<h1>تم إرسال الرسالة بنجاح!</h1><a href='/'>العودة للرئيسية</a>"
    return render_template('send_msg.html', user=user)

@app.route('/reply/<int:msg_id>', methods=['GET', 'POST'])
@login_required
def reply(msg_id):
    original_msg = Message.query.get_or_404(msg_id)
    # التأكد إن اللي بيرد هو صاحب الرسالة فعلاً
    if original_msg.receiver_id != current_user.id:
        return "غير مسموح", 403
    
    # لو مفيش sender_id يبقى اللي بعت مكنش مسجل دخول ومينفعش نرد عليه
    if not original_msg.sender_id:
        return "لا يمكن الرد على مستخدم غير مسجل", 400

    sender_to_reply = User.query.get(original_msg.sender_id)
    
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            new_reply = Message(content=content, receiver_id=sender_to_reply.id, sender_id=current_user.id)
            db.session.add(new_reply)
            db.session.commit()
            flash('تم إرسال ردك بنجاح!')
            return redirect(url_for('dashboard'))
            
    return render_template('send_msg.html', user=sender_to_reply, is_reply=True)

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
