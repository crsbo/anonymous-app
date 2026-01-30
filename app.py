import os
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import arrow

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-123')

# Database Setup
uri = os.environ.get('DATABASE_URL', 'sqlite:///anonymous_app.db')
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Models ---

class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class PointLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender_ip = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_premium = db.Column(db.Boolean, default=False)
    points = db.Column(db.Integer, default=0)
    messages = db.relationship('Message', backref='receiver', lazy=True)

    def get_friend_ids(self):
        f1 = Friendship.query.filter_by(user_id=self.id).all()
        f2 = Friendship.query.filter_by(friend_id=self.id).all()
        ids = [f.friend_id for f in f1] + [f.user_id for f in f2]
        return list(set(ids))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    name_opt_1 = db.Column(db.String(50)); name_opt_2 = db.Column(db.String(50)); name_opt_3 = db.Column(db.String(50))
    correct_name = db.Column(db.String(50))
    is_guessed = db.Column(db.Boolean, default=False)
    sender_ip = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        raw_username = request.form.get('username', '').strip()
        password = request.form.get('password')
        if any(char.isupper() for char in raw_username):
            flash('Please use lowercase letters only for your username.', 'danger')
            return redirect(url_for('register'))
        username = raw_username.lower()
        if User.query.filter_by(username=username).first():
            flash('Username already exists! Try another one.', 'danger')
            return redirect(url_for('register'))
        new_user = User(username=username, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('auth.html', type='Register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').lower().strip()
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid username or password. Please try again.', 'danger')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('auth.html', type='Login')

@app.route('/dashboard')
@login_required
def dashboard():
    messages = Message.query.filter_by(user_id=current_user.id).order_by(Message.timestamp.desc()).all()
    global_top = User.query.order_by(User.points.desc()).limit(5).all()
    friend_ids = current_user.get_friend_ids()
    friend_ids.append(current_user.id)
    friends_top = User.query.filter(User.id.in_(friend_ids)).order_by(User.points.desc()).all()
    return render_template('dashboard.html', messages=messages, count=len(messages), global_top=global_top, friends_top=friends_top, now=datetime.utcnow())

# رابط صفحة النجاح
@app.route('/sent_success')
def sent_success():
    return render_template('sent_success.html')

@app.route('/user/<username>', methods=['GET', 'POST'])
def send_message(username):
    user = User.query.filter_by(username=username.lower()).first()
    if not user:
        flash(f'User "{username}" not found. Make sure the link is correct.', 'danger')
        return redirect(url_for('register'))

    if request.method == 'POST':
        ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        content = request.form.get('content')
        opt1 = request.form.get('opt1'); opt2 = request.form.get('opt2'); opt3 = request.form.get('opt3')
        correct_choice = request.form.get('correct')
        
        final_correct_name = None
        if correct_choice == "1": final_correct_name = opt1
        elif correct_choice == "2": final_correct_name = opt2
        elif correct_choice == "3": final_correct_name = opt3

        new_msg = Message(content=content, user_id=user.id, sender_ip=ip_addr, name_opt_1=opt1, name_opt_2=opt2, name_opt_3=opt3, correct_name=final_correct_name)
        db.session.add(new_msg)
        db.session.commit()
        
        # بدلاً من عمل flash لنفس الصفحة، نوجه المستخدم لصفحة النجاح
        return redirect(url_for('sent_success'))
        
    return render_template('send_msg.html', user=user)

@app.route('/check_answer/<int:msg_id>', methods=['POST'])
@login_required
def check_answer(msg_id):
    msg = Message.query.get_or_404(msg_id)
    selected = request.json.get('answer')
    if msg.is_guessed: return jsonify({"status": "already_guessed"})
    if selected == msg.correct_name:
        time_threshold = datetime.utcnow() - timedelta(hours=24)
        recent_log = PointLog.query.filter(PointLog.user_id == current_user.id, PointLog.sender_ip == msg.sender_ip, PointLog.timestamp >= time_threshold).first()
        msg.is_guessed = True 
        if not recent_log:
            current_user.points += 1
            new_log = PointLog(user_id=current_user.id, sender_ip=msg.sender_ip)
            db.session.add(new_log)
            db.session.commit()
            return jsonify({"status": "correct", "points": current_user.points})
        else:
            db.session.commit()
            return jsonify({"status": "correct", "points": current_user.points, "message": "No new points for 24h"})
    return jsonify({"status": "wrong"})

@app.route('/add_friend/<int:friend_id>', methods=['POST'])
@login_required
def add_friend(friend_id):
    if friend_id == current_user.id: return redirect(url_for('dashboard'))
    exists = Friendship.query.filter(((Friendship.user_id == current_user.id) & (Friendship.friend_id == friend_id)) | ((Friendship.user_id == friend_id) & (Friendship.friend_id == current_user.id))).first()
    if not exists:
        new_f = Friendship(user_id=current_user.id, friend_id=friend_id)
        db.session.add(new_f)
        db.session.commit()
        flash("Friend added! 🤝", "success")
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
