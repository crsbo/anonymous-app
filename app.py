import os
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import arrow
import requests

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
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_premium = db.Column(db.Boolean, default=False)
    points = db.Column(db.Integer, default=0) # نظام النقاط
    free_reveals = db.Column(db.Integer, default=0) # عدد مرات الكشف المتاحة
    messages = db.relationship('Message', backref='receiver', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    # Game Fields
    name_opt_1 = db.Column(db.String(50))
    name_opt_2 = db.Column(db.String(50))
    name_opt_3 = db.Column(db.String(50))
    correct_name = db.Column(db.String(50))
    is_guessed = db.Column(db.Boolean, default=False)
    
    hint = db.Column(db.String(100))
    sender_name = db.Column(db.String(100))
    reveal_time = db.Column(db.DateTime)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    device_info = db.Column(db.String(100))
    location_info = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/dashboard')
@login_required
def dashboard():
    messages = Message.query.filter_by(user_id=current_user.id).order_by(Message.timestamp.desc()).all()
    return render_template('dashboard.html', messages=messages, count=len(messages), now=datetime.utcnow())

@app.route('/user/<username>', methods=['GET', 'POST'])
def send_message(username):
    user = User.query.filter_by(username=username).first_or_404()
    if request.method == 'POST':
        content = request.form.get('content')
        # Game Inputs
        opt1 = request.form.get('opt1')
        opt2 = request.form.get('opt2')
        opt3 = request.form.get('opt3')
        correct = request.form.get('correct') # بياخد القيمة من الـ Radio button
        
        hint = request.form.get('hint')
        sender_name = request.form.get('sender_name')
        reveal_delay = int(request.form.get('reveal_delay', 0))

        reveal_date = datetime.utcnow() + timedelta(hours=reveal_delay) if reveal_delay > 0 else None
        agent = request.headers.get('User-Agent', '')
        device = "iPhone" if "iPhone" in agent else "Android" if "Android" in agent else "PC"

        new_msg = Message(
            content=content, user_id=user.id, device_info=device, location_info="Remote",
            hint=hint, sender_name=sender_name, reveal_time=reveal_date,
            name_opt_1=opt1, name_opt_2=opt2, name_opt_3=opt3, correct_name=correct
        )
        db.session.add(new_msg)
        db.session.commit()
        return "<h1>Sent!</h1>"
    return render_template('send_msg.html', user=user)

# Route للتحقق من الإجابة وزيادة النقاط
@app.route('/check_answer/<int:msg_id>', methods=['POST'])
@login_required
def check_answer(msg_id):
    msg = Message.query.get_or_404(msg_id)
    selected = request.json.get('answer')
    
    if msg.is_guessed:
        return jsonify({"status": "already_guessed", "message": "Already answered!"})

    if selected == msg.correct_name:
        current_user.points += 1
        msg.is_guessed = True
        db.session.commit()
        return jsonify({"status": "correct", "points": current_user.points})
    else:
        return jsonify({"status": "wrong"})

@app.route('/be-pro')
@login_required
def be_pro():
    current_user.is_premium = True
    current_user.free_reveals = 5 # بنسلفه 5 مرات كشف كهدية
    db.session.commit()
    return redirect(url_for('dashboard'))

# ... باقي الـ Routes (Login, Logout, etc.) ...

# تشغيل السيرفر وبناء الجداول
with app.app_context():
    try:
        # بنمسح الجداول لمرة واحدة عشان التحديثات الجديدة (النقاط ولعبة الأسامي)
        db.drop_all() 
        db.create_all()
        print("Database Rebuilt with Points & Guess Game!")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    # السطرين دول هما اللي بيخلوا ريلواي يفتح الموقع صح
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
