import os
import json
import secrets
import string
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from cryptography.fernet import Fernet
from groq import Groq
from models import db, User, Post, NewsSubscriber
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

db.init_app(app)

mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def groq_verify_content(text_content):
    try:
        completion = groq_client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are a content safety filter for a cybersecurity forum. Analyze the user input. If it contains malicious code intended for harm (not educational), actual illegal PII, or dangerous uncontained malware without context, return unsafe. If it is educational, a proof of concept, or standard discussion, return safe. Return ONLY valid JSON in this format: {\"result\": \"safe\"} or {\"result\": \"unsure\"} or {\"result\": \"unsafe\"}"
                },
                {
                    "role": "user",
                    "content": text_content
                }
            ],
            model="llama3-8b-8192",
            response_format={"type": "json_object"}
        )
        return json.loads(completion.choices[0].message.content)
    except Exception as e:
        return {"result": "unsure"}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'danger')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(
            email=email,
            username=username,
            password=hashed_pw,
            is_verified=False
        )
        db.session.add(new_user)
        db.session.commit()

        token = s.dumps(email, salt='email-confirm')
        confirm_link = url_for('confirm_email', token=token, _external=True)

        msg = Message(
            subject='Verify your HackShield Account',
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )

        msg.body = f"""
Welcome to HackShield, {username}!

If you are seeing this then our HTML based email failed to send. Please contact the developers.
You can still verify your account by clicking the link below:
{confirm_link}
This link will expire in 30 minutes.

If you did not create this account, you can safely ignore this email.
"""

        msg.html = render_template(
            'emails/verify_email.html',
            username=username,
            confirm_link=confirm_link
        )

        try:
            mail.send(msg)
            flash('A verification link has been sent to your email. Expires in 30 minutes.', 'info')
        except Exception:
            flash('Account created, but email failed to send. Contact admin.', 'warning')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=1800)
    except (SignatureExpired, BadTimeSignature):
        return '<h1>Error: Invalid or expired confirmation link.</h1>'
    
    user = User.query.filter_by(email=email).first_or_404()
    if user.is_verified:
        flash('Account is already verified. Please login.', 'success')
    else:
        user.is_verified = True
        db.session.commit()
        flash('You have confirmed your account. Welcome to HackShield.', 'success')
    
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Login failed. Check your details.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/tools', methods=['GET', 'POST'])
@login_required
def tools():
    pwd_result = None
    enc_result = None
    dec_result = None
    
    if request.method == 'POST':
        if 'gen_pwd' in request.form:
            length = int(request.form.get('length', 12))
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            pwd_result = ''.join(secrets.choice(chars) for _ in range(length))
            
        elif 'encrypt' in request.form:
            text = request.form.get('text_to_enc')
            key = Fernet.generate_key()
            f = Fernet(key)
            enc_result = {
                'text': f.encrypt(text.encode()).decode(),
                'key': key.decode()
            }
            
        elif 'decrypt' in request.form:
            try:
                text = request.form.get('text_to_dec')
                key = request.form.get('dec_key')
                f = Fernet(key.encode())
                dec_result = f.decrypt(text.encode()).decode()
            except:
                dec_result = "Decryption Failed: Invalid Key or Token"

    return render_template('tools.html', pwd_result=pwd_result, enc_result=enc_result, dec_result=dec_result)

@app.route('/forum', methods=['GET', 'POST'])
@login_required
def forum():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        category = request.form.get('category')
        
        # Groq Safety Check
        safety = groq_verify_content(content)
        if safety.get('result') == 'unsafe':
            flash('Post rejected: Content got flagged as malicious.', 'danger')
        else:
            new_post = Post(title=title, content=content, category=category, author=current_user)
            db.session.add(new_post)
            db.session.commit()
            flash('Post shared successfully, no content policy violations detected.', 'success')
            
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    return render_template('forum.html', posts=posts)

@app.route('/news', methods=['GET', 'POST'])
def news():
    if request.method == 'POST':
        email = request.form.get('email')
        if not NewsSubscriber.query.filter_by(email=email).first():
            db.session.add(NewsSubscriber(email=email))
            db.session.commit()
            flash('Subscribed to newsletter!', 'success')
        else:
            flash('You are already subscribed.', 'info')
    return render_template('news.html')

@app.route('/chat_api', methods=['POST'])
@login_required
def chat_api():
    data = request.json
    user_msg = data.get('message')
    
    system_prompt = "You are a helpful cybersecurity assistant named HS-007 for HackSheild. Assist with ethical hacking, defense strategies, and script analysis. Prevent attacks by offering defensive guidance."
    
    try:
        completion = groq_client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_msg}
            ],
            model="llama3-8b-8192"
        )
        return jsonify({"response": completion.choices[0].message.content})
    except Exception as e:
        return jsonify({"response": "Error connecting to HS-007 (AI)."})

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html')

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
