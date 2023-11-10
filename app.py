from flask import Flask, render_template, request, make_response, redirect
from flask_sqlalchemy import SQLAlchemy
import os
import sys
import uuid
import requests
import hashlib
import shutil
from tld import get_tld
from tld.exceptions import TldDomainNotFound

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

FLAG = os.getenv("FLAG", default="sicctf{}")
JWT_SERVICE_URL = 'http://web_cloudsign_auth:5001'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    name = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(30), nullable=False)
    signature = db.Column(db.String(128), nullable=False)
    avatar_url = db.Column(db.String(500), nullable=True)

    def __init__(self, name, email, password):
        self.uuid = uuid.uuid4().hex
        self.name = name
        self.email = email
        self.password = password
        self.signature = hashlib.sha512(self.uuid.encode('utf-8')).hexdigest()


def verify_token(token):
    response = requests.post(f"{JWT_SERVICE_URL}/verify_token", json={'token': token})
    if response.status_code == 200:
        return response
    else:
        return None

def get_token(email):
    response = requests.get(JWT_SERVICE_URL + '/get_token', params={'email': email})
    if response.status_code == 200:
        return response
    else:
        return None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user:
            return "Email already in use"
        
        new_user = User(name, email, password)
        db.session.add(new_user)
        db.session.commit()

        # Memory limiter
        users = User.query.order_by(User.id).all()
        if len(users) > 250:
            oldest_user = users[0]
            shutil.rmtree(f'static/{oldest_user.uuid}', ignore_errors=True)
            db.session.delete(oldest_user)
            db.session.commit()

        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email, password=password).first()
        if user:
            response = get_token(email)
            if response:
                token = response.json()['token']
                resp = make_response(redirect("/profile"))
                resp.set_cookie('jwt', token)
                return resp
            else:
                return "Failed to get JWT token", 500
        else:
            return "Invalid credentials"
    return render_template('login.html')

@app.route('/profile')
def profile():
    token = request.cookies.get('jwt')
    if token:
        response = verify_token(token)
        if response:
            email = response.json()['email']
            user = User.query.filter_by(email=email).first()
            if user:
                return render_template('profile.html', user=user)
        return redirect("/login")
    return redirect("/login")

@app.route('/change_photo', methods=['POST'])
def change_photo():
    if request.method == 'POST':
        data = request.get_json()
        avatar_url = data.get('url')
        try:
            tld = get_tld(avatar_url)
        except TldDomainNotFound:
            return {"error": "Invalid URL, only URLs with top-level domains are accepted"}, 400
        if avatar_url.endswith(('.png', '.jpg', '.jpeg')):
            token = request.cookies.get('jwt')
            if token:
                response = verify_token(token)
                if response:
                    email = response.json()['email']
                    user = User.query.filter_by(email=email).first()
                    if user:
                        try:
                            response = requests.get(avatar_url, stream=True, timeout=3)
                        except Exception as ex:
                            print("Error while downloading avatar:", ex, flush=True)
                            return {"error": "Error while proceeding request to provided host"}, 500
                        if response.status_code == 200:
                            os.makedirs(f'static/{user.uuid}', exist_ok=True)
                            total_size = 0
                            max_size = 5 * 1024 * 1024
                            with open(f'static/{user.uuid}/avatar.png', 'wb') as out_file:
                                for chunk in response.iter_content(chunk_size=128):
                                    total_size += 128
                                    if total_size > max_size:
                                        return {"error": "Picture can't be bigger than 5MB"}, 400
                                    out_file.write(chunk)

                            user.avatar_url = f'/static/{user.uuid}/avatar.png'
                            db.session.commit()
                            return redirect("/profile")
    return redirect("/login")


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        admin = User.query.filter_by(email='admin@cloudsign.ru').first()
        if not admin:
            admin = User(name='admin', email='admin@cloudsign.ru', password=uuid.uuid4().hex)
            admin.signature = FLAG
            db.session.add(admin)
            db.session.commit()


    if len(sys.argv) == 1:
        app.run(debug=False)
