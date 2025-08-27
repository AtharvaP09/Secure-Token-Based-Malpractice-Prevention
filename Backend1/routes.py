from app import app
from models import *
from flask import request, jsonify

#Default
@app.route('/')
def home():
    return "Secure Token Based Malpractice Prevention , Hello World!"

#Users
@app.route('/users' , methods=["GET"])
def users():
    return"List of users to be displayed"

#User Registration
@app.route('/UserRegistration' , methods=["POST"])
def UserRegistration():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already registered"}), 400

    user = User(username=username, email=email)
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

#User Login
@app.route("/UserLogin", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if user is None or not user.check_password(password):
        return jsonify({"message": "Invalid credentials"}), 401

    return jsonify({"message": "Login successful", "user_id": user.id}), 200