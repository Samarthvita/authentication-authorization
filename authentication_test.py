import os 
import jwt
import bcrypt
from pymongo import MongoClient
from flask import Flask, jsonify, request
# from flask_pymongo import PyMongo
from datetime import datetime, timedelta
# from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
# from werkzeug.security import generate_password_hash, check_password_hash 
# from flask_httpauth import HTTPBasicAuth
# from functools import wraps

app = Flask(__name__)

# app.config['']
SECRET_KEY = '87782efa92944001bf53c5727610b44a'
# app.config['MONGO_URI'] = 'mongodb://localhost:27017/userdb'
# auth = HTTPBasicAuth()

client = MongoClient('mongodb://localhost:27017/')
db = client['userdb']
collection = db['user_data'], db['token_data']

print("Collection created")

# mongo = PyMongo(app)
# jwt = JWTManager(app)

@app.route('/register', methods = ['POST'])
def register():
    email = request.json.get('email')
    password = request.json.get('password')

    # data = [email, password]

    if email and password: 
        user = client.db.user_data.find_one({'email': email})
        if user:
            return jsonify({"message":"User already exists"}), 400 
        
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        client.db.user_data.insert_one({'email': email, 'password': hashed_password})

        return jsonify({"message": "user registered successfully"}), 201 
    
    return jsonify({"message": "Invalid data"}), 400 

@app.route('/login', methods = ['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')

    user = client.db.user_data.find_one({'email' : email})

    if not user or not bcrypt.checkpw(password.encode("utf-8"), user['password']):
        return jsonify ({"message": "Invalid email or password, kindly check and try again"}), 401
    

    #generating a JWT token 
    payload = {
        "user_id": str(user["_id"]),
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    client.db.token_data.insert_one({'token': token, 'payload': payload})
    
    return jsonify ({"message": "login successful", "token": token}), 200 

@app.route('')

if __name__ == '__main__':
    app.run(debug = True)


