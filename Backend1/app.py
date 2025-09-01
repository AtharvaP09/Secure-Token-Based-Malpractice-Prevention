from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from models import db
import os
import mysql.connector
from dotenv import load_dotenv


load_dotenv()

app = Flask(__name__)

#MySQL for room details
con = mysql.connector.connect(
    host = 'localhost',
    user = 'root',
    password = os.getenv('SQL_PASSWORD'),
    database = 'malpractice'
    )

cursor1 = con.cursor()
cursor1.execute("""CREATE TABLE IF NOT EXISTS rooms (
    roomid VARCHAR(200) NOT NULL PRIMARY KEY,
    starttime FLOAT NULL,
    duration INT NULL,
    creator VARCHAR(100) NULL,
    restricted json
);""")

cursor1.execute('create table if not exists submissions(roomid varchar(200), userid varchar(200), cheats json, time datetime);')

cursor1.close()

# Configure CORS
CORS(app, origins="*", methods=["GET", "POST"], 
     allow_headers=["Content-Type", "Authorization"])

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///project.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

# Import routes after app configuration
from routes import *

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5643, debug=True)