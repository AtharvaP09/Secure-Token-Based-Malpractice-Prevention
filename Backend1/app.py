from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from models import db
import os
import mysql.connector
from dotenv import load_dotenv
from flask_socketio import SocketIO

load_dotenv()

app = Flask(__name__)

# MySQL connection
con = mysql.connector.connect(
    host='localhost',
    user='root',
    password=os.getenv('SQL_PASSWORD'),
    database='malpractice'
)

cursor1 = con.cursor()

# Create 'rooms' table with proper columns if not exists
cursor1.execute("""
CREATE TABLE IF NOT EXISTS rooms (
    room_id VARCHAR(200) NOT NULL PRIMARY KEY,
    password VARCHAR(200) NOT NULL,
    start_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP NULL,
    creator VARCHAR(100) NOT NULL
);
""")

# Create 'tokenfunction' table
# cursor1.execute("""
# CREATE TABLE IF NOT EXISTS tokenfunction (
#     token_id INT AUTO_INCREMENT PRIMARY KEY,
#     roomid VARCHAR(50) NOT NULL,
#     token_name VARCHAR(100) NOT NULL,
#     duration_minutes INT DEFAULT 0,
#     passive BOOLEAN DEFAULT FALSE,
#     restrictions JSON,
#     created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
#     FOREIGN KEY (roomid) REFERENCES rooms(roomid) ON DELETE CASCADE
# );
# """)

cursor1.close()

# Configure CORS
CORS(app, origins="*", methods=["GET", "POST"], allow_headers=["Content-Type", "Authorization"])

# Database configuration for SQLAlchemy
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///project.db'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

# Setup SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# Memory store for active users (optional, for WebSocket tracking)
active_users = {}

# Import routes after app configuration
from routes import *
from ws_routes import *

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Creates SQLite tables if not exists
    socketio.run(app, port=5643, debug=True)
