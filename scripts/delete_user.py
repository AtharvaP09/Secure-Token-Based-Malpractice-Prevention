import sys
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add project root to sys.path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from backend import models, database

def delete_user(username):
    db = database.SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.username == username).first()
        if not user:
            print(f"User '{username}' not found.")
            return

        print(f"Found user: {user.username} (ID: {user.id}, Role: {user.role})")
        confirmation = input("Are you sure you want to delete this user? This will cascade and delete their exams/sessions logs! (yes/no): ")
        
        if confirmation.lower() == 'yes':
            db.delete(user)
            db.commit()
            print(f"User '{username}' deleted successfully.")
        else:
            print("Deletion cancelled.")
            
    except Exception as e:
        print(f"An error occurred: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python delete_user.py <username>")
        username_input = input("Enter username to delete: ")
        if username_input:
            delete_user(username_input)
    else:
        delete_user(sys.argv[1])
