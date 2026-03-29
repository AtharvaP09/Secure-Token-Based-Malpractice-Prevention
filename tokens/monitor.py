import time
import sys
import os
import threading
import json
import requests
import tkinter as tk
from tkinter import messagebox
from datetime import datetime
from logger import EncryptedLogger
from system_watcher import SystemWatcher
from network_sniffer import NetworkSniffer

class ExamMonitor:
    def __init__(self, api_url, jwt_token, session_id, username):
        self.api_url = api_url.rstrip('/')
        self.jwt_token = jwt_token
        self.session_id = session_id
        self.username = username
        
        # GUI Setup
        self.root = tk.Tk()
        self.root.title("Exam Monitor")
        self.root.geometry("300x180")
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        # Keep on top
        self.root.attributes('-topmost', True)
        
        # GUI Elements
        tk.Label(self.root, text="Exam Monitor Active", font=("Segoe UI", 14, "bold"), fg="green").pack(pady=(20, 10))
        tk.Label(self.root, text="Monitoring your exam environment.", font=("Segoe UI", 10)).pack()
        tk.Label(self.root, text="Do NOT close this window.", font=("Segoe UI", 10, "bold"), fg="red").pack(pady=5)
        tk.Label(self.root, text=f"Session ID: {session_id}", font=("Consolas", 8), fg="gray").pack(pady=(10, 0))

        # Fetch Configuration (Encryption Key)
        self.config = self.fetch_config()
        self.encryption_key = self.config.get("encryption_key")
        
        # Use username and session_id in filename
        self.logger = EncryptedLogger(f"{self.username}_session_{session_id}", "exam", self.encryption_key) 
        self.watcher = SystemWatcher(self.logger)
        self.sniffer = NetworkSniffer(self.logger)
        self.running = True

    def fetch_config(self):
        # We can't print easily in noconsole mode, so we rely on GUI errors if critical failure
        # For fetching config progress, we generally assume it works or fail fast.
        headers = {"Authorization": f"Bearer {self.jwt_token}"}
        try:
            url = f"{self.api_url}/exams/{self.session_id}/config"
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                messagebox.showerror("Error", f"Failed to fetch config: {response.text}")
                sys.exit(1)
        except Exception as e:
            messagebox.showerror("Error", f"Connection error: {e}")
            sys.exit(1)

    def on_closing(self):
        messagebox.showwarning("Restricted", "Exam monitoring is active.\nYou cannot close this window manually.\nIt will close automatically when you complete the exam.")

    def start(self):
        self.logger.log("SYSTEM", "Monitor Started")
        
        # Start Watchers
        self.watcher_thread = threading.Thread(target=self.watcher.start, daemon=True)
        self.watcher_thread.start()
        
        # Start Sniffer
        self.sniffer_thread = threading.Thread(target=self.sniffer.start, daemon=True)
        self.sniffer_thread.start()

        # Start Main Monitoring Loop in Thread
        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        # Run GUI Main Loop (Blocking)
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.stop()

    def monitor_loop(self):
        try:
            while self.running:
                self.upload_logs()
                time.sleep(5)
        except Exception as e:
            self.logger.log("SYSTEM", f"Monitor Loop Error: {e}")

    def upload_logs(self):
        # Flush any pending logs to queue
        self.logger.flush()
        
        if not self.logger.upload_queue:
            return

        # Take a batch (e.g., all of them)
        batch = self.logger.upload_queue[:] # Copy
        payload = {"logs": batch}
        
        headers = {
            "Authorization": f"Bearer {self.jwt_token}",
            "Content-Type": "application/json"
        }
        
        try:
            url = f"{self.api_url}/exams/{self.session_id}/log"
            response = requests.post(url, json=payload, headers=headers)
            
            if response.status_code == 200:
                # Remove successfully uploaded logs
                self.logger.upload_queue = self.logger.upload_queue[len(batch):]
                
                # Check for server commands
                try:
                    resp_json = response.json()
                    if resp_json.get("command") == "stop":
                        # Signal stop
                        self.stop()
                except:
                    pass 
        except Exception:
            pass # Keep trying silently

    def stop(self):
        if not self.running: return
        self.running = False
        
        self.watcher.stop()
        self.sniffer.stop()
        
        self.logger.log("SYSTEM", "Monitor Stopped")
        self.upload_logs() # Try one last upload
        self.logger.finalize()
        
        # Schedule GUI destruction on main thread
        self.root.after(0, lambda: [
            messagebox.showinfo("Exam Complete", f"Please upload the 'exam_ledger_{self.username}_session_{self.session_id}_exam.enc' file to the student portal to complete your submission."),
            self.root.destroy()
        ])

if __name__ == "__main__":
    api_url = None
    token = None
    sid = None
    username = "unknown"

    # Priority 1: Command Line Arguments
    if len(sys.argv) >= 5:
        api_url = sys.argv[1]
        token = sys.argv[2]
        sid = sys.argv[3]
        username = sys.argv[4]
    else:
        # Priority 2: Config File (monitor_config.json)
        config_path = "monitor_config.json"
        
        # Check current directory and executable directory
        if not os.path.exists(config_path):
             # Try executable directory (for PyInstaller bundle)
             if getattr(sys, 'frozen', False):
                exe_dir = os.path.dirname(sys.executable)
                config_path = os.path.join(exe_dir, "monitor_config.json")

        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    api_url = config.get("api_url")
                    token = config.get("jwt_token")
                    sid = config.get("session_id")
                    username = config.get("username", "unknown")
            except Exception:
                pass

    # Fallback / Validation
    if not all([api_url, token, sid]):
        # We can use Tkinter input dialogs if needed, but for now just error out
        # Since we are no-console, we can't input. 
        # But we can show error box.
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Configuration Error", "Missing monitor_config.json or arguments.\nPlease re-download the monitor from the exam portal.")
        sys.exit(1)

    monitor = ExamMonitor(api_url, token, sid, username)
    monitor.start()
