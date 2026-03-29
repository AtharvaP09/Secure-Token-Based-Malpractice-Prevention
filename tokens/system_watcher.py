import time
import psutil
try:
    import win32gui
    import win32process
except ImportError:
    win32gui = None

class SystemWatcher:
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.last_window = ""
        self.forbidden_processes = ["discord", "skype", "telegram", "chatgpt"]
        self.known_drives = []

    def start(self):
        self.running = True
        # Initial checks
        self.check_vm()
        self.known_drives = self.get_current_drives()
        
        # Start Keyboard Hooks
        try:
            import keyboard
            keyboard.add_hotkey('ctrl+c', self.on_copy_detected, suppress=False)
            keyboard.add_hotkey('ctrl+v', self.on_paste_detected, suppress=False)
            self.logger.log("SYSTEM", "Keyboard hooks started (Ctrl+C / Ctrl+V monitoring)")
        except ImportError:
            self.logger.log("ERROR", "Keyboard module not found. Copy/Paste detection disabled.")
        except Exception as e:
            self.logger.log("ERROR", f"Failed to start keyboard hooks: {e}")
        
        while self.running:
            self.check_active_window()
            self.check_processes()
            self.check_usb()
            time.sleep(1)

    def on_copy_detected(self):
        # We might not know what was copied, but we label the action
        self.logger.log("ALERT", "Suspicious Keyboard Action: Copy (Ctrl+C) Detected", is_suspicious=True)

    def on_paste_detected(self):
        self.logger.log("ALERT", "Suspicious Keyboard Action: Paste (Ctrl+V) Detected", is_suspicious=True)

    def stop(self):
        self.running = False
        try:
            import keyboard
            keyboard.unhook_all()
        except:
            pass

    def check_active_window(self):
        if not win32gui:
            return
        
        try:
            window = win32gui.GetForegroundWindow()
            title = win32gui.GetWindowText(window)
            if title != self.last_window:
                self.logger.log("WINDOW", f"Active Window: {title}")
                self.last_window = title
                
                # Simple keyword check
                title_lower = title.lower()
                suspicious_keywords = ["chat", "gpt", "claude", "gemini", "perplexity", "chegg", "stackoverflow", "blackbox", "quora", "brainly", "deepseek"]
                
                if any(keyword in title_lower for keyword in suspicious_keywords):
                     self.logger.log("ALERT", f"Suspicious Window Title: {title}", is_suspicious=True)
        except Exception as e:
            pass

    def check_processes(self):
        # This can be heavy, maybe run less frequently
        # For now, just check if any forbidden process allows it
        pass

    def check_vm(self):
        # 1. MAC Address Check
        mac_ouis = [
            "00:05:69", "00:0C:29", "00:1C:14", "00:50:56", # VMware
            "00:15:5D", # Hyper-V
            "08:00:27"  # VirtualBox
        ]
        try:
            # Simple check of primary interface (implementation varies, simplistic approach here)
            # Better to iterate all nics
            import uuid
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(47, -1, -8)]).upper()
            if any(oui in mac for oui in mac_ouis):
                 self.logger.log("ALERT", f"VM Detected (MAC OUI): {mac}", is_suspicious=True)
        except:
            pass
            
        # 2. Driver/File Check
        vm_files = [
            "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
            "C:\\Windows\\System32\\drivers\\vmmouse.sys",
            "C:\\Windows\\System32\\drivers\\wmbus.sys" # Hyper-V
        ]
        import os
        for f in vm_files:
            if os.path.exists(f):
                self.logger.log("ALERT", f"VM Detected (Driver File): {f}", is_suspicious=True)
                break

    def get_current_drives(self):
        try:
            return [d.device for d in psutil.disk_partitions() if 'removable' in d.opts or 'cdrom' in d.opts]
        except:
            return []

    def check_usb(self):
        current_drives = self.get_current_drives()
        # Check for new drives
        for drive in current_drives:
            if drive not in self.known_drives:
                 self.logger.log("ALERT", f"USB/External Drive Inserted: {drive}", is_suspicious=True)
        
        # Check for removed drives
        for drive in self.known_drives:
            if drive not in current_drives:
                 self.logger.log("SYSTEM", f"Drive Removed: {drive}")
                 
        self.known_drives = current_drives
