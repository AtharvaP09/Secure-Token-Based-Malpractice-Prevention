import time
import psutil
try:
    import win32gui
    import win32process
    import pythoncom
    import wmi
except ImportError:
    win32gui = None
    win32process = None
    pythoncom = None
    wmi = None

class SystemWatcher:
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.last_window = ""
        self.forbidden_processes = ["discord", "skype", "telegram", "chatgpt", "anydesk", "teamviewer"]
        self.known_devices = {}
        self.device_check_interval = 2  # Check peripherals every 2 seconds
        self.last_device_check = 0

    def start(self):
        self.running = True
        if pythoncom:
            try:
                pythoncom.CoInitialize()
            except Exception:
                pass

        # Initial checks
        self.check_vm()
        self.initialize_devices()
        
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
            
            # Check devices periodically
            now = time.time()
            if now - self.last_device_check >= self.device_check_interval:
                self.check_devices()
                self.last_device_check = now

            time.sleep(1)

    def on_copy_detected(self):
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
        if pythoncom:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass

    def check_active_window(self):
        if not win32gui:
            return
        
        try:
            window = win32gui.GetForegroundWindow()
            title = win32gui.GetWindowText(window)
            if title and title != self.last_window:
                self.last_window = title
                title_lower = title.lower()

                # 1. File Explorer / External Storage (e.g. Apple iPhone, USB drive, PenDrive)
                is_file_explorer = any(k in title_lower for k in [
                    "file explorer", "internal storage", "iphone", "android",
                    "removable disk", "usb drive", "sd card", "flash drive"
                ])
                if is_file_explorer:
                    self.logger.log(
                        "WARNING",
                        f"File Explorer / Device Storage Opened: {title}",
                        is_suspicious=False
                    )
                    return

                # 2. AI & Cheating Tools (ChatGPT, Claude, Gemini, DeepSeek, etc.)
                ai_keywords = [
                    "chat", "gpt", "claude", "gemini", "perplexity", "chegg",
                    "stackoverflow", "blackbox", "quora", "brainly", "deepseek",
                    "openai", "copilot", "github copilot", "bard", "huggingface",
                    "midjourney", "phind", "poe.com", "casual greeting"
                ]
                if any(keyword in title_lower for keyword in ai_keywords):
                    self.logger.log(
                        "ALERT",
                        f"Suspicious Window Title (AI / Solution Search): {title}",
                        is_suspicious=True
                    )
                    return

                # 3. Communication & Remote Access Tools
                forbidden_apps = [
                    "discord", "skype", "telegram", "whatsapp", "zoom", "teams", "slack",
                    "anydesk", "teamviewer", "ultraviewer", "rustdesk"
                ]
                if any(app in title_lower for app in forbidden_apps):
                    self.logger.log(
                        "ALERT",
                        f"Unauthorized Communication / Remote Screen Window: {title}",
                        is_suspicious=True
                    )
                    return

                # 4. Standard window logging
                self.logger.log("WINDOW", f"Active Window: {title}")
        except Exception:
            pass

    def check_processes(self):
        # Quick scan of active process names against forbidden list
        try:
            for p in psutil.process_iter(['name']):
                p_name = (p.info['name'] or '').lower()
                for forbidden in self.forbidden_processes:
                    if forbidden in p_name:
                        self.logger.log(
                            "ALERT",
                            f"Forbidden Process Running: {p.info['name']}",
                            is_suspicious=True
                        )
        except Exception:
            pass

    def check_vm(self):
        mac_ouis = [
            "00:05:69", "00:0C:29", "00:1C:14", "00:50:56", # VMware
            "00:15:5D", # Hyper-V
            "08:00:27"  # VirtualBox
        ]
        try:
            import uuid
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(47, -1, -8)]).upper()
            if any(oui in mac for oui in mac_ouis):
                 self.logger.log("ALERT", f"VM Detected (MAC OUI): {mac}", is_suspicious=True)
        except:
            pass
            
        vm_files = [
            "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
            "C:\\Windows\\System32\\drivers\\vmmouse.sys",
            "C:\\Windows\\System32\\drivers\\wmbus.sys"
        ]
        import os
        for f in vm_files:
            if os.path.exists(f):
                self.logger.log("ALERT", f"VM Detected (Driver File): {f}", is_suspicious=True)
                break

    def get_base_id(self, device_id):
        """Extracts physical hardware Vendor and Product ID (VID_xxxx&PID_xxxx) for deduplication."""
        import re
        m = re.search(r'VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}', str(device_id), re.IGNORECASE)
        if m:
            return m.group(0).upper()
        return str(device_id)

    def get_current_devices(self):
        """Captures a snapshot of currently connected physical devices, deduplicating composite peripherals."""
        raw_grouped = {}
        if wmi:
            try:
                c = wmi.WMI()
                # 1. Mice / Pointing Devices
                for m in c.Win32_PointingDevice():
                    bid = self.get_base_id(m.DeviceID)
                    name = m.Description or m.Name or "Mouse Device"
                    raw_grouped.setdefault(bid, []).append({'category': 'MOUSE', 'name': name, 'id': m.DeviceID})

                # 2. Keyboards
                for kb in c.Win32_Keyboard():
                    bid = self.get_base_id(kb.DeviceID)
                    name = kb.Description or kb.Name or "Keyboard Device"
                    raw_grouped.setdefault(bid, []).append({'category': 'KEYBOARD', 'name': name, 'id': kb.DeviceID})

                # 3. Mobile Phones / Portable Devices (WPD / iPhone / Android)
                for w in c.Win32_PnPEntity(PNPClass='WPD'):
                    bid = self.get_base_id(w.DeviceID)
                    name = w.Caption or w.Name or "Mobile Device / Phone"
                    raw_grouped.setdefault(bid, []).append({'category': 'MOBILE_DEVICE', 'name': name, 'id': w.DeviceID})

                # 4. USB Flash Drives / External Disks
                for d in c.Win32_DiskDrive():
                    if getattr(d, 'InterfaceType', None) == 'USB':
                        bid = self.get_base_id(d.DeviceID)
                        name = d.Caption or d.Model or "USB Storage Drive"
                        raw_grouped.setdefault(bid, []).append({'category': 'STORAGE', 'name': name, 'id': d.DeviceID})

                # 5. USB Hubs and Connected Peripherals
                for u in c.Win32_USBHub():
                    if not u.DeviceID.startswith("USB\\ROOT_HUB"):
                        bid = self.get_base_id(u.DeviceID)
                        name = u.Name or u.Description or "USB Peripheral"
                        raw_grouped.setdefault(bid, []).append({'category': 'USB_DEVICE', 'name': name, 'id': u.DeviceID})

            except Exception:
                pass

        # 6. Removable storage drive letters
        try:
            for d in psutil.disk_partitions():
                if 'removable' in d.opts or 'cdrom' in d.opts:
                    raw_grouped.setdefault(f"DRIVE_{d.device}", []).append({
                        'category': 'STORAGE',
                        'name': f"Removable Storage ({d.device})",
                        'id': f"DRIVE_{d.device}"
                    })
        except Exception:
            pass

        # Resolve each physical device to its primary identity (MOUSE > MOBILE_DEVICE > STORAGE > KEYBOARD > USB_DEVICE)
        resolved = {}
        for bid, items in raw_grouped.items():
            cats = [i['category'] for i in items]
            if 'MOUSE' in cats:
                # If a device has a mouse function, it is solely a mouse (ignore its secondary keyboard/composite handles)
                m_item = next(i for i in items if i['category'] == 'MOUSE')
                resolved[bid] = {'category': 'MOUSE', 'name': m_item['name'], 'id': bid}
            elif 'MOBILE_DEVICE' in cats:
                w_item = next(i for i in items if i['category'] == 'MOBILE_DEVICE')
                resolved[bid] = {'category': 'MOBILE_DEVICE', 'name': w_item['name'], 'id': bid}
            elif 'STORAGE' in cats:
                s_item = next(i for i in items if i['category'] == 'STORAGE')
                resolved[bid] = {'category': 'STORAGE', 'name': s_item['name'], 'id': bid}
            elif 'KEYBOARD' in cats:
                k_item = next(i for i in items if i['category'] == 'KEYBOARD')
                resolved[bid] = {'category': 'KEYBOARD', 'name': k_item['name'], 'id': bid}
            else:
                resolved[bid] = {'category': items[0]['category'], 'name': items[0]['name'], 'id': bid}

        return resolved

    def initialize_devices(self):
        """Records initial peripheral baseline before exam begins."""
        self.known_devices = self.get_current_devices()
        kb_count = sum(1 for d in self.known_devices.values() if d['category'] == 'KEYBOARD')
        mouse_count = sum(1 for d in self.known_devices.values() if d['category'] == 'MOUSE')
        storage_count = sum(1 for d in self.known_devices.values() if d['category'] in ['STORAGE', 'MOBILE_DEVICE'])
        usb_count = sum(1 for d in self.known_devices.values() if d['category'] == 'USB_DEVICE')
        self.logger.log(
            "SYSTEM",
            f"Hardware Baseline: {kb_count} Keyboard(s), {mouse_count} Mouse(s), {storage_count} Storage/Device(s), {usb_count} USB Peripheral(s) active."
        )

    def check_devices(self):
        """Monitors real-time peripheral connections and disconnections."""
        current_devices = self.get_current_devices()

        # Check for newly connected devices
        for dev_id, info in current_devices.items():
            if dev_id not in self.known_devices:
                cat = info["category"]
                name = info["name"]
                if cat == "MOUSE":
                    self.logger.log("DEVICE", f"External Mouse Connected: {name} ({dev_id})", is_suspicious=True)
                elif cat == "KEYBOARD":
                    self.logger.log("DEVICE", f"External Keyboard Connected: {name} ({dev_id})", is_suspicious=True)
                elif cat == "MOBILE_DEVICE":
                    self.logger.log("DEVICE", f"External Mobile Device / Phone Connected: {name}", is_suspicious=True)
                elif cat == "STORAGE":
                    self.logger.log("DEVICE", f"External USB / Storage Drive Inserted: {name}", is_suspicious=True)
                else:
                    self.logger.log("DEVICE", f"External USB Peripheral Connected: {name} ({dev_id})", is_suspicious=True)

        # Check for disconnected devices
        for dev_id, info in self.known_devices.items():
            if dev_id not in current_devices:
                cat = info["category"]
                name = info["name"]
                self.logger.log("DEVICE", f"External Device Disconnected: [{cat}] {name}", is_suspicious=False)

        self.known_devices = current_devices
