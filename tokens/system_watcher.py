import time
import sys
import os
import psutil

PLATFORM = sys.platform  # "win32" or "linux"

# ── Windows-only imports ──────────────────────────────────────────────────────
if PLATFORM == "win32":
    try:
        import win32gui
        import win32process
        import pythoncom
        import wmi
    except ImportError:
        win32gui = win32process = pythoncom = wmi = None
else:
    win32gui = win32process = pythoncom = wmi = None

# ── Linux-only imports ────────────────────────────────────────────────────────
if PLATFORM == "linux":
    try:
        import pyudev
    except ImportError:
        pyudev = None

    try:
        from Xlib import display as xdisplay
        from Xlib import X
    except ImportError:
        xdisplay = None
else:
    pyudev = None
    xdisplay = None


class SystemWatcher:
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.last_window = ""
        self.forbidden_processes = [
            "discord", "skype", "telegram", "chatgpt",
            "anydesk", "teamviewer"
        ]
        self.known_devices = {}
        self.device_check_interval = 2
        self.last_device_check = 0

    # ─────────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ─────────────────────────────────────────────────────────────────────────
    def start(self):
        self.running = True

        if PLATFORM == "win32" and pythoncom:
            try:
                pythoncom.CoInitialize()
            except Exception:
                pass

        self.check_vm()
        self.initialize_devices()

        # Keyboard hooks — work on both platforms
        # Linux requires root OR user in the 'input' group
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

            now = time.time()
            if now - self.last_device_check >= self.device_check_interval:
                self.check_devices()
                self.last_device_check = now

            time.sleep(1)

    def stop(self):
        self.running = False
        try:
            import keyboard
            keyboard.unhook_all()
        except Exception:
            pass
        if PLATFORM == "win32" and pythoncom:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    # Keyboard callbacks
    # ─────────────────────────────────────────────────────────────────────────
    def on_copy_detected(self):
        self.logger.log("ALERT", "Suspicious Keyboard Action: Copy (Ctrl+C) Detected", is_suspicious=True)

    def on_paste_detected(self):
        self.logger.log("ALERT", "Suspicious Keyboard Action: Paste (Ctrl+V) Detected", is_suspicious=True)

    # ─────────────────────────────────────────────────────────────────────────
    # Active Window Detection
    # ─────────────────────────────────────────────────────────────────────────
    def check_active_window(self):
        if PLATFORM == "win32":
            self._check_window_win32()
        elif PLATFORM == "linux":
            self._check_window_linux()

    def _check_window_win32(self):
        if not win32gui:
            return
        try:
            hwnd = win32gui.GetForegroundWindow()
            title = win32gui.GetWindowText(hwnd)
            self._process_window_title(title)
        except Exception:
            pass

    def _check_window_linux(self):
        """
        Read active window title on Linux.
        Tries python-xlib first (X11 sessions), then falls back to xdotool.
        Does NOT work on pure Wayland without XWayland. See README for details.
        """
        # Try python-xlib (X11)
        if xdisplay:
            try:
                d = xdisplay.Display()
                root = d.screen().root
                NET_ACTIVE_WINDOW = d.intern_atom('_NET_ACTIVE_WINDOW')
                NET_WM_NAME = d.intern_atom('_NET_WM_NAME')

                win_id = root.get_full_property(NET_ACTIVE_WINDOW, X.AnyPropertyType)
                if win_id and win_id.value:
                    win = d.create_resource_object('window', win_id.value[0])
                    title_prop = win.get_full_property(NET_WM_NAME, 0)
                    if title_prop:
                        title = title_prop.value
                        if isinstance(title, bytes):
                            title = title.decode('utf-8', errors='replace')
                        self._process_window_title(title)
                d.close()
                return
            except Exception:
                pass

        # Fallback: xdotool (must be installed: sudo apt install xdotool)
        try:
            import subprocess
            result = subprocess.run(
                ["xdotool", "getactivewindow", "getwindowname"],
                capture_output=True, text=True, timeout=1
            )
            if result.returncode == 0:
                self._process_window_title(result.stdout.strip())
        except Exception:
            pass

    def _process_window_title(self, title):
        if not title or title == self.last_window:
            return
        self.last_window = title
        title_lower = title.lower()

        # 1. File Manager / External Storage
        is_file_manager = any(k in title_lower for k in [
            "files", "nautilus", "dolphin", "thunar", "nemo",
            "file manager", "file explorer", "internal storage",
            "iphone", "android", "removable disk", "usb drive"
        ])
        if is_file_manager:
            self.logger.log("WARNING", f"File Manager / Device Storage Opened: {title}", is_suspicious=False)
            return

        # 2. AI & Cheating Tools
        ai_keywords = [
            "chat", "gpt", "claude", "gemini", "perplexity", "chegg",
            "stackoverflow", "blackbox", "quora", "brainly", "deepseek",
            "openai", "copilot", "bard", "huggingface", "phind", "poe.com"
        ]
        if any(kw in title_lower for kw in ai_keywords):
            self.logger.log("ALERT", f"Suspicious Window Title (AI / Solution Search): {title}", is_suspicious=True)
            return

        # 3. Communication & Remote Access
        forbidden_apps = [
            "discord", "skype", "telegram", "whatsapp", "zoom",
            "teams", "slack", "anydesk", "teamviewer", "ultraviewer", "rustdesk"
        ]
        if any(app in title_lower for app in forbidden_apps):
            self.logger.log("ALERT", f"Unauthorized Communication / Remote Screen Window: {title}", is_suspicious=True)
            return

        # 4. Standard window log
        self.logger.log("WINDOW", f"Active Window: {title}")

    # ─────────────────────────────────────────────────────────────────────────
    # Process Monitoring  (psutil = cross-platform)
    # ─────────────────────────────────────────────────────────────────────────
    def check_processes(self):
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

    # ─────────────────────────────────────────────────────────────────────────
    # VM Detection
    # ─────────────────────────────────────────────────────────────────────────
    def check_vm(self):
        # MAC OUI check — works on both platforms
        mac_ouis = [
            "00:05:69", "00:0C:29", "00:1C:14", "00:50:56",  # VMware
            "00:15:5D",   # Hyper-V
            "08:00:27"    # VirtualBox
        ]
        try:
            import uuid
            mac = ':'.join(
                ['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(47, -1, -8)]
            ).upper()
            if any(oui in mac for oui in mac_ouis):
                self.logger.log("ALERT", f"VM Detected (MAC OUI): {mac}", is_suspicious=True)
        except Exception:
            pass

        if PLATFORM == "win32":
            vm_files = [
                "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
                "C:\\Windows\\System32\\drivers\\vmmouse.sys",
                "C:\\Windows\\System32\\drivers\\wmbus.sys"
            ]
            for f in vm_files:
                if os.path.exists(f):
                    self.logger.log("ALERT", f"VM Detected (Driver File): {f}", is_suspicious=True)
                    break

        elif PLATFORM == "linux":
            # Check DMI product name
            dmi_path = "/sys/class/dmi/id/product_name"
            if os.path.exists(dmi_path):
                try:
                    with open(dmi_path) as f:
                        product = f.read().strip().lower()
                    vm_keywords = ["virtualbox", "vmware", "kvm", "qemu", "hyper-v", "xen"]
                    for kw in vm_keywords:
                        if kw in product:
                            self.logger.log("ALERT", f"VM Detected (DMI): {product}", is_suspicious=True)
                            break
                except Exception:
                    pass

            # Check /proc/scsi/scsi for virtual adapters
            scsi_path = "/proc/scsi/scsi"
            if os.path.exists(scsi_path):
                try:
                    with open(scsi_path) as f:
                        content = f.read().lower()
                    if "vmware" in content or "vbox" in content:
                        self.logger.log("ALERT", "VM Detected (SCSI)", is_suspicious=True)
                except Exception:
                    pass

    # ─────────────────────────────────────────────────────────────────────────
    # Device Monitoring
    # ─────────────────────────────────────────────────────────────────────────
    def initialize_devices(self):
        self.known_devices = self.get_current_devices()
        kb_count     = sum(1 for d in self.known_devices.values() if d['category'] == 'KEYBOARD')
        mouse_count  = sum(1 for d in self.known_devices.values() if d['category'] == 'MOUSE')
        storage_count= sum(1 for d in self.known_devices.values() if d['category'] in ['STORAGE', 'MOBILE_DEVICE'])
        usb_count    = sum(1 for d in self.known_devices.values() if d['category'] == 'USB_DEVICE')
        self.logger.log(
            "SYSTEM",
            f"Hardware Baseline: {kb_count} Keyboard(s), {mouse_count} Mouse(s), "
            f"{storage_count} Storage/Device(s), {usb_count} USB Peripheral(s) active."
        )

    def get_current_devices(self):
        if PLATFORM == "win32":
            return self._get_devices_win32()
        elif PLATFORM == "linux":
            return self._get_devices_linux()
        return {}

    # ── Windows device enumeration (original WMI logic) ──────────────────────
    def _get_devices_win32(self):
        raw_grouped = {}
        if wmi:
            try:
                c = wmi.WMI()
                for m in c.Win32_PointingDevice():
                    bid = self._get_base_id(m.DeviceID)
                    raw_grouped.setdefault(bid, []).append(
                        {'category': 'MOUSE', 'name': m.Description or m.Name or 'Mouse', 'id': m.DeviceID}
                    )
                for kb in c.Win32_Keyboard():
                    bid = self._get_base_id(kb.DeviceID)
                    raw_grouped.setdefault(bid, []).append(
                        {'category': 'KEYBOARD', 'name': kb.Description or kb.Name or 'Keyboard', 'id': kb.DeviceID}
                    )
                for w in c.Win32_PnPEntity(PNPClass='WPD'):
                    bid = self._get_base_id(w.DeviceID)
                    raw_grouped.setdefault(bid, []).append(
                        {'category': 'MOBILE_DEVICE', 'name': w.Caption or w.Name or 'Mobile Device', 'id': w.DeviceID}
                    )
                for d in c.Win32_DiskDrive():
                    if getattr(d, 'InterfaceType', None) == 'USB':
                        bid = self._get_base_id(d.DeviceID)
                        raw_grouped.setdefault(bid, []).append(
                            {'category': 'STORAGE', 'name': d.Caption or d.Model or 'USB Drive', 'id': d.DeviceID}
                        )
                for u in c.Win32_USBHub():
                    if not u.DeviceID.startswith("USB\\ROOT_HUB"):
                        bid = self._get_base_id(u.DeviceID)
                        raw_grouped.setdefault(bid, []).append(
                            {'category': 'USB_DEVICE', 'name': u.Name or u.Description or 'USB Peripheral', 'id': u.DeviceID}
                        )
            except Exception:
                pass

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

        return self._resolve_devices(raw_grouped)

    # ── Linux device enumeration (pyudev + psutil) ────────────────────────────
    def _get_devices_linux(self):
        raw_grouped = {}

        if pyudev:
            try:
                context = pyudev.Context()

                # Input devices: keyboards & mice
                for device in context.list_devices(subsystem='input'):
                    if device.get('ID_INPUT_KEYBOARD') == '1':
                        dev_id = device.get('ID_PATH', device.sys_path)
                        name   = device.get('NAME', 'Keyboard Device').strip('"')
                        raw_grouped.setdefault(dev_id, []).append(
                            {'category': 'KEYBOARD', 'name': name, 'id': dev_id}
                        )
                    if device.get('ID_INPUT_MOUSE') == '1':
                        dev_id = device.get('ID_PATH', device.sys_path)
                        name   = device.get('NAME', 'Mouse Device').strip('"')
                        raw_grouped.setdefault(dev_id, []).append(
                            {'category': 'MOUSE', 'name': name, 'id': dev_id}
                        )

                # USB devices
                for device in context.list_devices(subsystem='usb', DEVTYPE='usb_device'):
                    dev_id    = device.get('ID_PATH', device.sys_path)
                    name      = device.get('ID_MODEL', device.get('ID_VENDOR', 'USB Device'))
                    interfaces = device.get('ID_USB_INTERFACES', '')
                    # :08 = Mass Storage, :06 = Still Image (phones/cameras)
                    if ':08' in interfaces:
                        cat = 'STORAGE'
                    elif ':06' in interfaces:
                        cat = 'MOBILE_DEVICE'
                    else:
                        cat = 'USB_DEVICE'
                    raw_grouped.setdefault(dev_id, []).append(
                        {'category': cat, 'name': name, 'id': dev_id}
                    )

            except Exception:
                pass

        # Removable drives via psutil (mounts under /media or /run/media)
        try:
            for d in psutil.disk_partitions():
                mountpoint = d.mountpoint
                if mountpoint.startswith('/media') or mountpoint.startswith('/run/media'):
                    raw_grouped.setdefault(f"DRIVE_{d.device}", []).append({
                        'category': 'STORAGE',
                        'name': f"Removable Storage ({d.device})",
                        'id': f"DRIVE_{d.device}"
                    })
        except Exception:
            pass

        return self._resolve_devices(raw_grouped)

    # ── Shared helpers ────────────────────────────────────────────────────────
    def _resolve_devices(self, raw_grouped):
        priority = ['MOUSE', 'MOBILE_DEVICE', 'STORAGE', 'KEYBOARD', 'USB_DEVICE']
        resolved = {}
        for bid, items in raw_grouped.items():
            cats = [i['category'] for i in items]
            for cat in priority:
                if cat in cats:
                    item = next(i for i in items if i['category'] == cat)
                    resolved[bid] = {'category': cat, 'name': item['name'], 'id': bid}
                    break
            else:
                resolved[bid] = {'category': items[0]['category'], 'name': items[0]['name'], 'id': bid}
        return resolved

    def _get_base_id(self, device_id):
        import re
        m = re.search(r'VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}', str(device_id), re.IGNORECASE)
        return m.group(0).upper() if m else str(device_id)

    def check_devices(self):
        current = self.get_current_devices()

        for dev_id, info in current.items():
            if dev_id not in self.known_devices:
                cat, name = info['category'], info['name']
                msgs = {
                    'MOUSE':         f"External Mouse Connected: {name} ({dev_id})",
                    'KEYBOARD':      f"External Keyboard Connected: {name} ({dev_id})",
                    'MOBILE_DEVICE': f"External Mobile Device / Phone Connected: {name}",
                    'STORAGE':       f"External USB / Storage Drive Inserted: {name}",
                }
                self.logger.log(
                    "DEVICE",
                    msgs.get(cat, f"External USB Peripheral Connected: {name} ({dev_id})"),
                    is_suspicious=True
                )

        for dev_id, info in self.known_devices.items():
            if dev_id not in current:
                self.logger.log(
                    "DEVICE",
                    f"External Device Disconnected: [{info['category']}] {info['name']}",
                    is_suspicious=False
                )

        self.known_devices = current
