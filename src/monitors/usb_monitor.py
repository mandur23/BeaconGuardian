import time
import logging
import socket
import threading
import platform
import os

try:
    import wmi
    import pythoncom
    HAS_WMI = True
except ImportError:
    HAS_WMI = False


class USBMonitor(threading.Thread):
    """
    cross-platform 통합 USB 모니터
    - Windows: WMI 기반 탐지 (스마트폰, 마우스, 저장장치 등)
    - Linux: sysfs(/sys/bus/usb/devices) 및 psutil 마운트 포인트 모니터링 기반 탐지
    """
    def __init__(self, callback, interval=5):
        super().__init__()
        self.callback = callback
        self.interval = interval
        self.logger = logging.getLogger('USBMonitor')
        self.running = True
        self.daemon = True
        self.local_ip = self._get_local_ip()
        self.last_devices = {}
        self._wmi = None

        if platform.system() == "Windows":
            if not HAS_WMI:
                self.logger.error(
                    "WMI 라이브러리가 설치되지 않았습니다. (pip install wmi pywin32)"
                )
        else:
            self.logger.info("Linux 환경에서 USB 모니터를 초기화합니다. (sysfs 기반)")

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    @classmethod
    def snapshot_devices(cls):
        """스레드 없이 USB 장치 목록 스냅샷 (diff 테스트·진단용)."""
        mon = cls(callback=None)
        if platform.system() == "Windows" and HAS_WMI:
            pythoncom.CoInitialize()
            try:
                mon._wmi = wmi.WMI()
                return mon._get_all_usb_devices()
            finally:
                pythoncom.CoUninitialize()
        return mon._get_all_usb_devices()

    def _get_all_usb_devices(self):
        if platform.system() == "Windows":
            return self._get_all_usb_devices_windows()
        return self._get_all_usb_devices_linux()

    def _get_all_usb_devices_windows(self):
        """WMI를 통해 모든 USB 계열 장치 목록을 가져옵니다. (Windows 전용)"""
        devices = {}
        if not HAS_WMI or not self._wmi:
            return devices

        try:
            for device in self._wmi.Win32_PnPEntity():
                device_id = device.DeviceID
                if not device_id or "USB" not in device_id.upper():
                    continue

                pnp_class = device.PNPClass
                name = device.Name or "Unknown USB Device"

                category = "General"
                if pnp_class == "WPD":
                    category = "Smartphone/Portable"
                elif pnp_class == "Mouse":
                    category = "Mouse"
                elif pnp_class == "Keyboard":
                    category = "Keyboard"
                elif pnp_class == "DiskDrive":
                    category = "Storage"
                elif "Bluetooth" in name:
                    category = "Bluetooth"

                devices[device_id] = {
                    "deviceId": device_id,
                    "name": name,
                    "class": pnp_class,
                    "category": category,
                    "description": device.Description or "",
                }

                if category in ["Storage", "Smartphone/Portable"]:
                    drive_letter = self._get_drive_letter_windows(device_id, retries=3)
                    if drive_letter:
                        devices[device_id]["mountpoint"] = drive_letter
                        devices[device_id]["file_list"] = self._scan_usb_files(drive_letter)
                        if devices[device_id]["name"].endswith(":\\"):
                            devices[device_id]["name"] = f"{name} ({drive_letter})"
        except Exception as e:
            self.logger.error(f"WMI USB Query Error: {e}")

        return devices

    def _get_all_usb_devices_linux(self):
        """sysfs 및 psutil 마운트를 통해 USB 장치 목록을 가져옵니다. (Linux 전용)"""
        devices = {}
        base_dir = "/sys/bus/usb/devices"
        if os.path.exists(base_dir):
            try:
                for name in os.listdir(base_dir):
                    path = os.path.join(base_dir, name)
                    id_vendor_path = os.path.join(path, "idVendor")
                    id_product_path = os.path.join(path, "idProduct")

                    if not (
                        os.path.exists(id_vendor_path)
                        and os.path.exists(id_product_path)
                    ):
                        continue
                    try:
                        with open(id_vendor_path, "r", encoding="utf-8") as f:
                            vid = f.read().strip()
                        with open(id_product_path, "r", encoding="utf-8") as f:
                            pid = f.read().strip()
                    except Exception:
                        continue

                    prod_name = "Unknown USB Device"
                    prod_path = os.path.join(path, "product")
                    if os.path.exists(prod_path):
                        try:
                            with open(prod_path, "r", encoding="utf-8") as f:
                                prod_name = f.read().strip()
                        except Exception:
                            pass

                    mfg_name = ""
                    mfg_path = os.path.join(path, "manufacturer")
                    if os.path.exists(mfg_path):
                        try:
                            with open(mfg_path, "r", encoding="utf-8") as f:
                                mfg_name = f.read().strip()
                        except Exception:
                            pass

                    serial = ""
                    serial_path = os.path.join(path, "serial")
                    if os.path.exists(serial_path):
                        try:
                            with open(serial_path, "r", encoding="utf-8") as f:
                                serial = f.read().strip()
                        except Exception:
                            pass

                    device_id = f"USB/VID_{vid}&PID_{pid}/{serial or name}"

                    category = "General"
                    lower_name = prod_name.lower()
                    if "mouse" in lower_name:
                        category = "Mouse"
                    elif "keyboard" in lower_name:
                        category = "Keyboard"
                    elif any(
                        kw in lower_name
                        for kw in ["phone", "android", "iphone", "mtp"]
                    ):
                        category = "Smartphone/Portable"
                    elif any(
                        kw in lower_name
                        for kw in ["storage", "flash", "mass storage", "disk"]
                    ):
                        category = "Storage"

                    devices[device_id] = {
                        "deviceId": device_id,
                        "name": prod_name,
                        "class": "USB",
                        "category": category,
                        "description": f"{mfg_name} {prod_name}".strip(),
                    }
            except Exception as e:
                self.logger.error(f"Linux USB Query Error: {e}")

        try:
            import psutil

            for part in psutil.disk_partitions(all=False):
                if part.mountpoint.startswith(("/media/", "/mnt/")):
                    dev_id = f"MOUNT/{part.device.replace('/dev/', '')}"
                    mount_name = os.path.basename(part.mountpoint) or part.device
                    devices[dev_id] = {
                        "deviceId": dev_id,
                        "name": f"USB Storage ({mount_name})",
                        "class": "DiskDrive",
                        "category": "Storage",
                        "description": (
                            f"Mounted partition {part.device} on {part.mountpoint}"
                        ),
                        "mountpoint": part.mountpoint,
                    }
                    devices[dev_id]["file_list"] = self._scan_usb_files(
                        part.mountpoint
                    )
        except Exception as e:
            self.logger.debug(f"Linux mount check error: {e}")

        return devices

    def _get_drive_letter_windows(self, pnp_id, retries=1):
        """PNP 장치 ID로부터 드라이브 문자를 찾아냅니다. (Windows 전용)"""
        import psutil

        for i in range(retries):
            try:
                for disk in self._wmi.Win32_DiskDrive(PNPDeviceID=pnp_id):
                    for partition in disk.associators(
                        "Win32_DiskDriveToDiskPartition"
                    ):
                        for logical_disk in partition.associators(
                            "Win32_LogicalDiskToPartition"
                        ):
                            if logical_disk.DeviceID:
                                return logical_disk.DeviceID

                for part in psutil.disk_partitions(all=False):
                    if "removable" in part.opts or "cdrom" in part.opts:
                        if os.path.exists(part.mountpoint):
                            return part.mountpoint.rstrip("\\")
            except Exception:
                pass

            if retries > 1 and i < retries - 1:
                time.sleep(1.5)
        return None

    def _get_size_format(self, b):
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if b < 1024:
                return f"{b:.1f}{unit}"
            b /= 1024
        return f"{b:.1f}PB"

    def _scan_usb_files(self, drive_path):
        """해당 경로를 정밀 스캔하여 트리 구조의 파일 목록을 생성합니다. (최대 3단계, 1000개 제한)"""
        results = []
        self._items_count = 0
        self._max_items = 1000

        def _recursive_scan(path, depth=0, indent=""):
            if depth >= 3 or self._items_count >= self._max_items:
                return

            try:
                if not os.path.exists(path):
                    return

                with os.scandir(path) as it:
                    entries = sorted(
                        list(it), key=lambda e: (not e.is_dir(), e.name.lower())
                    )
                    for entry in entries:
                        if self._items_count >= self._max_items:
                            break
                        self._items_count += 1

                        prefix = indent + ("└─ " if indent else "")
                        if entry.is_dir():
                            results.append(f"{prefix}[Dir] {entry.name}")
                            _recursive_scan(entry.path, depth + 1, indent + "  ")
                        else:
                            size = self._get_size_format(entry.stat().st_size)
                            results.append(f"{prefix}[File] {entry.name} ({size})")
            except Exception:
                pass

        _recursive_scan(drive_path)
        return results

    def run(self):
        if platform.system() == "Windows":
            if not HAS_WMI:
                self.logger.error("WMI 모니터링을 시작할 수 없습니다.")
                return
            pythoncom.CoInitialize()
            if not self._wmi:
                self._wmi = wmi.WMI()
        else:
            if not HAS_WMI:
                pass

        self.last_devices = self._get_all_usb_devices()
        self.logger.info(f"{platform.system()} USB Monitor thread started.")

        while self.running:
            try:
                events = self.check_events()
                for event in events:
                    if self.callback:
                        self.callback(event)
            except Exception as e:
                self.logger.error(f"Error in USB monitor loop: {e}")
            time.sleep(self.interval)

    def check_events(self):
        current_devices = self._get_all_usb_devices()
        events = []

        current_ids = set(current_devices.keys())
        last_ids = set(self.last_devices.keys())

        added = current_ids - last_ids
        for dev_id in added:
            info = current_devices[dev_id]
            category = info.get("category", "General")
            events.append({
                "eventType": "USB_CONNECTED",
                "severity": "MEDIUM"
                if category in ["Storage", "Smartphone/Portable"]
                else "LOW",
                "sourceIp": self.local_ip,
                "summary": f"USB 장치 연결됨: {info.get('name', dev_id)}",
                "description": (
                    f"새로운 USB 장치({category})가 탐지되었습니다. (ID: {dev_id})"
                ),
                "metadata": info,
            })

        removed = last_ids - current_ids
        for dev_id in removed:
            info = self.last_devices[dev_id]
            category = info.get("category", "General")
            events.append({
                "eventType": "USB_DISCONNECTED",
                "severity": "LOW",
                "sourceIp": self.local_ip,
                "summary": f"USB 장치 제거됨: {info.get('name', dev_id)}",
                "description": f"USB 장치({category}) 연결이 해제되었습니다.",
                "metadata": info,
            })

        self.last_devices = current_devices
        return events

    def stop(self):
        self.running = False
