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
    Windows WMI 기반 통합 USB 모니터
    - 스마트폰(MTP/WPD), 마우스(HID), 저장장치(Disk)를 모두 감지합니다.
    """
    def __init__(self, callback, interval=5):
        super().__init__()
        self.callback = callback
        self.interval = interval
        self.logger = logging.getLogger('USBMonitor')
        self.running = True
        self.daemon = True
        self.local_ip = self._get_local_ip()
        
        if HAS_WMI and platform.system() == "Windows":
            # CoInitialize와 _wmi 생성은 이제 run()에서 수행합니다.
            self._wmi = None
            self.last_devices = {} 
        else:
            self.last_devices = {}
            if not HAS_WMI:
                self.logger.error("WMI 라이브러리가 설치되지 않았습니다. (pip install wmi pywin32)")

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _get_all_usb_devices(self):
        """WMI를 통해 모든 USB 계열 장치 목록을 가져옵니다."""
        devices = {}
        if not HAS_WMI or platform.system() != "Windows":
            return devices

        try:
            # WQL 쿼리 대신 전체를 긁어온 뒤 필터링하여 호환성 문제 해결
            for device in self._wmi.Win32_PnPEntity():
                device_id = device.DeviceID
                if not device_id or "USB" not in device_id.upper():
                    continue
                
                # 'USB\'로 시작하거나, USB 관련 클래스인 경우만 처리
                pnp_class = device.PNPClass
                name = device.Name or "Unknown USB Device"
                
                # 분류 로직
                category = "General"
                if pnp_class == "WPD": category = "Smartphone/Portable"
                elif pnp_class == "Mouse": category = "Mouse"
                elif pnp_class == "Keyboard": category = "Keyboard"
                elif pnp_class == "DiskDrive": category = "Storage"
                elif "Bluetooth" in name: category = "Bluetooth"

                devices[device_id] = {
                    "deviceId": device_id,
                    "name": name,
                    "class": pnp_class,
                    "category": category,
                    "description": device.Description or ""
                }
                
                # 저장 장치 또는 휴대용 장치인 경우 드라이브 문자 및 파일 목록 수집 시도
                if category in ["Storage", "Smartphone/Portable"]:
                    # 드라이브 문자가 할당될 때까지 약간의 지연이 있을 수 있으므로 재시도
                    drive_letter = self._get_drive_letter(device_id, retries=3)
                    if drive_letter:
                        devices[device_id]["mountpoint"] = drive_letter
                        devices[device_id]["file_list"] = self._scan_usb_files(drive_letter)
                        # 이름이 드라이브 문자로만 되어 있으면 더 구체적인 이름으로 보정
                        if devices[device_id]["name"].endswith(":\\"):
                             devices[device_id]["name"] = f"{name} ({drive_letter})"
        except Exception as e:
            self.logger.error(f"WMI USB Query Error: {e}")
            
        return devices

    def _get_drive_letter(self, pnp_id, retries=1):
        """PNP 장치 ID로부터 드라이브 문자(예: E:)를 찾아냅니다. (WMI 연쇄 추적 + psutil 2중 체크)"""
        import psutil
        
        for i in range(retries):
            try:
                # 1. WMI 연쇄 추적 (가장 정확한 하드웨어 연결 방식)
                for disk in self._wmi.Win32_DiskDrive(PNPDeviceID=pnp_id):
                    for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
                        for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                            if logical_disk.DeviceID:
                                return logical_disk.DeviceID
                
                # 2. psutil 기반 폴백 (WMI 연결이 끊긴 경우 새로 생긴 이동식 디스크 검색)
                # 드라이브 문자가 장치 ID나 이름에 포함된 경우를 대비한 단순 비교도 수행
                for part in psutil.disk_partitions(all=False):
                    if 'removable' in part.opts or 'cdrom' in part.opts:
                        # 새로 고침된 목록에서 해당 드라이브가 접근 가능한지 확인
                        if os.path.exists(part.mountpoint):
                            return part.mountpoint.rstrip("\\")
            except:
                pass
            
            if retries > 1 and i < retries - 1:
                time.sleep(1.5) # 드라이브 마운트 및 윈도우 인식 대기
        return None

    def _get_size_format(self, b):
        """바이트 단위를 읽기 쉬운 형식으로 변환합니다."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
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
                if not os.path.exists(path): return
                
                with os.scandir(path) as it:
                    entries = sorted(list(it), key=lambda e: (not e.is_dir(), e.name.lower()))
                    for entry in entries:
                        if self._items_count >= self._max_items: break
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
        if not HAS_WMI:
            self.logger.error("WMI 모니터링을 시작할 수 없습니다.")
            return

        pythoncom.CoInitialize() # 스레드별 초기화 필요
        if HAS_WMI and not self._wmi:
            self._wmi = wmi.WMI()
            # 첫 실행 시 현재 장치 상태를 한번 스냅샷 찍습니다.
            self.last_devices = self._get_all_usb_devices()

        self.logger.info("WMI-based USB Monitor thread started.")
        
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

        # 신규 장치 연결
        added = current_ids - last_ids
        for dev_id in added:
            info = current_devices[dev_id]
            events.append({
                "eventType": "USB_CONNECTED",
                "severity": "MEDIUM" if info["category"] in ["Storage", "Smartphone/Portable"] else "LOW",
                "sourceIp": self.local_ip,
                "summary": f"USB 장치 연결됨: {info['name']}",
                "description": f"새로운 USB 장치({info['category']})가 탐지되었습니다. (ID: {dev_id})",
                "metadata": info
            })

        # 장치 연결 해제
        removed = last_ids - current_ids
        for dev_id in removed:
            info = self.last_devices[dev_id]
            events.append({
                "eventType": "USB_DISCONNECTED",
                "severity": "LOW",
                "sourceIp": self.local_ip,
                "summary": f"USB 장치 제거됨: {info['name']}",
                "description": f"USB 장치({info['category']}) 연결이 해제되었습니다.",
                "metadata": info
            })

        self.last_devices = current_devices
        return events

    def stop(self):
        self.running = False
