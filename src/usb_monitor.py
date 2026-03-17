import psutil
import time
import logging
import socket
import threading

class USBMonitor(threading.Thread):
    def __init__(self, callback, interval=5):
        super().__init__()
        self.callback = callback
        self.interval = interval
        self.logger = logging.getLogger('USBMonitor')
        self.last_devices = self._get_removable_drives_info()
        self.local_ip = self._get_local_ip()
        self.running = True
        self.daemon = True

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _get_removable_drives_info(self):
        """Returns a dictionary of device names to their info for currently connected removable drives."""
        drives = {}
        for disk in psutil.disk_partitions():
            # Windows: 'removable' in disk.opts, Linux: /dev/sd* usually or specific fstypes
            if 'removable' in disk.opts or (disk.fstype and disk.device.startswith('/dev/sd')):
                drives[disk.device] = {
                    "device": disk.device,
                    "mountpoint": disk.mountpoint,
                    "fstype": disk.fstype
                }
        return drives

    def run(self):
        self.logger.info("USB Monitor thread started.")
        while self.running:
            try:
                events = self.check_events()
                for event in events:
                    self.callback(event)
            except Exception as e:
                self.logger.error(f"Error in USB monitor: {e}")
            time.sleep(self.interval)

    def check_events(self):
        current_devices_info = self._get_removable_drives_info()
        events = []

        current_devices = set(current_devices_info.keys())
        last_devices = set(self.last_devices.keys())

        # Check for new devices
        added = current_devices - last_devices
        for device in added:
            info = current_devices_info[device]
            events.append({
                "eventType": "USB_CONNECTED",
                "severity": "medium",
                "sourceIp": self.local_ip,
                "description": f"USB Device Connected: {device} at {info['mountpoint']}",
                "metadata": info
            })

        # Check for removed devices
        removed = last_devices - current_devices
        for device in removed:
            info = self.last_devices[device]
            events.append({
                "eventType": "USB_DISCONNECTED",
                "severity": "medium",
                "sourceIp": self.local_ip,
                "description": f"USB Device Disconnected: {device}",
                "metadata": info
            })

        self.last_devices = current_devices_info
        return events

    def stop(self):
        self.running = False
