import requests
import logging
import time
import socket
import platform
import getpass
import json
import threading

class BeaconClient:
    def __init__(self, server_url, username, password, agent_name="BeaconGuardian", agent_version="1.0.0"):
        self.server_url = server_url.rstrip('/')
        self.username = username
        self.password = password
        self.agent_name = agent_name
        self.agent_version = agent_version
        self.token = None
        self.logger = logging.getLogger('BeaconClient')
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': f'{agent_name}/{agent_version}'})
        self.last_login = 0
        self.login_timeout = 600
        
        self.heartbeat_interval = 60
        self.heartbeat_thread = None
        self.heartbeat_running = False
        
        self.system_info = self._collect_system_info()

    def _collect_system_info(self):
        try:
            return {
                'hostname': socket.gethostname(),
                'ipAddress': socket.gethostbyname(socket.gethostname()),
                'osType': platform.system(),
                'osVersion': platform.version(),
                'username': getpass.getuser(),
                'agentName': self.agent_name,
                'agentVersion': self.agent_version
            }
        except Exception as e:
            self.logger.error(f"Failed to collect system info: {e}")
            return {
                'hostname': 'unknown',
                'ipAddress': '0.0.0.0',
                'osType': 'unknown',
                'osVersion': 'unknown',
                'username': 'unknown',
                'agentName': self.agent_name,
                'agentVersion': self.agent_version
            }

    def login(self):
        """JWT 토큰을 획득하고 에이전트를 등록합니다."""
        if not self._authenticate():
            return False
        
        if not self._register_agent():
            self.logger.warning("Agent registration failed, but will continue with auth token")
        
        self._start_heartbeat()
        return True

    def _authenticate(self):
        """JWT 토큰을 획득합니다."""
        url = f"{self.server_url}/api/auth/login"
        payload = {
            "username": self.username,
            "password": self.password
        }
        try:
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                self.token = response.json().get('token')
                self.logger.info("Successfully authenticated with Beacon server.")
                self.last_login = time.time()
                return True
            else:
                self.logger.error(f"Login failed: {response.status_code} - {response.text}")
        except Exception as e:
            self.logger.error(f"Error during login: {e}")
        return False

    def _register_agent(self):
        """에이전트를 서버에 등록합니다."""
        url = f"{self.server_url}/api/agents/register"
        payload = {
            'agentName': self.system_info['agentName'],
            'hostname': self.system_info['hostname'],
            'ipAddress': self.system_info['ipAddress'],
            'osType': self.system_info['osType'],
            'osVersion': self.system_info['osVersion'],
            'agentVersion': self.system_info['agentVersion'],
            'username': self.system_info['username'],
            'metadata': json.dumps({'platform': platform.platform()})
        }
        
        try:
            response = requests.post(url, json=payload, headers=self._get_headers(), timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    self.logger.info(f"Agent registered: {data.get('agentName')} (ID: {data.get('agentId')})")
                    return True
            else:
                self.logger.error(f"Agent registration failed: {response.status_code} - {response.text}")
        except Exception as e:
            self.logger.error(f"Error during agent registration: {e}")
        return False

    def _send_heartbeat(self):
        """Heartbeat를 서버에 전송합니다."""
        url = f"{self.server_url}/api/agents/heartbeat"
        payload = {
            'agentName': self.agent_name
        }
        
        try:
            response = requests.post(url, json=payload, headers=self._get_headers(), timeout=5)
            if response.status_code == 200:
                self.logger.debug("Heartbeat sent successfully")
                return True
            else:
                self.logger.warning(f"Heartbeat failed: {response.status_code}")
        except Exception as e:
            self.logger.debug(f"Heartbeat error: {e}")
        return False

    def _start_heartbeat(self):
        """Heartbeat 스레드를 시작합니다."""
        if self.heartbeat_running:
            return
        
        self.heartbeat_running = True
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()
        self.logger.info(f"Heartbeat thread started (interval: {self.heartbeat_interval}s)")

    def _heartbeat_loop(self):
        """Heartbeat를 주기적으로 전송합니다."""
        while self.heartbeat_running:
            time.sleep(self.heartbeat_interval)
            if not self._send_heartbeat():
                if not self.token or (time.time() - self.last_login) > self.login_timeout:
                    self.logger.info("Re-authenticating due to heartbeat failure")
                    self._authenticate()

    def stop_heartbeat(self):
        """Heartbeat 스레드를 중지합니다."""
        self.heartbeat_running = False
        if self.heartbeat_thread:
            self.heartbeat_thread.join(timeout=2)
            self.logger.info("Heartbeat thread stopped")

    def _get_headers(self):
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['Authorization'] = f"Bearer {self.token}"
        return headers

    def _normalize_event(self, event_data):
        """SecurityEvent 엔티티의 필수 필드를 채우고 metadata를 JSON 문자열로 변환합니다."""
        normalized = dict(event_data)

        # metadata가 dict이면 JSON 문자열로 직렬화 (Java 엔티티의 String 타입과 일치시킴)
        if isinstance(normalized.get('metadata'), dict):
            normalized['metadata'] = json.dumps(normalized['metadata'], ensure_ascii=False)

        # 필수 필드 기본값 채우기
        normalized.setdefault('sourceIp', self.system_info.get('ipAddress', '127.0.0.1'))
        normalized.setdefault('protocol', 'UNKNOWN')
        normalized.setdefault('port', 0)
        normalized.setdefault('status', 'DETECTED')

        return normalized

    def send_event(self, event_data, endpoint="/api/security-events"):
        """보안 이벤트를 전송합니다. 실패 시 자동 재연결 및 재시도합니다."""
        url = f"{self.server_url}{endpoint}"
        max_retries = 3
        payload = self._normalize_event(event_data)

        for attempt in range(max_retries):
            try:
                if not self.token:
                    if not self._authenticate():
                        time.sleep(2 ** attempt)
                        continue

                response = requests.post(url, json=payload, headers=self._get_headers(), timeout=10)
                
                if response.status_code in [200, 201]:
                    self.logger.debug(f"Data successfully sent to {endpoint}")
                    return True
                elif response.status_code == 401:
                    self.logger.warning("Token expired or invalid, attempting re-login.")
                    self.token = None
                    if self._authenticate():
                        continue
                else:
                    self.logger.error(f"Failed to send data to {endpoint}: {response.status_code} - {response.text}")
            except Exception as e:
                self.logger.error(f"Error sending data (attempt {attempt + 1}/{max_retries}) to {endpoint}: {e}")
            
            time.sleep(2 ** attempt)
        return False

    def send_traffic(self, traffic_data):
        """트래픽 로그를 전송합니다."""
        return self.send_event(traffic_data, endpoint="/api/traffic")
