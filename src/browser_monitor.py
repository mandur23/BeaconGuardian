import os
import sqlite3
import tempfile
import threading
import time
import logging
from pathlib import Path
import shutil

class BrowserMonitor(threading.Thread):
    """브라우저 히스토리를 모니터링하여 웹 접속 이력을 추적합니다."""
    
    def __init__(self, callback, interval=30):
        super().__init__()
        self.callback = callback
        self.interval = interval
        self.logger = logging.getLogger('BrowserMonitor')
        self.last_chrome_timestamp = 0
        self.last_edge_timestamp = 0
        self.last_firefox_timestamp = 0
        self.running = True
        self.daemon = True
        
        # 브라우저 히스토리 경로
        self.chrome_history = self._get_chrome_history_path()
        self.edge_history = self._get_edge_history_path()
        self.firefox_history = self._get_firefox_history_path()
        
    def _get_chrome_history_path(self):
        """Chrome 히스토리 파일 경로"""
        appdata = os.getenv('LOCALAPPDATA')
        if appdata:
            return os.path.join(appdata, 'Google', 'Chrome', 'User Data', 'Default', 'History')
        return None
    
    def _get_edge_history_path(self):
        """Edge 히스토리 파일 경로"""
        appdata = os.getenv('LOCALAPPDATA')
        if appdata:
            return os.path.join(appdata, 'Microsoft', 'Edge', 'User Data', 'Default', 'History')
        return None
    
    def _get_firefox_history_path(self):
        """Firefox 히스토리 파일 경로"""
        appdata = os.getenv('APPDATA')
        if appdata:
            firefox_dir = os.path.join(appdata, 'Mozilla', 'Firefox', 'Profiles')
            if os.path.exists(firefox_dir):
                for profile in os.listdir(firefox_dir):
                    places_db = os.path.join(firefox_dir, profile, 'places.sqlite')
                    if os.path.exists(places_db):
                        return places_db
        return None
    
    @staticmethod
    def _open_history_db(history_path):
        """브라우저 히스토리 DB를 읽기 전용으로 열기. 실패 시 임시 복사본 폴백."""
        # 먼저 읽기 전용 URI로 시도 (파일 복사 불필요)
        uri = f"file:{history_path}?mode=ro&nolock=1"
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=3)
            conn.execute("SELECT 1 FROM urls LIMIT 1")
            return conn, None
        except Exception:
            pass

        # 잠김 등 실패 시 임시 파일로 복사
        fd, temp_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            shutil.copy2(history_path, temp_path)
            conn = sqlite3.connect(temp_path, timeout=3)
            return conn, temp_path
        except Exception:
            os.remove(temp_path)
            raise

    def _read_chrome_history(self):
        """Chrome/Edge 히스토리 읽기"""
        events = []

        for browser_name, history_path in [
            ('Chrome', self.chrome_history),
            ('Edge', self.edge_history)
        ]:
            if not history_path or not os.path.exists(history_path):
                continue

            temp_path = None
            try:
                conn, temp_path = self._open_history_db(history_path)
                cursor = conn.cursor()

                last_ts = self.last_chrome_timestamp if browser_name == 'Chrome' else self.last_edge_timestamp

                cursor.execute(
                    "SELECT url, title, visit_count, last_visit_time "
                    "FROM urls "
                    "WHERE last_visit_time > ? "
                    "ORDER BY last_visit_time DESC "
                    "LIMIT 100",
                    (last_ts,),
                )
                rows = cursor.fetchall()

                for row in rows:
                    url, title, visit_count, visit_time = row

                    # Chrome 타임스탬프 변환 (마이크로초 -> Unix 타임)
                    unix_time = (visit_time / 1000000) - 11644473600

                    events.append({
                        "eventType": "WEB_VISIT",
                        "severity": "low",
                        "description": f"{browser_name} 웹 방문: {url}",
                        "metadata": {
                            "browser": browser_name,
                            "url": url,
                            "title": title if title else "No Title",
                            "visit_count": visit_count,
                            "timestamp": unix_time
                        }
                    })

                    # 최신 타임스탬프 업데이트
                    if browser_name == 'Chrome':
                        self.last_chrome_timestamp = max(self.last_chrome_timestamp, visit_time)
                    else:
                        self.last_edge_timestamp = max(self.last_edge_timestamp, visit_time)

                conn.close()

            except Exception as e:
                self.logger.error(f"Error reading {browser_name} history: {e}")
            finally:
                if temp_path and os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except OSError:
                        pass

        return events
    
    def _read_firefox_history(self):
        """Firefox 히스토리 읽기"""
        events = []

        if not self.firefox_history or not os.path.exists(self.firefox_history):
            return events

        temp_path = None
        try:
            conn, temp_path = self._open_history_db(self.firefox_history)
            cursor = conn.cursor()

            cursor.execute(
                "SELECT url, title, visit_count, last_visit_date "
                "FROM moz_places "
                "WHERE last_visit_date > ? "
                "ORDER BY last_visit_date DESC "
                "LIMIT 100",
                (self.last_firefox_timestamp,),
            )
            rows = cursor.fetchall()

            for row in rows:
                url, title, visit_count, visit_date = row

                if visit_date:
                    unix_time = visit_date / 1000000

                    events.append({
                        "eventType": "WEB_VISIT",
                        "severity": "low",
                        "description": f"Firefox 웹 방문: {url}",
                        "metadata": {
                            "browser": "Firefox",
                            "url": url,
                            "title": title if title else "No Title",
                            "visit_count": visit_count,
                            "timestamp": unix_time
                        }
                    })

                    self.last_firefox_timestamp = max(self.last_firefox_timestamp, visit_date)

            conn.close()

        except Exception as e:
            self.logger.error(f"Error reading Firefox history: {e}")
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

        return events
    
    def run(self):
        self.logger.info("Browser Monitor thread started.")
        
        # 초기 타임스탬프 설정 (현재 시간 이후만 추적)
        current_time_chrome = int((time.time() + 11644473600) * 1000000)
        self.last_chrome_timestamp = current_time_chrome
        self.last_edge_timestamp = current_time_chrome
        self.last_firefox_timestamp = int(time.time() * 1000000)
        
        while self.running:
            try:
                # Chrome/Edge 히스토리 읽기
                chrome_events = self._read_chrome_history()
                for event in chrome_events:
                    self.callback(event)
                
                # Firefox 히스토리 읽기
                firefox_events = self._read_firefox_history()
                for event in firefox_events:
                    self.callback(event)
                
                if chrome_events or firefox_events:
                    self.logger.info(f"Found {len(chrome_events) + len(firefox_events)} new web visits")
                    
            except Exception as e:
                self.logger.error(f"Error in browser monitor: {e}")
            
            time.sleep(self.interval)
    
    def stop(self):
        self.running = False
