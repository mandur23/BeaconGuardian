import logging

class ActiveResponseManager:
    """
    실시간 보안 이벤트(Suricata, Wazuh 등)의 위험도를 분석하여 
    IP 차단이나 프로세스 제어 등의 능동적인 대응을 결정하고 수행합니다.
    """
    def __init__(self, config, block_controller):
        self.config = config.get('active_response', {})
        self.block_controller = block_controller
        self.logger = logging.getLogger('ActiveResponseManager')
        self.enabled = self.config.get('enabled', False)
        
        # 차단 임계치 설정 (기본값: 수리카타 Severity 1, 와주 Level 12)
        self.suri_min_sev = self.config.get('suricata_block_severity', 1)
        self.wazuh_min_lvl = self.config.get('wazuh_block_level', 12)
        
        # 오차단 방지를 위한 화이트리스트 (자신, 루프백 등)
        self.whitelist = ["127.0.0.1", "::1", "0.0.0.0"]

    def evaluate_and_respond(self, event):
        """
        수신된 이벤트를 분석하여 대응 정책에 맞을 경우 차단을 수행합니다.
        :return: 수행된 액션 태그 (None, "BLOCK_IP", "BLOCK_ALL")
        """
        if not self.enabled or not self.block_controller:
            return None

        # 1. 수리카타(네트워크) 위협 대응
        if self._check_suricata(event):
            src_ip = event.get('src_ip')
            if src_ip and src_ip not in self.whitelist:
                sig = event.get('alert', {}).get('signature', 'Unknown Attack')
                reason = f"[ActiveResponse] Suricata Alert: {sig}"
                self.logger.critical(f"⚠️ 수리카타 긴급 위협! 공격자 IP 차단: {src_ip}")
                if self.block_controller.block_network(remote_ip=src_ip, reason=reason):
                    return "BLOCK_IP"

        # 2. 와주(EDR/호스트) 위협 대응
        if self._check_wazuh(event):
            metadata = event.get('metadata', {})
            lvl = metadata.get('level', 0)
            desc = event.get('summary', 'Critical Host Anomaly')
            
            self.logger.critical(f"⚠️ 와주 치명적 위협 탐지 (Lv.{lvl}): {desc}")
            
            # 와주 경보에 포함된 IP가 있다면 해당 IP 차단, 
            # 그렇지 않다면 시스템 보호를 위해 비상 전체 차단 고려 (설정에 따라)
            # 현재는 로그 기반 IP 추출 로직이 복잡하므로 일단 로그 기록 후 대응
            return "WAZUH_RESPONSE"

        return None

    def _check_suricata(self, event):
        """수리카타 알람의 위험도가 임계치를 넘었는지 확인"""
        if event.get('event_type') == 'alert':
            sev = event.get('alert', {}).get('severity', 99)
            return sev <= self.suri_min_sev
        return False

    def _check_wazuh(self, event):
        """와주 알람의 위험도가 임계치를 넘었는지 확인"""
        if event.get('eventType') == 'WAZUH_ALERT':
            lvl = event.get('metadata', {}).get('level', 0)
            return lvl >= self.wazuh_min_lvl
        return False
