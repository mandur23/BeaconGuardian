import logging
from firewall.wfas_applier import WindowsFirewallApplier

class LocalBlockController:
    """
    비정상 징후 탐지 시 로컬에서 네트워크를 즉시 차단하거나 해제하는 기능을 제공합니다.
    """
    RULE_ID_EMERGENCY = 9999    # 전체 차단용
    RULE_ID_SPECIFIC_IP = 9998  # 특정 IP 차단용
    
    def __init__(self, rule_prefix="BeaconGuardian/"):
        self.logger = logging.getLogger("LocalBlockController")
        self.applier = WindowsFirewallApplier(rule_name_prefix=rule_prefix)

    def block_network(self, remote_ip="Any", reason="Security anomaly"):
        """네트워크 차단 규칙 적용 (Any 또는 특정 IP)"""
        if not self.applier.is_supported():
            self.logger.error("이 운영체제에서는 로컬 차단 기능을 지원하지 않습니다.")
            return False
            
        rule_id = self.RULE_ID_SPECIFIC_IP if remote_ip != "Any" else self.RULE_ID_EMERGENCY
        self.logger.warning(f"네트워크 차단 실행 ({remote_ip}): {reason}")
        
        rule = {
            "ruleId": rule_id,
            "action": "block",
            "direction": "outbound",
            "remoteAddresses": [remote_ip],
            "enabled": True,
            "displayName": f"BG Block ({remote_ip}): {reason}",
            "protocol": "any"
        }
        
        err = self.applier._upsert_rule(rule)
        if err:
            self.logger.error(f"차단 규칙 적용 실패: {err}")
            return False
            
        self.logger.info(f"네트워크 차단 완료: {remote_ip}")
        return True

    def unblock_network(self, rule_id=None):
        """차단 규칙 제거 (기본값은 전체/특정 IP 모두 시도)"""
        if not self.applier.is_supported():
            return False
            
        ids_to_remove = [rule_id] if rule_id else [self.RULE_ID_EMERGENCY, self.RULE_ID_SPECIFIC_IP]
        
        success = True
        for rid in ids_to_remove:
            err = self.applier._remove_rule(rid)
            if err:
                # 규칙이 없어서 발생하는 에러는 무시
                pass
        
        self.logger.info("선택된 네트워크 차단이 해제되었습니다.")
        return True

    def is_blocked(self):
        """차단 규칙이 하나라도 활성화되어 있는지 확인"""
        ids, _ = self.applier.list_managed_rule_ids()
        return (self.RULE_ID_EMERGENCY in ids) or (self.RULE_ID_SPECIFIC_IP in ids)
