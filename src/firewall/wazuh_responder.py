import sys
import json
import logging
from firewall.local_block_controller import LocalBlockController

# Wazuh 전용 로그 설정
logging.basicConfig(
    filename='logs/wazuh_response.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)
logger = logging.getLogger("WazuhResponder")

def main():
    """
    Wazuh Active Response 입력을 처리합니다.
    형식: JSON { "command": "add" | "delete", ... }
    """
    try:
        # stdin으로부터 Wazuh 명령 읽기
        input_str = sys.stdin.read()
        if not input_str:
            return

        data = json.loads(input_str)
        command = data.get("command")
        
        controller = LocalBlockController()

        if command == "add":
            # 차단 명령
            reason = "Wazuh Active Response"
            alert = data.get("parameters", {}).get("alert", {})
            if alert:
                reason = f"Wazuh Alert {alert.get('id')}: {alert.get('rule', {}).get('description')}"
            
            success = controller.block_network(reason=reason)
            if success:
                logger.info("Wazuh 명령에 의한 네트워크 차단 완료")
            else:
                logger.error("Wazuh 명령 차단 실패")

        elif command == "delete":
            # 해제 명령
            success = controller.unblock_network()
            if success:
                logger.info("Wazuh 명령에 의한 네트워크 해제 완료")
            else:
                logger.error("Wazuh 명령 해제 실패")

    except Exception as e:
        logger.error(f"Wazuh 응답 처리 중 오류: {e}")

if __name__ == "__main__":
    main()
