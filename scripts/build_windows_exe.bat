@echo off
REM 프로젝트 루트에서 실행: 무콘솔 단일 exe
cd /d "%~dp0.."
py -m pip install pyinstaller -q
py -m PyInstaller --onefile --noconsole --name BeaconGuardian src\agent.py
echo.
echo dist\BeaconGuardian.exe 생성됨 (콘솔 없음)
