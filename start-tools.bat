@echo off
rem Startet eine Eingabeaufforderung im Tool-Ordner mit der virtuellen Python-Umgebung.
cd /d "%~dp0"
if not exist ".venv\Scripts\activate.bat" (
    echo Die virtuelle Umgebung fehlt. Bitte zuerst setup.bat ausfuehren.
    pause
    exit /b 1
)
call ".venv\Scripts\activate.bat"
set PYTHONUTF8=1
title Aruba Instant Python Tools
echo.
echo  Aruba Instant Python Tools - Arbeitsordner: %CD%
echo  Beispiele:  py ap_check.py 10.1.1.1 --log
echo              py ap_list.py --help
echo  Logs und Ergebnisordner entstehen in diesem Ordner.
echo.
cmd /k
