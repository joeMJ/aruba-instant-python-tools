@echo off
rem Oeffnet eine Eingabeaufforderung im Tool-Ordner (Arbeitsordner fuer Logs und Ergebnisse).
cd /d "%~dp0"
set PYTHONUTF8=1
title Aruba Instant Python Tools
echo.
echo  Aruba Instant Python Tools - Arbeitsordner: %CD%
echo  Beispiele:  py ap_check.py 10.1.1.1 --log
echo              py ap_list.py --help
echo  Logs und Ergebnisordner entstehen in diesem Ordner.
echo.
cmd /k
