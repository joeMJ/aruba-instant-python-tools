@echo off
rem ============================================================================
rem  Aruba Instant Python Tools - Windows-Setup
rem  Prueft Python (ab 3.9), installiert es bei Bedarf (nur fuer den aktuellen
rem  Benutzer, kein Admin noetig), kopiert die Toolsammlung in einen
rem  Installationsordner (aus dem Ordner dieser setup.bat, sonst Download von
rem  GitHub), installiert die Python-Bibliotheken und legt eine
rem  Desktop-Verknuepfung an.
rem  Erneutes Ausfuehren aktualisiert die Tools; config.json, Logs und
rem  gespeicherte Zugangsdaten bleiben erhalten.
rem  Lies dieses Skript, bevor du es ausfuehrst: es kann Dateien aus dem Internet laden.
rem ============================================================================
setlocal EnableExtensions EnableDelayedExpansion
title Aruba Instant Python Tools - Setup

set "REPO_ZIP=https://github.com/joeMJ/aruba-instant-python-tools/archive/refs/heads/main.zip"
set "PY_VERSION=3.12.10"
set "DEFAULT_DIR=%USERPROFILE%\ArubaInstantTools"
set "WORK=%TEMP%\aruba_tools_setup"
set "HERE=%~dp0"

echo.
echo ==== Aruba Instant Python Tools - Setup ====
echo.
echo Dieses Skript
echo   1. prueft, ob Python 3.9 oder neuer vorhanden ist
echo      (sonst Installation von Python %PY_VERSION% von python.org),
echo   2. kopiert die Toolsammlung in den Installationsordner
echo      (aus dem Ordner dieser setup.bat, sonst Download von GitHub),
echo   3. installiert die benoetigten Python-Bibliotheken.
echo.
echo Es sind keine Administratorrechte noetig.
echo.

rem ---- Zielordner -----------------------------------------------------------
set "TARGET="
set /p "TARGET=Installationsordner [%DEFAULT_DIR%]: "
if not defined TARGET set "TARGET=%DEFAULT_DIR%"
set "TARGET=%TARGET:"=%"
if "%TARGET:~-1%"=="\" set "TARGET=%TARGET:~0,-1%"
echo.
echo Zielordner: "%TARGET%"
echo (Hier liegen die Tools, config.json und alle Logs/Ergebnisordner. Der Ordner muss beschreibbar sein.)
echo.

rem ---- Python suchen ----------------------------------------------------------
set "PYCMD="
for %%C in ("py -3" "python") do (
    if not defined PYCMD (
        %%~C -c "import sys; sys.exit(0 if sys.version_info>=(3,9) else 1)" >nul 2>&1 && set "PYCMD=%%~C"
    )
)
if defined PYCMD (
    echo Python gefunden: 
    %PYCMD% --version
    goto :have_python
)

echo Es wurde kein Python 3.9 oder neuer gefunden.
echo.
choice /c JN /n /m "Python %PY_VERSION% jetzt von python.org herunterladen und fuer diesen Benutzer installieren? [J/N] "
if errorlevel 2 (
    echo.
    echo Bitte Python manuell installieren: https://www.python.org/downloads/windows/
    echo ^(Beim Installer "Add python.exe to PATH" aktivieren.^) Danach setup.bat erneut starten.
    start "" "https://www.python.org/downloads/windows/"
    goto :end_fail
)

rem ---- Python-Installer herunterladen und pruefen --------------------------
if not exist "%WORK%" mkdir "%WORK%"
set "PY_FILE=python-%PY_VERSION%-amd64.exe"
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "PY_FILE=python-%PY_VERSION%-arm64.exe"
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" if not defined PROCESSOR_ARCHITEW6432 set "PY_FILE=python-%PY_VERSION%.exe"
set "PY_URL=https://www.python.org/ftp/python/%PY_VERSION%/%PY_FILE%"
set "PY_EXE=%WORK%\%PY_FILE%"

echo.
echo Lade %PY_URL% ...
call :download "%PY_URL%" "%PY_EXE%" || goto :end_fail

echo Pruefe die digitale Signatur des Installers ...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s = Get-AuthenticodeSignature -LiteralPath '%PY_EXE%'; if ($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -like '*Python Software Foundation*') { exit 0 } else { exit 1 }"
if errorlevel 1 (
    echo FEHLER: Die Signatur des Python-Installers ist ungueltig oder stammt nicht von der Python Software Foundation.
    echo Die Datei wird nicht ausgefuehrt und geloescht.
    del /q "%PY_EXE%" >nul 2>&1
    goto :end_fail
)
echo Signatur ok ^(Python Software Foundation^).

echo Installiere Python %PY_VERSION% ^(nur fuer diesen Benutzer, inkl. PATH und py-Launcher^) - das dauert etwas ...
start "" /wait "%PY_EXE%" /quiet InstallAllUsers=0 PrependPath=1 Include_launcher=1 Include_pip=1 Include_test=0 Shortcuts=0
if errorlevel 1 (
    echo FEHLER: Die Python-Installation ist fehlgeschlagen ^(Code !errorlevel!^).
    goto :end_fail
)
del /q "%PY_EXE%" >nul 2>&1

rem PATH dieses Fensters ist noch alt: Python ueber den Standard-Installationspfad suchen
for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
    if exist "%%~D\python.exe" set PYCMD="%%~D\python.exe"
)
if not defined PYCMD (
    echo FEHLER: Python wurde installiert, aber nicht gefunden. Bitte ein neues Fenster oeffnen und setup.bat erneut starten.
    goto :end_fail
)
echo Python installiert:
%PYCMD% --version
echo.
echo Hinweis: Neue Eingabeaufforderungen kennen Python nach der Installation automatisch ^(PATH^).

:have_python
rem ---- Toolsammlung: aus diesem Ordner oder von GitHub ----------------------
set "SRC="
if exist "%HERE%ap_check.py" if exist "%HERE%requirements.txt" (
    set "SRC=%HERE:~0,-1%"
    echo.
    echo Toolsammlung im Ordner dieser setup.bat gefunden - kein Download noetig.
)
if defined SRC goto :have_tools

if not exist "%WORK%" mkdir "%WORK%"
if exist "%WORK%\tools.zip" del /q "%WORK%\tools.zip"
if exist "%WORK%\extract" rmdir /s /q "%WORK%\extract"
echo.
echo Lade Toolsammlung von GitHub:
echo   %REPO_ZIP%
call :download "%REPO_ZIP%" "%WORK%\tools.zip" || goto :end_fail
powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -LiteralPath '%WORK%\tools.zip' -DestinationPath '%WORK%\extract' -Force"
if errorlevel 1 (
    echo FEHLER: Das ZIP-Archiv konnte nicht entpackt werden.
    goto :end_fail
)
for /d %%D in ("%WORK%\extract\*") do set "SRC=%%~D"
if not defined SRC (
    echo FEHLER: Im ZIP-Archiv wurde kein Projektordner gefunden.
    goto :end_fail
)

:have_tools
rem ---- Dateien in den Zielordner kopieren -----------------------------------
if /i "%SRC%"=="%TARGET%" (
    echo Quelle und Zielordner sind identisch - es wird nichts kopiert.
    goto :after_copy
)
if not exist "%TARGET%" mkdir "%TARGET%"
if not exist "%TARGET%" (
    echo FEHLER: Der Zielordner "%TARGET%" konnte nicht angelegt werden.
    goto :end_fail
)
rem config.json (eigene Conductor-IPs/Schwellenwerte) nie ueberschreiben, nichts loeschen
robocopy "%SRC%" "%TARGET%" /E /XF config.json /XD .git /NFL /NDL /NJH /NJS /NP >nul
if errorlevel 8 (
    echo FEHLER: Das Kopieren in den Zielordner ist fehlgeschlagen.
    goto :end_fail
)
if not exist "%TARGET%\config.json" (
    copy /y "%SRC%\config.json" "%TARGET%\config.json" >nul
    echo config.json angelegt - bitte Conductor-IPs und Schwellenwerte anpassen.
) else (
    copy /y "%SRC%\config.json" "%TARGET%\config.json.neu" >nul
    echo Vorhandene config.json bleibt unveraendert ^(aktuelle Vorlage: config.json.neu^).
)
:after_copy

rem ---- SSH-Kompatibilitaet (paramiko) -------------------------------------------
echo.
echo ---- Verbindung zu aelteren Aruba-Geraeten ----
echo Aeltere Aruba-Access-Points melden sich mit einer aelteren, weniger sicheren
echo Verschluesselung an ^(SSH^). Neue Versionen der Python-Bibliothek "paramiko"
echo unterstuetzen das nicht mehr. Die Tools koennten sich dann NICHT mehr mit den
echo APs verbinden.
echo.
echo Empfehlung: J. Es wird die letzte passende Version ^(paramiko 4.0.0^) installiert.
echo.
echo Hinweis zur Sicherheit: Diese aeltere Verschluesselung gilt als nicht mehr
echo zeitgemaess. Nutze die Tools nur im internen Verwaltungsnetz ^(nicht ueber das
echo Internet^) und halte die Firmware der APs aktuell. Mehr dazu in der README auf
echo GitHub, Abschnitt "SSH-Kompatibilitaet".
echo.
set "PARAMIKO_NEW="
choice /c JN /n /m "Passende Version installieren ^(empfohlen^)? [J/N] "
if errorlevel 2 set "PARAMIKO_NEW=1"

rem ---- Python-Bibliotheken ----------------------------------------------------
echo.
echo Installiere Bibliotheken aus requirements.txt ^(fuer diesen Benutzer^) ...
%PYCMD% -m pip install --user --disable-pip-version-check --upgrade pip >nul 2>&1
%PYCMD% -m pip install --user --disable-pip-version-check -r "%TARGET%\requirements.txt"
if errorlevel 1 (
    echo Installation mit --user fehlgeschlagen, neuer Versuch ohne --user ...
    %PYCMD% -m pip install --disable-pip-version-check -r "%TARGET%\requirements.txt"
    if errorlevel 1 (
        echo FEHLER: Die Bibliotheken konnten nicht installiert werden. Internetzugang/Proxy pruefen.
        goto :end_fail
    )
)
if defined PARAMIKO_NEW (
    echo Installiere die neueste Version ^(Achtung: aeltere Aruba-Geraete werden damit voraussichtlich nicht erreicht^) ...
    %PYCMD% -m pip install --user --disable-pip-version-check --upgrade paramiko
)
%PYCMD% -c "import paramiko; print('paramiko', paramiko.__version__)"
%PYCMD% -c "import paramiko, keyring, Crypto, requests, bs4" >nul 2>&1
if errorlevel 1 (
    echo FEHLER: Nicht alle Bibliotheken lassen sich importieren.
    goto :end_fail
)

rem ---- Desktop-Verknuepfung ----------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -Command "$w = New-Object -ComObject WScript.Shell; $l = $w.CreateShortcut([Environment]::GetFolderPath('Desktop') + '\Aruba Instant Tools.lnk'); $l.TargetPath = '%TARGET%\start-tools.bat'; $l.WorkingDirectory = '%TARGET%'; $l.Save()" >nul 2>&1

rem ---- Aufraeumen ---------------------------------------------------------------
if exist "%WORK%" rmdir /s /q "%WORK%" >nul 2>&1

echo.
echo ============================================================
echo  Fertig.
echo.
echo  Starten:  Desktop-Verknuepfung "Aruba Instant Tools"
echo            oder "%TARGET%\start-tools.bat"
echo            oder eine beliebige Eingabeaufforderung/PowerShell
echo            im Installationsordner
echo  Dort z. B.:  py ap_check.py 10.1.1.1 --log
echo.
echo  Alle Logs und Ergebnisordner entstehen in:
echo     %TARGET%
echo  Einstellungen: %TARGET%\config.json
echo  Aktualisieren: setup.bat erneut ausfuehren.
echo ============================================================
echo.
pause
endlocal
exit /b 0

:end_fail
echo.
echo Setup abgebrochen.
echo.
pause
endlocal
exit /b 1

rem ---- Unterprogramm: Datei per HTTPS herunterladen ---------------------------
:download
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $ProgressPreference = 'SilentlyContinue'; try { Invoke-WebRequest -UseBasicParsing -Uri '%~1' -OutFile '%~2' } catch { Write-Host $_.Exception.Message; exit 1 }"
if errorlevel 1 (
    echo FEHLER: Download fehlgeschlagen: %~1
    exit /b 1
)
exit /b 0
