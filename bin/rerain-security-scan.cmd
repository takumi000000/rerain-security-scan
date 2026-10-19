@echo off
rem Run scan.py next to this folder (Windows launcher)
where py >nul 2>nul
if %ERRORLEVEL%==0 (
  py -3 "%~dp0..\scan.py" %*
) else (
  python "%~dp0..\scan.py" %*
)
