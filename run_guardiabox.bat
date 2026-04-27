@echo off
REM ============================================================
REM  run_guardiabox.bat — Lanceur GuardiaBox (double-clic)
REM  Lance l'interface graphique GuardiaBox sans ouvrir
REM  de fenêtre de terminal visible.
REM ============================================================

SET "SCRIPT_DIR=%~dp0"
SET "MAIN=%SCRIPT_DIR%guardiabox\main.py"
SET "VENV_PYTHONW=%SCRIPT_DIR%.venv\Scripts\pythonw.exe"
SET "VENV_PYTHON=%SCRIPT_DIR%.venv\Scripts\python.exe"

REM --- Venv Python (prioritaire) ---
IF EXIST "%VENV_PYTHONW%" (
    "%VENV_PYTHONW%" "%MAIN%"
    GOTO :EOF
)
IF EXIST "%VENV_PYTHON%" (
    "%VENV_PYTHON%" "%MAIN%"
    GOTO :EOF
)

REM --- Repli sur Python système ---
where python >nul 2>&1
IF ERRORLEVEL 1 (
    echo Python n'est pas installe ou introuvable dans le PATH.
    echo Installez Python depuis https://www.python.org/
    pause
    GOTO :EOF
)
python "%MAIN%"
