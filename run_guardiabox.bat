@echo off
REM ============================================================
REM  run_guardiabox.bat — Lanceur GuardiaBox (double-clic)
REM  Lance l'interface graphique GuardiaBox sans ouvrir
REM  de fenêtre de terminal visible.
REM ============================================================

SET "SCRIPT_DIR=%~dp0"
SET "MAIN=%SCRIPT_DIR%guardiabox\main.py"

REM --- Vérification Python ---
where python >nul 2>&1
IF ERRORLEVEL 1 (
    msgbox "Python n'est pas installé ou introuvable dans le PATH.^nInstallez Python depuis https://www.python.org/"
    GOTO :EOF
)

REM --- Lancement silencieux via pythonw (pas de console) ---
pythonw "%MAIN%"

REM --- Si pythonw échoue, repli sur python standard ---
IF ERRORLEVEL 1 (
    python "%MAIN%"
)
