@echo off
REM Removes the "Process with Artifact Engine" right-click menu entry
REM (current user). Safe to run even if it was never installed.
title Artifact Engine - remove right-click menu
call "%~dp0aeng.cmd" uninstall-menu
echo.
pause
