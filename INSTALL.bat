@echo off
REM Adds the "Process with Artifact Engine" entry to the Windows right-click
REM menu for the CURRENT USER (no admin required). On Windows 11 it appears
REM under "Show more options". Run UNINSTALL.bat to remove it.
title Artifact Engine - install right-click menu
call "%~dp0aeng.cmd" install-menu
echo.
pause
