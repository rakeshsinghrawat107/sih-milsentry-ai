@echo off
title MailSentry AI — National Cyber Defense Server
echo ================================================================
echo  Shielding India's Digital Sovereignty — MailSentry AI v2.0
echo  Starting Enterprise Backend Server (Live DNS, RDAP, GeoIP)
echo ================================================================
cd /d "%~dp0server"
if not exist node_modules (
    echo [Setup] Installing server dependencies...
    "C:\Program Files\nodejs\npm.cmd" install
)
echo [Launch] Launching Node.js production server on http://localhost:3000 ...
"C:\Program Files\nodejs\node.exe" server.js
pause
