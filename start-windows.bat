@echo off
cd /d "%~dp0"
if not exist node_modules call npm install
if not exist .env copy .env.example .env
node server.js
pause
