@echo off
setlocal
cd /d "%~dp0"

where uv >nul 2>nul
if errorlevel 1 (
    echo uv was not found. Install it from https://docs.astral.sh/uv/getting-started/installation/
    pause
    exit /b 1
)

if not defined ST_PG_BIN if exist "%ProgramFiles%\PostgreSQL\16\bin\initdb.exe" set "ST_PG_BIN=%ProgramFiles%\PostgreSQL\16\bin"
if not defined ST_PG_BIN (
    echo PostgreSQL 16 or newer is required. Install PostgreSQL, or set ST_PG_BIN to its bin folder.
    echo Example: set ST_PG_BIN=C:\Program Files\PostgreSQL\16\bin
    pause
    exit /b 1
)
if not exist "%ST_PG_BIN%\initdb.exe" (
    echo Could not find initdb.exe in "%ST_PG_BIN%".
    pause
    exit /b 1
)
if not exist "%ST_PG_BIN%\pg_ctl.exe" (
    echo Could not find pg_ctl.exe in "%ST_PG_BIN%".
    pause
    exit /b 1
)

set "PATH=%ST_PG_BIN%;%PATH%"
uv run --locked --no-dev python -m scripts.demo serve
if errorlevel 1 pause
