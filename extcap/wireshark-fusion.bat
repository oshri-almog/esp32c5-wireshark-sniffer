@echo off
rem Start Wireshark with the Fusion widget style.
rem
rem Why: on Windows, Qt's native style draws tick boxes using the system theme, and in dark mode an
rem UNTICKED box has no visible outline - only the tick of an already-ticked row shows. That makes the
rem "Channels to scan" list in the interface options hard to read. Fusion draws tick boxes itself, from
rem the colour palette, so they stay visible in both light and dark mode.
rem
rem Dark mode is kept; only the widget drawing changes.
rem
rem To use this for every Wireshark you start, instead of this shortcut, set a user environment variable:
rem     setx QT_STYLE_OVERRIDE Fusion
rem and to undo that:
rem     reg delete HKCU\Environment /v QT_STYLE_OVERRIDE /f

rem This has to be an environment variable, NOT a "-style Fusion" argument: Wireshark parses the command
rem line itself and reads "-style" as its own "-s" (snapshot length) followed by "tyle", then refuses to
rem start with: The specified snapshot length "tyle" isn't a decimal number.

set "WS=%ProgramW6432%\Wireshark\Wireshark.exe"
if not exist "%WS%" set "WS=%ProgramFiles%\Wireshark\Wireshark.exe"
if not exist "%WS%" (
    echo Could not find Wireshark.exe
    exit /b 1
)
set "QT_STYLE_OVERRIDE=Fusion"
start "" "%WS%" %*
