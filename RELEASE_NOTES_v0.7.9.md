# SFTP Manager v0.7.9.4 — Console appearance test build

- Added an Appearance toolbar above the remote SSH console.
- Combined classic Windows Command Prompt styling with the retro SFTP purple theme.
- Added four themes, font choice, font size, four text color presets, reset, ANSI SGR foreground colors, and saved preferences.
- Preserved existing remote SSH authentication and console command execution.
- Kept original toolbar sizing and transfer fixes from v0.7.7.

Limitations: ANSI cursor-positioning/full-screen terminal programs are not emulated. Blinking cursor is a preference only. Windows EXE must be built on Windows with `build_windows.bat`.
