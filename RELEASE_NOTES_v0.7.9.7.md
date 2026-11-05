# SFTP Manager v0.7.9.7 — Interface cleanup

- Removed decorative leading symbols from the main, sidebar, remote console, and Transfer Queue headers.
- Removed the Interactive keys checkbox from the Remote Console. Clicking the terminal continues to focus the command input.
- Preserved SSH shell, terminal display, appearance themes, uptime, help, and file browsing.
- Full-screen programs such as htop, vim, and nano are not guaranteed to accept interactive keystrokes in this build; the separate input box remains the supported command-entry method.
- Windows EXE is built locally using build_windows.bat; GitHub Actions is deferred to v0.8.0.
