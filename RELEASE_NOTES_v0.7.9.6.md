# SFTP Manager v0.7.9.7 — Console launch fix

This patch fixes the PySide6 `AttributeError` when opening the experimental Remote Console in v0.7.9.5. `QPlainTextEdit.ExtraSelection()` has been replaced with `QTextEdit.ExtraSelection()`, the correct PySide6 API.

The existing SSH connection, interactive terminal experiment, appearance controls, Help window, and SFTP navigation remain unchanged.

Build on Windows with `build_windows.bat`, then test the Console, ordinary commands, `htop`, `nano`, and `vim`. Only Python syntax and package integrity were verified here; Windows runtime and interactive terminal behavior still need testing.
