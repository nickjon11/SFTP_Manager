# SFTP Manager v0.7.9.7 — Remote Console refinement (test build)

Based on v0.7.9.4. Preserves SFTP browser history, transfers, Docker management and SSH login.

- Remote Console uses a VT-style terminal screen interpreter (pyte) for interactive output.
- Adds **Interactive keys** mode for htop, nano and vim. Standard command entry remains available.
- Clicking terminal output focuses the command field when Interactive keys is off.
- Sends SSH PTY resize notifications when the Console window is resized.
- Adds **IT610 Project - Jonathan Lachman** footer to Console Help.
- Preserves connection banner, uptime, icons, collapsible Appearance and themes.
- GitHub Actions is **not** part of this test build; it remains planned for v0.8.0.

This source has passed Python syntax compilation. The UI, interactive keys and terminal rendering must be verified on Windows against a live SSH server before release. ANSI color fidelity and some advanced terminal modes may remain limited.
