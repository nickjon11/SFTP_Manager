# SFTP Manager

SFTP Manager is a desktop file transfer application I've been working on for my IT610 project. The main idea was to build a Windows client that can connect to a Linux server, browse files, and transfer them securely without having to use the terminal for everything.

I also wanted to work Docker into the project, so I set up a separate SFTP server inside a Debian 13 VM and added some basic container controls to the client.

**Current version:** v0.8.0

## What it does

- Connects to SFTP servers using SSH
- Lets you browse folders and upload or download files
- Shows transfer activity and connection information
- Includes a Docker page for viewing and managing containers
- Works with local Docker Desktop or Docker on a remote machine over SSH
- Has a retro-style interface with light and dark themes
- Includes a remote SSH Console using the same authenticated connection as SFTP
- Keeps the classic v0.7.5 toolbar button sizing and caps transfer progress at 100%

The application is written in Python. I used PySide6 for the interface and Paramiko for SSH/SFTP. The Docker tools use the Docker CLI.

A couple of things are still unfinished: Docker Hub login isn't available yet, and local Docker Compose management isn't implemented.

## Running it on Windows

I used Python 3.13 for the Windows build.

Open PowerShell in the project folder and run:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

To make the Windows executable, run `build_windows.bat`. The compiled app is placed in the `dist` folder. If you're sharing that build, keep the entire application folder together, including `_internal`.

You don't need Python installed to run the compiled version, but the local Docker features do need Docker Desktop and its command-line tools.

## Setting up the SFTP server in Debian

The Dockerfile is in [`docker-sftp-server/`](docker-sftp-server/). This is the server that I used to test the client from Windows.

On the Debian VM:

```bash
cd docker-sftp-server
docker build -t my-sftp-server:1.0 .
mkdir -p ~/docker-sftp-data
docker run -d --name sftp-server --restart unless-stopped \
  -p 2223:22 \
  -v "$HOME/docker-sftp-data:/home/sftpuser/uploads" \
  my-sftp-server:1.0
```

The uploads folder is mounted from Debian so the files remain there even if the container is restarted. Make sure the directory is writable by `sftpuser`. You can check the account's UID and GID with:

```bash
docker exec sftp-server id sftpuser
```

If needed, set the folder owner using the UID and GID from that command:

```bash
sudo chown UID:GID ~/docker-sftp-data
```

Then set the SFTP account password:

```bash
docker exec -it sftp-server passwd sftpuser
```

### Connecting from Windows

My VM is using VirtualBox NAT networking. I forwarded Windows port **2223** to Debian port **2223**, which Docker then forwards to port **22** inside the container.

In SFTP Manager, I used:

| Setting | Value |
| --- | --- |
| Host | `127.0.0.1` |
| Port | `2223` |
| Username | `sftpuser` |
| Password | Password set inside the container |

Once connected, the upload folder is `/home/sftpuser/uploads`. The same files can be checked on Debian in `~/docker-sftp-data`.

For remote Docker management, use the normal Debian SSH account instead, on Windows port **2222**. The SFTP-only account can't run Docker commands.

## Showing the project

For the demonstration, I build the server image in Debian, start the container, and check it with `docker ps`. Then I open SFTP Manager on Windows and upload a test file. Finally, I go back into Debian and show that the file is in the mounted folder.

I wrote out the steps in [DEMO.md](DEMO.md) so the setup is easier to follow.

## A note about security

This Docker setup is intended for a local class lab, not a public-facing production server. It uses password authentication for testing. If I were deploying it outside the lab, I would use SSH keys, persist the server host keys, and restrict access to the server.

Don't put passwords, private keys, or uploaded personal files in the repository.

## v0.7.9.4 notes

The Console button (between Users and Settings) opens a shell on the computer running SFTP Manager. It does not open a remote terminal on an SFTP-only account. For remote administration, use an authorized SSH account.

The top toolbar uses smaller icons and tighter button sizing on narrower windows, and the Docker controls no longer enforce a wide minimum toolbar. Transfer percentages are limited to 0–100%.

This ZIP contains the updated Python source, **not a rebuilt Windows executable**. To produce a v0.7.9.4 EXE, run `build_windows.bat` on Windows with Python 3.13. Do not relabel the older v0.7.5 executable as v0.7.9.4.

### v0.7.9.4 button sizing
The top toolbar and Docker action buttons use the v0.7.5 sizing again. The Console feature from v0.7.9.4 is retained. Narrow windows may require horizontal scrolling in the Docker action row.


## Remote Console (v0.7.9.4)

Connect using **Connect** first, then select **Console**. The console opens an SSH pseudo-terminal on the same authenticated connection and uses the same remote user permissions. Commands execute on the remote host, not the local computer. Use **Hide input** for password prompts and **Ctrl+C** to interrupt a running command.

Accounts configured for SFTP-only access cannot open a shell. Full-screen terminal programs may not render correctly in the plain-text console; test normal shell commands first. Do not use this feature with untrusted servers or accounts.

The original v0.7.5 toolbar and Docker button sizing has been restored for this test build.

## Remote Console appearance (v0.7.9.4)

Open **Console** after connecting with an SSH account that permits shell access. The Appearance bar offers SFTP Classic (purple/black), Classic Command Prompt, Retro Green, and Purple Terminal themes, font selection, font size, ANSI text colors, blinking cursor preference, subtle border styling, and color presets. These choices are saved between launches.

The remote shell still runs with the connected account’s permissions. The console supports basic ANSI foreground colors, but it is **not a full terminal emulator**: full-screen apps such as `htop`, `nano`, and `vim` may still display incorrectly. The blinking-cursor setting is a saved preference, not full terminal cursor emulation.

## Windows builds with GitHub Actions

Push to `main` or run **Actions → Build Windows Client → Run workflow**.
When the workflow succeeds, download `SFTP_Manager_Windows` from the run's Artifacts section.
For a public release, push a version tag such as `v0.8.0`; the workflow creates a GitHub Release with `SFTP_Manager_Windows.zip`.

The ZIP includes `SFTP Manager.exe` and its `_internal` dependencies. Extract the entire folder before launching.
