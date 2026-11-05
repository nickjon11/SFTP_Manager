# IT610 Demonstration Guide

## What the project demonstrates

The project has two separate components: a Python desktop SFTP client on Windows and an OpenSSH-based SFTP server in a Docker container on Debian 13. The server is created from the Dockerfile in `docker-sftp-server/`. VirtualBox forwards Windows port 2223 to the Debian VM, and Docker forwards Debian port 2223 to SSH port 22 inside the container.

**The client does not create the Dockerfile.** The Dockerfile is built and run on the Debian server. SFTP Manager then connects to the running container using the SFTP protocol.

## Presentation sequence

1. **Show the source:** Open `main.py`, `sftp_manager/app.py`, and `docker-sftp-server/Dockerfile` in VS Code. Explain Python, PySide6, Paramiko, and the Docker CLI.
2. **Show the server build:** On Debian, run `cd ~/docker-sftp-server` and `docker build -t my-sftp-server:1.0 .`. If already built, use `docker images` to show the image.
3. **Show the container:** Run `docker ps --filter name=sftp-server` and point out the `2223->22/tcp` port mapping.
4. **Explain the network path:** VirtualBox NAT forwards Windows `127.0.0.1:2223` to Debian `10.0.2.15:2223`; Docker forwards that to container port 22.
5. **Open the client:** Launch `SFTP Manager.exe` on Windows. Connect to `127.0.0.1` port `2223` as `sftpuser` using the lab password.
6. **Transfer a file:** Navigate to `/home/sftpuser/uploads` and upload `presentation-test.txt` using the application's Upload button.
7. **Verify on Debian:** Run `ls -la ~/docker-sftp-data` and `docker exec sftp-server ls -la /home/sftpuser/uploads`. Open the uploaded file to show its contents.
8. **Optional:** Download the file back to Windows. Demonstrate Docker management separately by selecting Remote Docker (SSH) and connecting to the Debian SSH server, or Local Docker Desktop to manage Windows containers.

## What to submit

- GitHub repository with the Python source, Dockerfile, README, and demonstration guide
- GitHub Release ZIP containing the compiled Windows application folder
- Screenshots of the Docker build, `docker ps`, client connection, and successful file transfer
- Optional short screen recording showing the transfer end-to-end

## Suggested explanation

“I built a Windows SFTP client in Python using PySide6 for the interface and Paramiko for encrypted file transfers. I also created a Dockerfile on Debian 13 that installs OpenSSH and runs an SFTP-only account inside a container. Docker and VirtualBox port forwarding make that server accessible to the Windows client. I can upload a file through my own application and verify that it appears in the container and in Debian's persistent storage.”

## Troubleshooting

- `Connection refused`: Check `docker ps`, Docker's port mapping, and VirtualBox's port-forwarding rule.
- `Permission denied`: Confirm that the account is `sftpuser` and the password was set with `docker exec -it sftp-server passwd sftpuser`.
- `No such file`: Use the full remote path `/home/sftpuser/uploads` and confirm the local file exists before uploading.
- Windows port 2222 is typically the VM's own SSH service (`2222->22`); the containerized SFTP service is on Windows port 2223.

## Console appearance test

Connect to your Raspberry Pi, open Console, and try each theme and font size. Run `hostname`, `free -h`, and `ls --color=always`. Close and reopen Console to confirm preferences are saved. Full-screen programs are not supported.
