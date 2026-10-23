# SFTP Manager v0.7.5

This is my SFTP Manager project for IT610. The project consists of a Windows application that connects to an SFTP server running through Docker on a Debian 13 virtual machine.

I've already compiled the Windows application into an EXE, so there's no need to install Python or build the application yourself. I also included the Dockerfile and source code so you can recreate the server on your own VM and look through how the application was made.

## 1. Running the Windows Application

To open the application, go to:

`SFTP Manager/`

Then run `SFTP Manager.exe`.

Just make sure to keep the `_internal` folder in the same location as the EXE, since the application needs those files to run properly.

The application should open even if the server isn't running yet, but you won't be able to transfer files until the server is set up.

## 2. Setting Up the SFTP Server

For my setup, I used Debian 13 as the operating system inside VirtualBox and ran the SFTP server through Docker.

You'll need Docker Engine installed on the Debian VM before starting. If you don't have it installed already, here's the official guide I used as a reference:

https://docs.docker.com/engine/install/debian/

Once Docker is installed, copy the `docker-sftp-server` folder into your Debian VM.

Open a terminal and navigate to the folder containing the Dockerfile.

Run these commands:

```bash
docker build -t my-sftp-server:1.0 .

mkdir -p ~/docker-sftp-data

docker run -d --name sftp-server --restart unless-stopped \
  -p 2223:22 \
  -v "$HOME/docker-sftp-data:/home/sftpuser/uploads" \
  my-sftp-server:1.0
```

This builds the Docker image and starts the SFTP server. The uploads folder is stored outside the container so that files won't disappear if the container is restarted or recreated.

Next, run the following commands to give the SFTP account permission to use the uploads folder:

```bash
uid=$(docker exec sftp-server id -u sftpuser)
gid=$(docker exec sftp-server id -g sftpuser)

sudo chown "$uid:$gid" ~/docker-sftp-data
```

After that, set a password for the SFTP account:

```bash
docker exec -it sftp-server passwd sftpuser
```

You'll use this password later when connecting through the Windows application.

To make sure the container is running, enter:

```bash
docker ps
```

You should see a container named `sftp-server` with port `2223` mapped to port `22`.

If you've already created the container before, you can start it again using:

```bash
docker start sftp-server
```

You don't need to rebuild the Docker image every time you start the VM.

## 3. Setting Up VirtualBox Port Forwarding

Since the Windows application is running outside the VM, you'll need to set up port forwarding so it can reach the Docker container.

In VirtualBox, select your Debian VM and go to:

**Settings > Network > Adapter 1 > NAT > Port Forwarding**

Add the following rule:

| Setting | Value |
|---|---|
| Host IP | `127.0.0.1` |
| Host Port | `2223` |
| Guest IP | Your Debian VM's IP address |
| Guest Port | `2223` |
| Protocol | TCP |

To find your Debian VM's IP address, run:

```bash
hostname -I
```

In my setup, the VM address was `10.0.2.15`, but yours may be different. You can also leave the Guest IP field blank if VirtualBox allows it.

Make sure port `2223` isn't already being used by something else on Windows.

## 4. Connecting and Testing the Application

Once the Docker server is running and VirtualBox is configured, open SFTP Manager on Windows.

Use the following connection details:

- **Host:** `127.0.0.1`
- **Port:** `2223`
- **Username:** `sftpuser`
- **Password:** The password you created earlier

Click **Connect**.

If everything is set up correctly, the application should connect to the SFTP server running inside the VM.

To test it, try uploading a small text file through the application.

You can check whether the file was uploaded by going back to the Debian terminal and running:

```bash
ls -la ~/docker-sftp-data
```

If the file appears there, the upload worked.

You can also try downloading the file back through SFTP Manager to test the download feature.

## 5. Optional: Remote Docker Management

I also added a feature that allows the application to connect to Docker remotely through SSH.

This isn't required for regular SFTP transfers, but it's there if you want to test the Docker management portion of the application.

To use it, add another VirtualBox port forwarding rule:

| Setting | Value |
|---|---|
| Host IP | `127.0.0.1` |
| Host Port | `2222` |
| Guest IP | Your Debian VM's IP address |
| Guest Port | `22` |
| Protocol | TCP |

For this connection, use your normal Debian username and password rather than `sftpuser`.

The Debian account needs SSH access and permission to manage Docker containers. The `sftpuser` account is only meant for file transfers, so it won't work for remote Docker commands.

## 6. Files Included

I kept the package fairly simple and removed most of the extra build and setup scripts since the Windows application is already compiled.

Here's what's included:

- **SFTP Manager/** - The Windows EXE and the files it needs to run.
- **Source/** - The Python source code and application files.
- **docker-sftp-server/** - The Dockerfile used to create the SFTP server.
- **README.md** - The instructions you're reading now.

## Final Notes

I built and tested this project using Windows 11 as the host and Debian 13 VM running through VirtualBox.

The server uses password authentication to make it easier to set up and test locally. It isn't intended to be exposed directly to the internet without additional security changes and still very much a work in progress.

For this project, the main goal was to get the Windows client communicating with a Docker-based SFTP server, while also including some additional features for managing Docker remotely.

Jonathan Lachman
10/23/26