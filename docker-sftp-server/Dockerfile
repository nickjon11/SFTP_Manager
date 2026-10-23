FROM debian:13-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-server && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /usr/sbin/nologin sftpuser && \
    mkdir -p /home/sftpuser/uploads /run/sshd && \
    chown sftpuser:sftpuser /home/sftpuser/uploads && \
    chmod 700 /home/sftpuser/uploads

RUN printf '\nPasswordAuthentication yes\nPermitRootLogin no\nAllowUsers sftpuser\nMatch User sftpuser\n    ForceCommand internal-sftp\n    AllowTcpForwarding no\n    X11Forwarding no\n' >> /etc/ssh/sshd_config

EXPOSE 22

CMD ["/bin/sh", "-c", "ssh-keygen -A && exec /usr/sbin/sshd -D -e"]
