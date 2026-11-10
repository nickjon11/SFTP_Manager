"""Retro SFTP Manager: secure SFTP file browsing and transfers."""
import sys
import os
import stat
import posixpath
import datetime
import time
import threading
import json
import re
import shlex
import subprocess
import shutil
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
from .terminal_view import TerminalView
import paramiko
from PySide6.QtWidgets import QDialog, QFormLayout, QDialogButtonBox, QFileDialog, QInputDialog
from pathlib import Path
from PySide6.QtCore import Qt, QSize, QEvent, QTimer, QDateTime, QThread, Signal, QSettings, QProcess
from PySide6.QtGui import QAction, QIcon, QMovie, QFont, QPainter, QColor, QPen, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
 QLabel, QPushButton, QFrame, QStackedWidget, QTableWidget, QTableWidgetItem,
 QHeaderView, QMessageBox, QLineEdit, QAbstractItemView, QCheckBox, QProgressBar, QComboBox, QTextBrowser, QPlainTextEdit, QTabWidget, QGroupBox, QSpinBox, QScrollArea, QSplitter, QGridLayout, QSizePolicy, QTextEdit, QToolButton, QLayout)


HERE = Path(__file__).resolve().parent
ASSETS = HERE / 'assets'
PAGES = ['Dashboard', 'My Files', 'Transfers', 'Users', 'Activity', 'Docker', 'Settings']
PAGE_ICONS = ['computer', 'folder', 'network', 'users', 'activity', 'docker', 'settings']

def icon(name):
    return QIcon(str(ASSETS / (name + '.png')))

class ConfirmHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, parent):self.parent=parent
    def missing_host_key(self,client,hostname,key):
        fingerprint=':'.join(f'{b:02x}' for b in key.get_fingerprint())
        result=QMessageBox.question(self.parent,'Unknown server host key',
            f'First connection to {hostname}\nKey type: {key.get_name()}\nFingerprint (MD5): {fingerprint}\n\nVerify this fingerprint with your server before trusting it.\nTrust and save this host key?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if result!=QMessageBox.StandardButton.Yes:raise paramiko.SSHException('Host key not trusted')
        client.get_host_keys().add(hostname,key.get_name(),key)
        known=Path.home()/'.ssh'/'known_hosts'
        known.parent.mkdir(parents=True,exist_ok=True)
        client.save_host_keys(str(known))


class SSHDiscoveryWorker(QThread):
    """Bounded TCP reachability check for SSH services on the local IPv4 /24."""
    found = Signal(str, str, int)
    completed = Signal(str)

    def __init__(self, port=22, parent=None):
        super().__init__(parent)
        self.port = port
        self._cancelled = False

    def stop(self):
        self._cancelled = True

    def run(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(('192.0.2.1', 80))  # UDP route lookup; no packet sent
                local_ip = sock.getsockname()[0]
            network = ipaddress.ip_network(local_ip + '/24', strict=False)
            addresses = [str(ip) for ip in network.hosts() if str(ip) != local_ip]
            addresses.insert(0, local_ip)
            def probe(ip):
                if self._cancelled:
                    return None
                try:
                    with socket.create_connection((ip, self.port), timeout=0.4) as conn:
                        conn.settimeout(0.5)
                        try:
                            banner = conn.recv(128)
                        except (socket.timeout, OSError):
                            banner = b''
                        if banner and not banner.startswith(b'SSH-'):
                            return None
                    try:
                        name = socket.gethostbyaddr(ip)[0]
                    except (socket.herror, socket.gaierror, OSError):
                        name = 'SSH server'
                    return name, ip, self.port
                except OSError:
                    return None
            with ThreadPoolExecutor(max_workers=24) as pool:
                futures = [pool.submit(probe, ip) for ip in addresses]
                for future in as_completed(futures):
                    if self._cancelled:
                        break
                    result = future.result()
                    if result:
                        self.found.emit(*result)
            self.completed.emit('Scan cancelled.' if self._cancelled else 'Scan complete.')
        except Exception as exc:
            self.completed.emit(f'Scan unavailable: {exc}')


class NetworkGraph(QWidget):
    """Win98-style graph of bytes/sec transferred by this application (not total NIC traffic)."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.samples = deque([0.0]*65, maxlen=65)
        self.setMinimumHeight(105)
        self.setToolTip('SFTP Manager transfer throughput only; not whole-system network traffic')

    def add_sample(self, value):
        self.samples.append(max(0.0, float(value)))
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor('#030d03'))
        w, h = max(1,self.width()), max(1,self.height())
        painter.setPen(QPen(QColor('#176b1b'), 1))
        for x in range(0,w,16):painter.drawLine(x,0,x,h)
        for y in range(0,h,16):painter.drawLine(0,y,w,y)
        peak = max(1024*1024, max(self.samples,default=0)*1.15)
        points = list(self.samples)
        painter.setPen(QPen(QColor('#00ff4c'), 2))
        for i in range(1,len(points)):
            x0=int((i-1)* (w-1)/max(1,len(points)-1))
            x1=int(i*(w-1)/max(1,len(points)-1))
            y0=int((h-2)*(1-min(points[i-1]/peak,1)))
            y1=int((h-2)*(1-min(points[i]/peak,1)))
            painter.drawLine(x0,y0,x1,y1)
        painter.end()

class DockerSparkline(QWidget):
    """Small retro graph showing recent samples for one Docker metric."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.samples=deque(maxlen=45)
        self.setMinimumHeight(30)
    def add_value(self, value):
        self.samples.append(max(0.0,float(value)))
        self.update()
    def clear(self):
        self.samples.clear();self.last_total=None;self.update()
    def paintEvent(self,event):
        p=QPainter(self)
        p.fillRect(self.rect(),QColor('#0b1411'))
        w,h=self.width(),self.height()
        p.setPen(QPen(QColor('#21472c'),1))
        for x in range(0,w,16):p.drawLine(x,0,x,h)
        for y in range(0,h,16):p.drawLine(0,y,w,y)
        data=list(self.samples)
        if len(data)>1:
            scale=max(1.0,max(data)*1.2)
            p.setPen(QPen(QColor('#21ef76'),2))
            for i in range(1,len(data)):
                p.drawLine(int((i-1)*(w-1)/(len(data)-1)),int((h-2)*(1-data[i-1]/scale)),
                           int(i*(w-1)/(len(data)-1)),int((h-2)*(1-data[i]/scale)))
        p.end()

class TransferWorker(QThread):
    progress = Signal(int,int)
    completed = Signal(str)
    failed = Signal(str)
    def __init__(self, ssh, direction, source, target, parent=None):
        super().__init__(parent)
        self.ssh, self.direction, self.source, self.target = ssh, direction, source, target
        self.pause_event=threading.Event()
        self.cancel_event=threading.Event()
        self.created_new=False
    def run(self):
        channel=None
        try:
            channel=self.ssh.open_sftp()
            def callback(current,total):
                while self.pause_event.is_set() and not self.cancel_event.is_set():
                    time.sleep(0.08)
                if self.cancel_event.is_set():
                    raise InterruptedError('Transfer cancelled')
                self.progress.emit(current,total)
            if self.direction=='Upload':
                try:channel.stat(self.target)
                except IOError:self.created_new=True
                channel.put(self.source,self.target,callback=callback)
            else:
                self.created_new=not os.path.exists(self.target)
                channel.get(self.source,self.target,callback=callback)
            if self.cancel_event.is_set():raise InterruptedError('Transfer cancelled')
            self.completed.emit(self.target)
        except Exception as exc:
            if self.cancel_event.is_set() and self.created_new:
                try:
                    if self.direction=='Upload' and channel:channel.remove(self.target)
                    elif self.direction=='Download' and os.path.isfile(self.target):os.remove(self.target)
                except Exception:pass
            self.failed.emit('Cancelled' if self.cancel_event.is_set() else str(exc))
        finally:
            if channel:
                try:channel.close()
                except Exception:pass

class LocalDockerWorker(QThread):
    """Run Docker commands using the local Docker CLI."""

    finished_command = Signal(str, str, str, int)

    def __init__(self, action, command, parent=None):
        super().__init__(parent)
        self.action = action
        self.command = command

    def run(self):
        if not shutil.which('docker'):
            self.finished_command.emit(
                self.action, '', 'Docker CLI not found. Install Docker Desktop and enable its CLI integration.', 127
            )
            return

        try:
            args = shlex.split(self.command, posix=True)
            if not args or args[0] != 'docker':
                self.finished_command.emit(self.action, '', 'Unsupported local command.', 2)
                return

            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=30,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
            self.finished_command.emit(
                self.action,
                result.stdout[-150000:],
                result.stderr[-12000:],
                result.returncode,
            )
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            self.finished_command.emit(self.action, '', str(exc), 1)


class DockerCommandWorker(QThread):
    finished_command = Signal(str, str, str, int)
    def __init__(self, ssh, operation, command, parent=None):
        super().__init__(parent)
        self.ssh, self.operation, self.command = ssh, operation, command
    def run(self):
        try:
            _, stdout, stderr = self.ssh.exec_command(self.command, timeout=12)
            # Bounded reads: logs and inspect results must not exhaust desktop memory.
            out = stdout.read(262144).decode('utf-8', 'replace')
            err = stderr.read(16384).decode('utf-8', 'replace')
            code = stdout.channel.recv_exit_status()
            self.finished_command.emit(self.operation, out, err, code)
        except Exception as exc:
            self.finished_command.emit(self.operation, '', str(exc), -1)

GETTING_STARTED = """# Getting Started — Configuration

## 1. Prepare Debian 13
Install and enable OpenSSH (`sudo apt install openssh-server` and `sudo systemctl enable --now ssh`). Confirm your account can sign in over SSH.

## 2. Configure VirtualBox networking
For the existing NAT example, forward **Windows 127.0.0.1:2222** to **Debian guest port 22**. Do not expose SSH to the public internet without appropriate security controls.

## 3. Connect from SFTP Manager
Choose **File → Connect to Server**. Enter host `127.0.0.1`, port `2222`, username `virtual11`, and your Debian password. These are examples for the current VM; use your own details on other servers.

## 4. Verify the host key
Compare the SSH server fingerprint with a trusted value from Debian before accepting an unfamiliar host key. Never blindly approve an unexpected change.

## 5. Start transferring
Open **My Files**. Choose **Upload** to send a local file or select a remote file and choose **Download**. Confirm overwrites when prompted.

## Troubleshooting
- **Connection refused:** Verify the VM is running, SSH is active, and port forwarding is correct.
- **Authentication failed:** Verify username, password, and SSH server configuration.
- **Permission denied:** Use a directory owned by your SFTP account; avoid system paths.
- **Host key changed:** Investigate on Debian before trusting a replacement key.
- **Docker unavailable:** Docker may not be installed or the SSH user may lack permission. Do not grant unrestricted Docker access casually.
"""

USER_GUIDE = """# SFTP Manager — User Guide

## Connect and browse
Use **File → Connect to Server** to authenticate to a server. **My Files** lists the remote directory. Double-click folders to open them and use the up arrow to navigate to the parent folder. The search box filters entries in the current directory.

## Upload and download
**Upload** chooses a local file and sends it to the open remote folder. **Download** saves the selected remote file to your computer. Confirm overwrites before replacing files. SFTP encrypts the connection.

## Transfer queue
The Transfer Queue lists running, queued, completed, cancelled, and failed jobs. **Queue** selects a local file for later upload; queued transfers start when the active transfer finishes. **Pause / Resume** temporarily suspends the current transfer without discarding its in-memory session. **Cancel** stops the selected active or waiting transfer. A newly created partial file is removed when possible. Resume is not persistent across application restarts.

## File operations
**New Folder** creates a remote directory. **Edit → Rename** changes the selected item's name. **Edit → Delete** permanently deletes a file or empty folder after confirmation. **File Properties** displays size, ownership IDs, and Unix permissions. Recursive deletion and remote copy/paste are not implemented.

## Dashboard and Activity
The dashboard displays connection state, transfers, and disk capacity when Debian permits the required read-only query. **Activity** records actions performed by this application and can export a local log. It is not a system-wide SSH audit log.

## Docker
The Docker page lists running and stopped containers through the existing authenticated SSH connection. Select a container to inspect it, view its recent logs or a resource snapshot, or start/stop/restart it with confirmation. Docker access is root-equivalent on Debian; use this only with a trusted administrator account. No Docker TCP API is exposed.

## Settings and safe disconnect
Change the purple theme, overwrite confirmation, graph, globe animation, and local logging in **Settings**. Wait for transfers to complete or cancel them before disconnecting. SFTP Manager does not shut down Debian when disconnected.

## Important limitations
The application is an SFTP client, not a complete Linux administration console. Server-wide user management, automated backups, privileged log access, and quota management require separate server-side configuration.
"""

SHORTCUTS = """# Keyboard Shortcuts

The following built-in shortcuts are available in this version:

- **Ctrl+O** — Connect to server
- **Ctrl+U** — Upload file
- **Ctrl+D** — Download selected file
- **Ctrl+N** — New folder
- **F2** — Rename selected file
- **Delete** — Delete selected file
- **Ctrl+A** — Select all file rows
- **F5** — Refresh
- **F1** — User Guide
- **F11** — Fullscreen
"""

class Manager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.preferences = QSettings('IT610', 'SFTP Manager')
        self.dark = self.preferences.value('dark_mode', False, type=bool)
        self.confirm_overwrites = self.preferences.value('confirm_overwrites', True, type=bool)
        self.show_graph = self.preferences.value('show_graph', True, type=bool)
        self.animate_globe = self.preferences.value('animate_globe', True, type=bool)
        self.log_to_file = self.preferences.value('log_to_file', False, type=bool)
        self.activity_events=[]
        self.transfer_worker=None
        self.pending_transfers=[]
        self.transfer_paused=False
        self.transfer_start=0.0
        self.transfer_last_time=0.0
        self.transfer_last_bytes=0
        self.transfer_rate=0.0
        self.console_dialog = None
        self.console_channel = None
        self.storage_summary='N/A'
        self.storage_detail='Storage information unavailable'
        self.connected_host=''
        self.connected_user=''

        self.docker_worker = None
        self.docker_containers = []
        self.docker_stats_history = deque(maxlen=45)
        self.docker_poll = QTimer(self)
        self.docker_poll.timeout.connect(self.docker_poll_stats)
        self.docker_poll.setInterval(3000)
        self.ssh = None
        self.sftp = None
        self.remote_path = '/home'
        self.remote_back_history = []
        self.remote_forward_history = []
        self.remote_entries = []
        self.transfer_history = []
        self.connect_worker = None
        self.setWindowTitle('SFTP Manager v0.8.2 — SFTP Client')
        self.setWindowIcon(QIcon(str(ASSETS / 'app.ico')))
        self.resize(1440, 900)
        self.setMinimumSize(900, 640)
        self.make_ui()
        self.make_menus()
        self.apply_theme()
        self.change_page(1)
        self.record_event('Application started')

    def make_ui(self):
        center = QWidget()
        self.setCentralWidget(center)
        outer = QVBoxLayout(center)
        outer.setContentsMargins(5, 5, 5, 5)
        outer.setSpacing(5)
        self.banner = QLabel('  SFTP MANAGER     /     SFTP CLIENT v0.8.2')
        self.banner.setObjectName('banner')
        self.banner.setMinimumHeight(36)
        outer.addWidget(self.banner)
        toolbar = QFrame()
        toolbar.setObjectName('toolbar')
        tools = QHBoxLayout(toolbar)
        tools.setContentsMargins(6, 3, 6, 3)
        tools.setSpacing(6)
        self.top_tools = []
        for title, ico in [('Upload','upload'), ('Download','download'),
                           ('New Folder','folder'), ('Permissions','permissions'),
                           ('Search','search'), ('Users','users'), ('Console','console_prompt'), ('Settings','settings')]:
            self.top_tools.append(self.tool_button(tools, title, ico))
        tools.addStretch(1)
        self.connect_button = self.tool_button(tools, 'Connect', 'connect')
        self.disconnect_button = self.tool_button(tools, 'Disconnect', 'disconnect')
        self.disconnect_button.setEnabled(False)
        self.top_tools.extend((self.connect_button, self.disconnect_button))
        self.globe_indicator = QFrame()
        self.globe_indicator.setObjectName('globeIndicator')
        self.globe_indicator.setFixedWidth(66)
        globe_layout = QVBoxLayout(self.globe_indicator)
        globe_layout.setContentsMargins(3, 4, 3, 3)
        globe_layout.setSpacing(1)
        globe = QLabel()
        globe.setAlignment(Qt.AlignmentFlag.AlignCenter)
        globe.setFixedHeight(43)
        self.globe_movie = QMovie(str(ASSETS / 'globe.gif'))
        self.globe_movie.setScaledSize(QSize(38, 38))
        globe.setMovie(self.globe_movie)
        self.globe_movie.start()
        self.globe_movie.setPaused(True)
        globe_layout.addWidget(globe)
        self.globe_label = QLabel('OFFLINE')
        self.globe_label.setObjectName('globeLabel')
        self.globe_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        globe_layout.addWidget(self.globe_label)
        tools.addWidget(self.globe_indicator)
        self.connection_timer = QTimer(self)
        self.connection_timer.setSingleShot(True)
        self.connection_timer.timeout.connect(self.end_connection_attempt)
        outer.addWidget(toolbar)
        middle = QHBoxLayout()
        middle.setSpacing(5)
        sidebar = QFrame()
        sidebar.setObjectName('sidebar')
        sidebar.setMinimumWidth(232)
        sl = QVBoxLayout(sidebar)
        sl.setContentsMargins(5, 5, 5, 5)
        sl.setSpacing(3)
        side_title = QLabel('  SFTP MANAGER')
        side_title.setObjectName('sectionTitle')
        side_title.setMinimumHeight(33)
        sl.addWidget(side_title)
        self.nav_buttons=[]
        for idx,name in enumerate(PAGES):
            btn=QPushButton('  '+name)
            btn.setIcon(icon(PAGE_ICONS[idx]))
            btn.setIconSize(QSize(30,30))
            btn.setObjectName('nav')
            btn.setCheckable(True)
            btn.setMinimumHeight(40)
            btn.clicked.connect(lambda checked=False,i=idx:self.change_page(i))
            sl.addWidget(btn)
            self.nav_buttons.append(btn)
        sl.addStretch(1)
        refresh_frame=QFrame()
        refresh_frame.setObjectName('networkBox')
        refresh_layout=QVBoxLayout(refresh_frame)
        refresh_layout.setContentsMargins(5,5,5,5)
        refresh_layout.setSpacing(4)
        self.docker_interval=QComboBox()
        self.docker_interval.addItems(['Off','3 seconds','5 seconds','10 seconds'])
        self.docker_interval.setCurrentIndex(1)
        self.docker_interval.currentIndexChanged.connect(self.docker_monitor_interval)
        refresh_layout.addWidget(QLabel('Docker Auto-Refresh'))
        refresh_layout.addWidget(self.docker_interval)
        refresh_button=QPushButton('Refresh Now')
        refresh_button.setMinimumHeight(38)
        refresh_button.clicked.connect(self.sidebar_refresh)
        refresh_layout.addWidget(refresh_button)
        sl.addWidget(refresh_frame)
        self.docker_metrics={}
        self.sidebar_monitor=QFrame()
        self.sidebar_monitor.setObjectName('networkBox')
        monitor_layout=QVBoxLayout(self.sidebar_monitor)
        monitor_layout.setContentsMargins(5,5,5,5)
        monitor_layout.setSpacing(3)
        monitor_heading=QLabel('System Monitor (Selected Container)')
        monitor_heading.setObjectName('sectionTitle')
        monitor_heading.setWordWrap(True)
        monitor_layout.addWidget(monitor_heading)
        for key in ('CPU','Memory','Disk I/O','Network I/O'):
            metric_header=QFrame()
            metric_header.setObjectName('sectionTitle')
            metric_row=QHBoxLayout(metric_header)
            metric_row.setContentsMargins(6,2,6,2)
            metric_row.addWidget(QLabel(key))
            value=QLabel('—')
            value.setAlignment(Qt.AlignmentFlag.AlignRight)
            metric_row.addWidget(value,1)
            monitor_layout.addWidget(metric_header)
            graph=DockerSparkline()
            graph.setMinimumHeight(29)
            graph.setMaximumHeight(34)
            monitor_layout.addWidget(graph)
            bar=QProgressBar()
            bar.setRange(0,100)
            bar.setValue(0)
            bar.hide()
            self.docker_metrics[key]=(value,bar,graph)
        sl.addWidget(self.sidebar_monitor)
        self.network_box=QFrame()
        self.network_box.hide()
        self.net_title=QLabel('SFTP transfer')
        self.network_graph=NetworkGraph()
        self.network_timer=QTimer(self)
        self.network_timer.timeout.connect(self.network_tick)
        self.network_timer.start(1000)
        bottom=QLabel('  DEBIAN 13  •  SFTP\n  No server connection')
        self.server_note=bottom
        bottom.setObjectName('sideNote')
        bottom.setMinimumHeight(58)
        sl.addWidget(bottom)
        sidebar_scroll=QScrollArea()
        sidebar_scroll.setWidget(sidebar)
        sidebar_scroll.setWidgetResizable(True)
        sidebar_scroll.setFixedWidth(252)
        sidebar_scroll.setFrameShape(QFrame.Shape.NoFrame)
        sidebar_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        sidebar_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        middle.addWidget(sidebar_scroll)
        self.pages=QStackedWidget()
        middle.addWidget(self.pages,1)
        outer.addLayout(middle,1)
        self.status=QLabel('Ready.  |  Not connected')
        self.status.setObjectName('status')
        self.status.setMinimumHeight(25)
        status_row = QHBoxLayout()
        status_row.setSpacing(4)
        status_row.addWidget(self.status, 1)
        self.clock = QLabel()
        self.clock.setObjectName('clock')
        self.clock.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.clock.setMinimumWidth(105)
        status_row.addWidget(self.clock)
        outer.addLayout(status_row)
        self.clock_timer = QTimer(self)
        self.clock_timer.timeout.connect(self.update_clock)
        self.clock_timer.start(1000)
        self.update_clock()
        self.make_pages()

    def update_clock(self):
        self.clock.setText(QDateTime.currentDateTime().toString('h:mm AP'))
        self.clock.setToolTip(QDateTime.currentDateTime().toString('dddd, MMMM d, yyyy'))

    def tool_button(self,layout,title,ico):
        btn=QPushButton(title)
        btn.setObjectName('toolButton')
        btn.setIcon(icon(ico))
        btn.setIconSize(QSize(38,38))
        btn.setMinimumWidth(52)
        btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        btn.clicked.connect(lambda checked=False,n=title:self.toolbar_action(n))
        layout.addWidget(btn)
        return btn

    def toolbar_action(self,name):
        if name=='Connect':self.begin_connection_attempt()
        elif name=='Disconnect':self.disconnect_demo()
        elif name=='Settings':self.change_page(6)
        elif name=='Users':self.change_page(3)
        elif name=='Console':self.open_console()
        elif name=='Search':
            self.change_page(1)
            self.search.setFocus()
        elif name=='Upload':self.upload_file()
        elif name=='Download':self.download_file()
        elif name=='New Folder':self.new_folder()
        elif name=='Permissions':self.show_permissions()
        else:self.demo_action(name)

    def open_console(self):
        transport = self.ssh.get_transport() if self.ssh else None
        if not transport or not transport.is_active():
            QMessageBox.information(self, 'Remote Console',
                'Connect to a server first. The remote SSH account must allow shell access.')
            return
        if self.console_dialog is not None and self.console_dialog.isVisible():
            self.console_dialog.raise_()
            self.console_dialog.activateWindow()
            return

        dialog = QDialog(self)
        dialog.setWindowTitle('SFTP Manager — Remote Console')
        dialog.resize(1180, 780)
        dialog.setMinimumSize(700, 460)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.console_dialog = dialog
        layout = QVBoxLayout(dialog)
        layout.setSpacing(6)

        pref = self.preferences
        # Match the main application's beveled purple banner.
        status_banner = QFrame(dialog)
        status_banner.setObjectName('consoleBanner')
        status_banner.setStyleSheet(
            'QFrame#consoleBanner { background: #380083; '
            'border: 2px outset #a78be0; }'
            'QFrame#consoleBanner QLabel { color: white; border: none; '
            'background: transparent; }')
        top = QHBoxLayout(status_banner)
        top.setContentsMargins(8, 3, 8, 3)
        top.setSpacing(7)
        status = QLabel()
        status.setObjectName('consoleStatus')
        status.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        top.addWidget(status, 1)
        clock_icon = QLabel()
        clock_icon.setPixmap(icon('console_clock').pixmap(QSize(16, 16)))
        top.addWidget(clock_icon)
        uptime = QLabel('Uptime: 00:00:00')
        top.addWidget(uptime)
        help_button = QPushButton('Help')
        help_button.setIcon(icon('console_help'))
        help_button.setAutoDefault(False)
        help_button.setDefault(False)
        help_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        top.addWidget(help_button)
        layout.addWidget(status_banner)

        def show_console_help():
            help_dialog = QDialog(dialog)
            help_dialog.setWindowTitle('About Remote Console')
            help_dialog.setMinimumWidth(460)
            help_layout = QVBoxLayout(help_dialog)
            explanation = QLabel(
                'Remote Console opens an interactive SSH shell on the connected machine.\n\n'
                'Commands and executables run with your SSH account permissions, '
                'not on the computer running SFTP Manager.\n\n'
                'SFTP-only accounts cannot open a shell. Ctrl+C interrupts a running '
                'command. Disconnecting closes the remote terminal.\n\n'
                'Uptime measures this console session, not remote system uptime.')
            explanation.setWordWrap(True)
            help_layout.addWidget(explanation)
            footer = QLabel('IT610 Project - Jonathan Lachman')
            footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
            footer.setStyleSheet('border-top: 1px solid #74639a; padding-top: 9px;')
            help_layout.addWidget(footer)
            close_help = QPushButton('OK')
            close_help.setAutoDefault(False)
            close_help.clicked.connect(help_dialog.accept)
            help_layout.addWidget(close_help, alignment=Qt.AlignmentFlag.AlignRight)
            help_dialog.exec()
        help_button.clicked.connect(show_console_help)

        appearance_toggle = QToolButton()
        appearance_toggle.setText('Appearance')
        appearance_toggle.setArrowType(Qt.ArrowType.RightArrow)
        appearance_toggle.setCheckable(True)
        appearance_toggle.setChecked(False)
        appearance_toggle.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        layout.addWidget(appearance_toggle)
        appearance_panel = QWidget()
        appearance = QHBoxLayout(appearance_panel)
        appearance.setContentsMargins(5, 2, 5, 2)
        appearance.addWidget(QLabel('Theme:'))
        theme = QComboBox()
        theme.addItems(['Default (Purple/Black)', 'Classic Command Prompt',
                        'Green', 'Purple Terminal'])
        saved = str(pref.value('console/theme', 'Default (Purple/Black)'))
        saved = {'SFTP Classic (Purple / Black)': 'Default (Purple/Black)',
                 'Retro Green': 'Green'}.get(saved, saved)
        theme.setCurrentText(saved)
        appearance.addWidget(theme)
        blink = QCheckBox('Blinking cursor')
        blink.setChecked(str(pref.value('console/blink', 'true')).lower() == 'true')
        appearance.addWidget(blink)
        appearance.addStretch()
        appearance_panel.setVisible(False)
        layout.addWidget(appearance_panel)
        def toggle_appearance(expanded):
            appearance_panel.setVisible(expanded)
            appearance_toggle.setArrowType(
                Qt.ArrowType.DownArrow if expanded else Qt.ArrowType.RightArrow)
        appearance_toggle.toggled.connect(toggle_appearance)

        output = TerminalView()
        layout.addWidget(output, 1)
        row = QHBoxLayout()
        entry = QLineEdit()
        entry.setPlaceholderText('Remote command or terminal input...')
        secret = QCheckBox('Hide input')
        send = QPushButton('Send')
        interrupt = QPushButton('Ctrl+C')
        for button in (send, interrupt):
            button.setAutoDefault(False)
            button.setDefault(False)
        row.addWidget(entry, 1)
        row.addWidget(secret)
        row.addWidget(send)
        row.addWidget(interrupt)
        layout.addLayout(row)
        output.focus_command_requested.connect(entry.setFocus)

        palette = {
            'Default (Purple/Black)': ('#09070d', '#f2f2f2', '#49018c'),
            'Classic Command Prompt': ('#000000', '#eeeeee', '#292929'),
            'Green': ('#020b04', '#00ff54', '#164b22'),
            'Purple Terminal': ('#1b102b', '#dfc6ff', '#5b2794'),
        }
        cursor_timer = QTimer(dialog)
        cursor_timer.setInterval(550)
        cursor_state = [False]
        def blink_cursor():
            # The remote shell draws its own cursor; avoid inserting fake characters.
            cursor_state[0] = not cursor_state[0]
            output.set_cursor_visible(cursor_state[0])
        cursor_timer.timeout.connect(blink_cursor)

        def update_appearance():
            bg, fg, accent = palette[theme.currentText()]
            output.setStyleSheet(
                f'QPlainTextEdit {{ background-color: {bg}; color: {fg}; '
                f'border: 3px ridge {accent}; padding: 5px; }}')
            status.setText(
                f'  Remote SSH Terminal: {self.connected_user}@{self.connected_host}'
                '    •    Connected (SSH)')
            # The connection bar keeps the same fixed purple style as
            # the main window, regardless of the selected terminal theme.
            status.setStyleSheet(
                'QLabel { background: transparent; color: white; '
                'border: none; font-weight: bold; }')
            pref.setValue('console/theme', theme.currentText())
            pref.setValue('console/blink', blink.isChecked())
            if blink.isChecked():
                cursor_timer.start()
            else:
                cursor_timer.stop()
                output.set_cursor_visible(True)
        theme.currentTextChanged.connect(update_appearance)
        blink.toggled.connect(update_appearance)
        update_appearance()
        secret.toggled.connect(lambda checked: entry.setEchoMode(
            QLineEdit.EchoMode.Password if checked else QLineEdit.EchoMode.Normal))

        started = time.monotonic()
        uptime_timer = QTimer(dialog)
        def update_uptime():
            seconds = int(time.monotonic() - started)
            uptime.setText(f'Uptime: {seconds // 3600:02d}:'
                           f'{seconds // 60 % 60:02d}:{seconds % 60:02d}')
        uptime_timer.timeout.connect(update_uptime)
        uptime_timer.start(1000)

        try:
            channel = transport.open_session(timeout=8)
            columns, rows = output.dimensions()
            channel.get_pty(term='xterm', width=columns, height=rows)
            channel.invoke_shell()
            self.console_channel = channel
            output.resize_screen(columns, rows)
        except Exception as exc:
            QMessageBox.warning(dialog, 'Remote Console',
                f'Unable to open a remote shell. The account may be SFTP-only.\n\n{exc}')
            uptime_timer.stop()
            dialog.close()
            self.console_dialog = None
            return

        # Debounce resize events so the remote shell receives actual PTY dimensions.
        from PySide6.QtCore import QObject, QEvent
        resize_timer = QTimer(dialog)
        resize_timer.setSingleShot(True)
        resize_timer.setInterval(150)
        def update_dimensions():
            if channel.closed:
                return
            columns, rows = output.dimensions()
            if (columns, rows) != (output.screen.columns, output.screen.lines):
                output.resize_screen(columns, rows)
                try:
                    channel.resize_pty(width=columns, height=rows)
                except (OSError, paramiko.SSHException):
                    pass
        resize_timer.timeout.connect(update_dimensions)
        class ViewportWatcher(QObject):
            def eventFilter(self, obj, event):
                if event.type() == QEvent.Type.Resize:
                    resize_timer.start()
                return False
        watcher = ViewportWatcher(dialog)
        output.viewport().installEventFilter(watcher)

        timer = QTimer(dialog)
        timer.setInterval(60)
        def poll_output():
            try:
                if channel.recv_ready():
                    chunks = []
                    while channel.recv_ready():
                        chunks.append(channel.recv(65536))
                    output.feed(b''.join(chunks).decode('utf-8', errors='replace'))
                if (channel.closed or channel.exit_status_ready() or
                    not self.ssh or not self.ssh.get_transport() or
                    not self.ssh.get_transport().is_active()):
                    timer.stop()
                    uptime_timer.stop()
                    entry.setEnabled(False)
                    send.setEnabled(False)
                    interrupt.setEnabled(False)
            except (OSError, EOFError, paramiko.SSHException):
                timer.stop()
                uptime_timer.stop()
                entry.setEnabled(False)
                send.setEnabled(False)
                interrupt.setEnabled(False)

        def send_input(value):
            if channel.closed:
                return
            try:
                channel.sendall(value)
            except (OSError, paramiko.SSHException):
                pass

        def run_command():
            if channel.closed:
                return
            send_input(entry.text() + '\n')
            entry.clear()
            entry.setFocus()

        def send_interrupt():
            send_input('\x03')

        def cleanup(*_):
            timer.stop()
            cursor_timer.stop()
            uptime_timer.stop()
            resize_timer.stop()
            channel.close()
            if self.console_channel is channel:
                self.console_channel = None
            self.console_dialog = None

        output.input_requested.connect(send_input)
        entry.returnPressed.connect(run_command)
        send.clicked.connect(run_command)
        interrupt.clicked.connect(send_interrupt)
        dialog.finished.connect(cleanup)
        timer.timeout.connect(poll_output)
        timer.start()
        dialog.show()
        entry.setFocus()

    def begin_connection_attempt(self):
        if self.sftp:
            QMessageBox.information(self, 'Connected', 'Already connected. Disconnect first to change servers.')
            return
        dlg = QDialog(self)
        dlg.setWindowTitle('Connect to SFTP Server')
        dlg.resize(900, 420)
        outer = QVBoxLayout(dlg)
        columns = QHBoxLayout()
        outer.addLayout(columns, 1)

        left = QWidget(dlg)
        form = QFormLayout(left)
        host = QLineEdit(self.preferences.value('host','127.0.0.1'))
        port = QLineEdit(self.preferences.value('port','22'))
        username = QLineEdit(self.preferences.value('username','virtual11'))
        password = QLineEdit()
        password.setEchoMode(QLineEdit.EchoMode.Password)
        for label, widget in [('Host / IP',host),('Port',port),('Username',username),('Password',password)]:
            form.addRow(label,widget)
        note = QLabel('VirtualBox NAT example: 127.0.0.1 : 2222\nThe server fingerprint must be approved on first connection.')
        note.setWordWrap(True)
        form.addRow(note)
        # Reuse the application's existing globe GIF as the discovery activity indicator.
        globe_footer = QHBoxLayout()
        discovery_globe = QLabel(left)
        discovery_globe.setFixedSize(48, 48)
        discovery_globe.setAlignment(Qt.AlignmentFlag.AlignCenter)
        discovery_movie = QMovie(str(ASSETS / 'globe.gif'), parent=dlg)
        discovery_movie.setScaledSize(QSize(40, 40))
        discovery_globe.setMovie(discovery_movie)
        discovery_movie.start()
        discovery_movie.setPaused(True)
        discovery_globe_text = QLabel('Ready to scan', left)
        discovery_globe_text.setWordWrap(True)
        globe_footer.addWidget(discovery_globe)
        globe_footer.addWidget(discovery_globe_text, 1)
        form.addRow(globe_footer)
        columns.addWidget(left, 2)

        right = QGroupBox('Network Discovery', dlg)
        discovery_layout = QVBoxLayout(right)
        discovery_layout.addWidget(QLabel('Find reachable SSH/SFTP servers on your local network.'))
        scan_row = QHBoxLayout()
        scan_button = QPushButton('Scan Network')
        refresh_button = QPushButton('Refresh')
        scan_port = QSpinBox()
        scan_port.setRange(1, 65535)
        scan_port.setValue(22)
        scan_port.setPrefix('Port: ')
        scan_row.addWidget(scan_button)
        scan_row.addWidget(refresh_button)
        scan_row.addWidget(scan_port)
        discovery_layout.addLayout(scan_row)
        results = QTableWidget(0, 4)
        results.setHorizontalHeaderLabels(['Device / Hostname', 'IP Address', 'Port', 'Status'])
        results.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        results.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        results.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        results.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        results.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        results.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        results.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        discovery_layout.addWidget(results, 1)
        discovery_footer = QHBoxLayout()
        scan_status = QLabel('Select Scan Network to search your local /24 subnet.')
        scan_status.setWordWrap(True)
        use_selected = QPushButton('Use Selected')
        use_selected.setEnabled(False)
        discovery_footer.addWidget(scan_status, 1)
        discovery_footer.addWidget(use_selected)
        discovery_layout.addLayout(discovery_footer)
        columns.addWidget(right, 3)

        worker_holder = {'worker': None}
        def add_result(name, ip, ssh_port):
            row = results.rowCount()
            results.insertRow(row)
            for col, value in enumerate((name, ip, str(ssh_port), 'SSH Available')):
                results.setItem(row, col, QTableWidgetItem(value))
            scan_status.setText(f'{results.rowCount()} reachable SSH server(s) found.')

        def scan_done(message):
            scan_button.setEnabled(True)
            refresh_button.setEnabled(True)
            scan_status.setText(f'{message} {results.rowCount()} server(s) found.')
            discovery_movie.setPaused(True)
            discovery_globe_text.setText(f'{message}\n{results.rowCount()} server(s) found.')

        def start_scan():
            worker = worker_holder['worker']
            if worker is not None and worker.isRunning():
                return
            results.setRowCount(0)
            use_selected.setEnabled(False)
            scan_button.setEnabled(False)
            refresh_button.setEnabled(False)
            scan_status.setText('Scanning local network...')
            discovery_globe_text.setText('Scanning local network...\nSearching for SSH/SFTP servers...')
            discovery_movie.start()
            discovery_movie.setPaused(False)
            worker = SSHDiscoveryWorker(scan_port.value(), dlg)
            worker_holder['worker'] = worker
            worker.found.connect(add_result)
            worker.completed.connect(scan_done)
            worker.start()

        def select_server():
            row = results.currentRow()
            if row < 0:
                return
            host.setText(results.item(row, 1).text())
            port.setText(results.item(row, 2).text())
            host.setFocus()

        scan_button.clicked.connect(start_scan)
        refresh_button.clicked.connect(start_scan)
        results.itemSelectionChanged.connect(lambda: use_selected.setEnabled(results.currentRow() >= 0))
        results.itemDoubleClicked.connect(lambda _item: select_server())
        use_selected.clicked.connect(select_server)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        def validate_and_accept():
            required = [('Host / IP', host), ('Port', port), ('Username', username), ('Password', password)]
            missing = [(name, field) for name, field in required if not field.text().strip()]
            if missing:
                QMessageBox.warning(dlg, 'Incomplete Connection Information',
                    'Please fill in all required connection fields before pressing OK.\n\n'
                    'Missing: ' + ', '.join(name for name, _ in missing) + '\n\n'
                    'If you do not wish to connect, select Cancel to close this window.')
                missing[0][1].setFocus()
                return
            try:
                value = int(port.text().strip())
                if not 1 <= value <= 65535:
                    raise ValueError()
            except ValueError:
                QMessageBox.warning(dlg, 'Invalid Port', 'Enter a port number between 1 and 65535.')
                port.setFocus()
                return
            dlg.accept()
        buttons.accepted.connect(validate_and_accept)
        buttons.rejected.connect(dlg.reject)
        outer.addWidget(buttons)

        def cleanup_discovery():
            discovery_movie.setPaused(True)
            worker = worker_holder['worker']
            if worker is not None and worker.isRunning():
                worker.stop()
                worker.wait(2500)
        dlg.finished.connect(lambda _code: cleanup_discovery())
        if dlg.exec()!=QDialog.DialogCode.Accepted:return
        try: number=int(port.text())
        except ValueError:
            QMessageBox.warning(self,'Invalid port','Enter a numeric port.');return
        self.globe_movie.setPaused(not self.animate_globe)
        self.globe_label.setText('CONNECTING')
        QApplication.processEvents()
        client=paramiko.SSHClient()
        client.load_system_host_keys()
        try:client.load_host_keys(str(Path.home()/'.ssh'/'known_hosts'))
        except OSError:pass
        client.set_missing_host_key_policy(ConfirmHostKeyPolicy(self))
        try:
            client.connect(hostname=host.text().strip(),port=number,username=username.text().strip(),
                           password=password.text(),timeout=7,auth_timeout=7,banner_timeout=7,
                           look_for_keys=False,allow_agent=False)
            self.sftp=client.open_sftp()
            self.preferences.setValue('host',host.text().strip())
            self.preferences.setValue('port',str(number))
            self.preferences.setValue('username',username.text().strip())
            self.connected_host=f'{host.text().strip()}:{number}'
            self.connected_user=username.text().strip()
            self.ssh=client
            self.remote_path=self.sftp.normalize('.')
            self.remote_back_history.clear()
            self.remote_forward_history.clear()
            self.update_remote_navigation_buttons()
            self.globe_label.setText('ONLINE')
            self.server_note.setText(f'  {host.text()}:{number}\n  Connected as {username.text()}')
            self.connect_button.setEnabled(False)
            self.disconnect_button.setEnabled(True)
            self.refresh_remote()
            self.update_storage()
            self.update_dashboard()
            self.record_event(f'Connected to {self.connected_host} as {self.connected_user}')
            self.change_page(1)
            self.status.setText(f'Connected to {host.text()}:{number} via SFTP')
        except Exception as exc:
            client.close()
            self.ssh=None;self.sftp=None
            self.globe_label.setText('OFFLINE')
            self.record_event('Connection failed: '+str(exc),'ERROR')
            QMessageBox.warning(self,'Connection failed',str(exc))
        finally:self.globe_movie.setPaused(True)

    def end_connection_attempt(self):
        self.globe_movie.setPaused(True)

    def disconnect_demo(self):
        if self.transfer_worker and self.transfer_worker.isRunning():
            QMessageBox.warning(self,'Transfer active','Wait for the current transfer to finish before disconnecting.')
            return
        if self.console_dialog is not None:
            self.console_dialog.close()
        was_connected=bool(self.sftp)
        if self.sftp:
            self.sftp.close();self.sftp=None
        if self.ssh:
            self.ssh.close();self.ssh=None
        self.globe_movie.setPaused(True)
        self.globe_label.setText('OFFLINE')
        self.server_note.setText('  DEBIAN 13  •  SFTP\n  No server connection')
        self.connect_button.setEnabled(True)
        self.disconnect_button.setEnabled(False)
        self.top_tools.extend((self.connect_button, self.disconnect_button))
        self.remote_back_history.clear()
        self.remote_forward_history.clear()
        self.update_remote_navigation_buttons()
        self.location.setText('')
        self.filter_files(self.search.text())
        self.storage_summary='N/A'
        self.storage_detail='Storage information unavailable'
        self.connected_user=''
        self.connected_host=''
        self.update_dashboard()
        if was_connected:self.record_event('Disconnected from SFTP server')
        self.status.setText('Disconnected  |  Connect to a server to access files')

    def refresh_remote(self):
        if not self.sftp:
            self.filter_files(self.search.text());return
        try:
            entries=self.sftp.listdir_attr(self.remote_path)
            self.remote_entries=sorted(entries,key=lambda e:(not stat.S_ISDIR(e.st_mode),e.filename.lower()))
            self.location.setText(self.remote_path)
            self.filter_files(self.search.text())
            self.record_event('Opened '+self.remote_path)
        except Exception as exc:
            self.record_event('Folder error: '+str(exc),'ERROR')
            QMessageBox.warning(self,'Folder error',str(exc))

    def update_remote_navigation_buttons(self):
        self.remote_back_button.setEnabled(bool(self.sftp and self.remote_back_history))
        self.remote_forward_button.setEnabled(bool(self.sftp and self.remote_forward_history))

    def change_remote_directory(self, path, direction='new'):
        if not self.sftp:
            return False
        path = posixpath.normpath(path)
        if path == self.remote_path:
            return True
        previous = self.remote_path
        try:
            entries = self.sftp.listdir_attr(path)
        except Exception as exc:
            self.record_event('Folder error: ' + str(exc), 'ERROR')
            QMessageBox.warning(self, 'Folder error', str(exc))
            return False
        if direction == 'back':
            self.remote_back_history.pop()
            self.remote_forward_history.append(previous)
        elif direction == 'forward':
            self.remote_forward_history.pop()
            self.remote_back_history.append(previous)
        else:
            self.remote_back_history.append(previous)
            self.remote_forward_history.clear()
        self.remote_path = path
        self.remote_entries = sorted(entries, key=lambda e: (not stat.S_ISDIR(e.st_mode), e.filename.lower()))
        self.location.setText(path)
        self.filter_files(self.search.text())
        self.record_event('Opened ' + path)
        self.update_remote_navigation_buttons()
        return True

    def navigate_back(self):
        if self.sftp and self.remote_back_history:
            self.change_remote_directory(self.remote_back_history[-1], 'back')

    def navigate_forward(self):
        if self.sftp and self.remote_forward_history:
            self.change_remote_directory(self.remote_forward_history[-1], 'forward')

    def navigate_up(self):
        if not self.sftp:
            return
        self.change_remote_directory(posixpath.dirname(self.remote_path.rstrip('/')) or '/')

    def open_selected(self):
        if not self.sftp:
            self.demo_action('Open file');return
        row=self.file_table.currentRow()
        if row<0:return
        item=self.file_table.item(row,0)
        if not item:return
        name=item.data(Qt.ItemDataRole.UserRole)
        if not name:return
        entry=next((e for e in self.remote_entries if e.filename==name),None)
        if entry and stat.S_ISDIR(entry.st_mode):
            self.change_remote_directory(posixpath.join(self.remote_path,name))
        else:self.download_file()

    def selected_remote(self):
        row=self.file_table.currentRow()
        if row<0:return None
        item=self.file_table.item(row,0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def add_transfer(self, filename, direction, status):
        row=self.queue.rowCount()
        self.queue.insertRow(row)
        for col,value in enumerate((filename,direction,status,'0%')):
            self.queue.setItem(row,col,QTableWidgetItem(value))
        self.transfer_count+=1
        self.update_dashboard()
        return row

    def start_transfer(self,direction,source,target,display_name,enqueue=False):
        if enqueue or (self.transfer_worker and self.transfer_worker.isRunning()):
            row=self.add_transfer(display_name,direction,'Queued')
            self.pending_transfers.append((direction,source,target,display_name,row))
            self.record_event(f'{direction} queued: {display_name}')
            return
        self._run_transfer(direction,source,target,display_name)

    def _run_transfer(self,direction,source,target,display_name,row=None):
        self.transfer_start=time.monotonic()
        self.transfer_last_time=self.transfer_start
        self.transfer_last_bytes=0
        self.transfer_rate=0.0
        if row is None:row=self.add_transfer(display_name,direction,'Running')
        else:self.queue.item(row,2).setText('Running')
        self.active_queue_row=row
        self.record_event(f'{direction} started: {display_name}')
        self.status.setText(f'{direction}ing {display_name}...')
        self.globe_movie.setPaused(not self.animate_globe)
        worker=TransferWorker(self.ssh,direction,source,target,self)
        self.transfer_worker=worker
        self.update_dashboard()
        def on_progress(current,total):
            now=time.monotonic()
            elapsed=max(now-self.transfer_last_time,0.001)
            if elapsed>=0.15 or current>=total:
                self.transfer_rate=max(0,(current-self.transfer_last_bytes)/elapsed)
                self.transfer_last_bytes=current
                self.transfer_last_time=now
            percent=min(100,max(0,int(100*current/total))) if total>0 else 0
            self.queue.item(row,3).setText(f'{percent}%')
            self.status.setText(f'{direction}: {display_name}  |  {percent}%  |  {self.transfer_rate/1024:.1f} KB/s')
        def on_complete(_):
            self.queue.item(row,2).setText('Complete')
            self.queue.item(row,3).setText('100%')
            self.record_event(f'{direction} completed: {display_name}')
            self.status.setText(f'{direction} completed: {display_name}')
            self.transfer_rate=0
            self.globe_movie.setPaused(True)
            self.pause_button.setText('Pause')
            self.update_dashboard()
            if direction=='Upload':self.refresh_remote()
            QTimer.singleShot(0,self._next_transfer)
        def on_failure(message):
            self.queue.item(row,2).setText('Cancelled' if message=='Cancelled' else 'Failed')
            self.record_event(f'{direction} stopped: {display_name} ({message})','ERROR')
            self.status.setText(f'{direction} failed: {display_name}')
            self.transfer_rate=0
            self.globe_movie.setPaused(True)
            self.pause_button.setText('Pause')
            self.update_dashboard()
            if message!='Cancelled':QMessageBox.warning(self,f'{direction} failed',message)
            QTimer.singleShot(0,self._next_transfer)
        worker.progress.connect(on_progress)
        worker.completed.connect(on_complete)
        worker.failed.connect(on_failure)
        worker.finished.connect(self.update_dashboard)
        worker.start()

    def _next_transfer(self):
        if self.transfer_worker and self.transfer_worker.isRunning():
            QTimer.singleShot(150,self._next_transfer)
            return
        if self.pending_transfers and self.sftp:
            direction,source,target,name,row=self.pending_transfers.pop(0)
            self._run_transfer(direction,source,target,name,row)

    def pause_transfer(self):
        worker=self.transfer_worker
        if not worker or not worker.isRunning():
            QMessageBox.information(self,'Pause','No active transfer to pause.')
            return
        if worker.pause_event.is_set():
            worker.pause_event.clear()
            self.pause_button.setText('Pause')
            self.queue.item(self.active_queue_row,2).setText('Running')
            self.record_event('Transfer resumed')
        else:
            worker.pause_event.set()
            self.pause_button.setText('Resume')
            self.queue.item(self.active_queue_row,2).setText('Paused')
            self.record_event('Transfer paused')

    def cancel_transfer(self):
        row=self.queue.currentRow()
        if row<0:
            QMessageBox.information(self,'Cancel','Select a transfer in the queue first.')
            return
        if self.transfer_worker and self.transfer_worker.isRunning() and row==self.active_queue_row:
            if QMessageBox.question(self,'Cancel transfer?','Cancel the active transfer? Partial files created by this transfer will be removed when possible.',QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)!=QMessageBox.StandardButton.Yes:return
            self.transfer_worker.cancel_event.set()
            self.transfer_worker.pause_event.clear()
            self.pause_button.setText('Pause')
        else:
            matches=[item for item in self.pending_transfers if item[4]==row]
            if matches:
                self.pending_transfers=[item for item in self.pending_transfers if item[4]!=row]
                self.queue.item(row,2).setText('Cancelled')
                self.record_event('Queued transfer cancelled')

    def queue_upload(self):
        if not self.require_connection():return
        filename,_=QFileDialog.getOpenFileName(self,'Choose file to queue')
        if not filename:return
        target=posixpath.join(self.remote_path,Path(filename).name)
        if self.confirm_overwrite(target):self.start_transfer('Upload',filename,target,Path(filename).name,enqueue=True)

    def queue_download(self):
        if not self.require_connection():return
        name=self.selected_remote()
        if not name:return
        entry=next((e for e in self.remote_entries if e.filename==name),None)
        if entry and stat.S_ISDIR(entry.st_mode):return
        destination,_=QFileDialog.getSaveFileName(self,'Save queued download',name)
        if destination:
            if os.path.exists(destination) and self.confirm_overwrites:
                answer=QMessageBox.question(self,'Replace local file?',f'{destination} already exists. Overwrite?',QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,QMessageBox.StandardButton.No)
                if answer!=QMessageBox.StandardButton.Yes:return
            self.start_transfer('Download',posixpath.join(self.remote_path,name),destination,name,enqueue=True)

    def upload_file(self):
        if not self.require_connection():return
        filename,_=QFileDialog.getOpenFileName(self,'Choose file to upload')
        if not filename:return
        target=posixpath.join(self.remote_path,Path(filename).name)
        if not self.confirm_overwrite(target):return
        self.start_transfer('Upload',filename,target,Path(filename).name)

    def download_file(self):
        if not self.require_connection():return
        name=self.selected_remote()
        if not name:
            QMessageBox.information(self,'Select a file','Select a remote file first.');return
        entry=next((e for e in self.remote_entries if e.filename==name),None)
        if entry and stat.S_ISDIR(entry.st_mode):
            QMessageBox.information(self,'Folder selected','Select a file, not a folder.');return
        destination,_=QFileDialog.getSaveFileName(self,'Save downloaded file',name)
        if not destination:return
        if os.path.exists(destination) and self.confirm_overwrites:
            answer=QMessageBox.question(self,'Replace local file?',f'{destination} already exists. Overwrite?',QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,QMessageBox.StandardButton.No)
            if answer!=QMessageBox.StandardButton.Yes:return
        self.start_transfer('Download',posixpath.join(self.remote_path,name),destination,name)

    def new_folder(self):
        if not self.require_connection():return
        name,ok=QInputDialog.getText(self,'New Folder','Folder name:')
        if not ok or not name:return
        if name in ('.','..') or '/' in name or '\\' in name:
            QMessageBox.warning(self,'Invalid name','Enter a single folder name.');return
        try:
            self.sftp.mkdir(posixpath.join(self.remote_path,name))
            self.record_event('Created folder: '+posixpath.join(self.remote_path,name))
            self.refresh_remote()
        except Exception as exc:QMessageBox.warning(self,'Cannot create folder',str(exc))

    def show_permissions(self):
        if not self.require_connection():
            return
        name = self.selected_remote()
        if not name:
            QMessageBox.information(self, 'File Permissions', 'Select a remote file or folder first.')
            return
        path = posixpath.join(self.remote_path, name)
        try:
            entry = self.sftp.stat(path)
        except Exception as exc:
            QMessageBox.warning(self, 'Permissions unavailable', str(exc))
            return

        current = stat.S_IMODE(entry.st_mode)
        dialog = QDialog(self)
        dialog.setWindowTitle('File Permissions — ' + name)
        dialog.setMinimumWidth(410)
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel('Remote path: ' + path))
        layout.addWidget(QLabel('Owner UID: {}    Group GID: {}'.format(
            getattr(entry, 'st_uid', 'Unknown'), getattr(entry, 'st_gid', 'Unknown'))))
        layout.addWidget(QLabel('Current Unix permissions: {:04o}'.format(current)))
        table = QGridLayout()
        table.setHorizontalSpacing(18)
        for col, label in enumerate(('Read', 'Write', 'Execute'), 1):
            table.addWidget(QLabel(label), 0, col)
        boxes = []
        for row, (role, shift) in enumerate((('Owner', 6), ('Group', 3), ('Others', 0)), 1):
            table.addWidget(QLabel(role), row, 0)
            for col, bit in enumerate((4, 2, 1), 1):
                cb = QCheckBox()
                cb.setChecked(bool((current >> shift) & bit))
                table.addWidget(cb, row, col)
                boxes.append((cb, shift, bit))
        layout.addLayout(table)
        mode_label = QLabel()
        layout.addWidget(mode_label)
        def selected_mode():
            # Preserve special mode bits (setuid, setgid, sticky).
            value = current & 0o7000
            for cb, shift, bit in boxes:
                if cb.isChecked():
                    value |= bit << shift
            return value
        def update_mode():
            value = selected_mode()
            mode_label.setText('New permissions: {:04o}    ({})'.format(
                value, stat.filemode((entry.st_mode & ~0o7777) | value)))
        for cb, _, _ in boxes:
            cb.toggled.connect(lambda checked=False: update_mode())
        update_mode()
        layout.addWidget(QLabel('Changes use your connected SSH account permissions.'))
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Apply | QDialogButtonBox.StandardButton.Cancel)
        layout.addWidget(buttons)
        buttons.rejected.connect(dialog.reject)
        def apply_changes():
            new_mode = selected_mode()
            if new_mode == current:
                dialog.accept()
                return
            if QMessageBox.question(
                dialog, 'Confirm permission change',
                'Change permissions for:\\n{}\\n\\n{:04o} → {:04o}?'.format(
                    path, current, new_mode),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            ) != QMessageBox.StandardButton.Yes:
                return
            try:
                self.sftp.chmod(path, new_mode)
                self.record_event('Permissions changed: {} {:04o} -> {:04o}'.format(
                    path, current, new_mode))
                self.refresh_remote()
                dialog.accept()
            except Exception as exc:
                self.record_event('Permission change failed: {} ({})'.format(path, exc))
                QMessageBox.warning(dialog, 'Permission change failed', str(exc))
        buttons.button(QDialogButtonBox.StandardButton.Apply).clicked.connect(apply_changes)
        dialog.exec()

    def require_connection(self):
        if self.sftp:return True
        QMessageBox.information(self,'Not connected','Connect to an SFTP server first.')
        return False

    def confirm_overwrite(self,path):
        if not self.confirm_overwrites:return True
        try:self.sftp.stat(path)
        except IOError:return True
        return QMessageBox.question(self,'Replace remote file?',f'{path} already exists. Overwrite it?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)==QMessageBox.StandardButton.Yes

    def page(self,title,description):
        w=QWidget()
        layout=QVBoxLayout(w)
        layout.setContentsMargins(7,7,7,7)
        layout.setSpacing(8)
        heading=QLabel('  '+title)
        heading.setObjectName('sectionTitle')
        heading.setMinimumHeight(33)
        layout.addWidget(heading)
        if description:
            caption=QLabel(description)
            caption.setObjectName('caption')
            layout.addWidget(caption)
        return w,layout

    def make_pages(self):
        dashboard,lay=self.page('Dashboard','Live connection and transfer information; storage requires read-only SSH command access')
        row=QHBoxLayout()
        self.dashboard_values={}
        for label,value in [('SERVER','OFFLINE'),('STORAGE','N/A'),('USERS','N/A'),('TRANSFERS','0 active')]:
            panel=QFrame();panel.setObjectName('card')
            l=QVBoxLayout(panel);l.addWidget(QLabel(label))
            v=QLabel(value);v.setObjectName('bigValue');l.addWidget(v)
            row.addWidget(panel)
            self.dashboard_values[label]=v
        lay.addLayout(row)
        self.storage_label=QLabel('Disk capacity: unavailable until connected')
        lay.addWidget(self.storage_label)
        self.storage_bar=QProgressBar()
        self.storage_bar.setRange(0,100)
        self.storage_bar.setValue(0)
        self.storage_bar.setFormat('Storage usage unavailable')
        lay.addWidget(self.storage_bar)
        refresh_storage=QPushButton('Refresh Storage')
        refresh_storage.clicked.connect(self.update_storage)
        lay.addWidget(refresh_storage)
        lay.addWidget(QLabel('RECENT ACTIVITY'))
        self.recent_activity=QLabel('No activity yet')
        self.recent_activity.setWordWrap(True)
        lay.addWidget(self.recent_activity)
        lay.addStretch();self.pages.addWidget(dashboard)
        self.transfer_count=0

        files,lay=self.page('My Files','')
        lay.setSpacing(5)
        controls=QHBoxLayout()
        controls.addWidget(QLabel('Browse files on the connected server'))
        controls.addStretch(1)
        for label,handler in [('Upload',self.upload_file),('Download',self.download_file),('Pause',self.pause_transfer),('Queue',self.queue_upload),('Cancel',self.cancel_transfer)]:
            button=QPushButton(label)
            button.setObjectName('quickTransferButton')
            button.setFixedHeight(27)
            button.setMinimumWidth(0)
            button.setMaximumWidth(80)
            button.clicked.connect(handler)
            controls.addWidget(button)
            if label=='Pause':self.pause_button=button
        lay.addLayout(controls)
        path=QHBoxLayout()
        for sym, handler, tip in [
            ('◀', self.navigate_back, 'Back to previous folder'),
            ('▶', self.navigate_forward, 'Forward to next folder'),
            ('▲', self.navigate_up, 'Up one folder')]:
            b=QPushButton(sym)
            b.setFixedWidth(35)
            b.setToolTip(tip)
            b.clicked.connect(handler)
            path.addWidget(b)
            if sym=='◀':self.remote_back_button=b
            elif sym=='▶':self.remote_forward_button=b
        self.update_remote_navigation_buttons()
        location=QLineEdit('');location.setPlaceholderText('Connect to a server to browse directories');location.setReadOnly(True)
        self.location=location
        path.addWidget(location,1)
        self.search=QLineEdit();self.search.setPlaceholderText('Search files...')
        self.search.setFixedWidth(210)
        self.search.textChanged.connect(self.filter_files)
        path.addWidget(self.search)
        lay.addLayout(path)
        self.file_icons_large = False
        self.file_table=QTableWidget(0,4)
        self.file_table.setIconSize(QSize(16, 16))
        self.file_table.verticalHeader().setDefaultSectionSize(28)
        self.file_table.setHorizontalHeaderLabels(['Name','Size','Type','Modified'])
        self.file_table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
        self.file_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.file_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.file_table.setSortingEnabled(True)
        self.file_table.doubleClicked.connect(lambda _:self.open_selected())
        self.offline_notice=QLabel('No files, need a connection first to access')
        self.offline_notice.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.offline_notice.setObjectName('offlineNotice')
        lay.addWidget(self.offline_notice,1)
        lay.addWidget(self.file_table,1)
        queue_title=QLabel('  Transfer Queue')
        queue_title.setObjectName('sectionTitle')
        queue_title.setMinimumHeight(30)
        lay.addWidget(queue_title)
        self.queue=QTableWidget(0,4)
        self.queue.setHorizontalHeaderLabels(['File Name','Direction','Status','Progress'])
        self.queue.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.queue.setFixedHeight(125)
        self.queue.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.queue.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        lay.addWidget(self.queue)
        self.pages.addWidget(files)
        self.filter_files('')

        transfers,lay=self.page('Transfers','Live transfers are displayed in My Files → Transfer Queue')
        self.transfer_note=QLabel('No transfer is currently running.')
        lay.addWidget(self.transfer_note)
        lay.addStretch();self.pages.addWidget(transfers)
        users,lay=self.page('Users','Current SFTP login; Linux account administration is not available from this client')
        self.users_note=QLabel('Not connected')
        lay.addWidget(self.users_note)
        lay.addStretch();self.pages.addWidget(users)
        activity,lay=self.page('Activity','Live application activity. This is not the Debian system-wide SSH audit log.')
        self.activity_table=QTableWidget(0,3)
        self.activity_table.setHorizontalHeaderLabels(['Time','Event','Result'])
        self.activity_table.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch)
        self.activity_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        lay.addWidget(self.activity_table,1)
        controls=QHBoxLayout()
        clear=QPushButton('Clear View')
        clear.clicked.connect(self.clear_activity)
        export=QPushButton('Export Log...')
        export.clicked.connect(self.export_activity)
        controls.addWidget(clear);controls.addWidget(export);controls.addStretch()
        lay.addLayout(controls)
        self.pages.addWidget(activity)
        docker,lay=self.page('Docker','Manage local Docker Desktop or a remote Docker Engine over SSH. Engine access is highly privileged.')
        modebar=QHBoxLayout()
        modebar.addWidget(QLabel('Docker connection:'))
        self.docker_mode=QComboBox()
        self.docker_mode.addItems(['Local Docker Desktop','Remote Docker (SSH)','Docker Hub (planned)'])
        self.docker_mode.setMinimumWidth(230)
        self.docker_mode.currentIndexChanged.connect(self.docker_mode_changed)
        modebar.addWidget(self.docker_mode)
        self.docker_connect=QPushButton('Test connection')
        self.docker_connect.clicked.connect(self.docker_test_connection)
        modebar.addWidget(self.docker_connect)
        help_button=QPushButton('Help')
        help_button.setToolTip('Docker Quick Start / Help')
        help_button.setFixedWidth(58)
        help_button.clicked.connect(lambda:QMessageBox.information(
            self,'Docker quick start',
            '1. Connect to your Debian SSH server.\n'
            '2. Click Refresh to list containers.\n'
            '3. Select a container in the table.\n'
            '4. Start, Stop, Restart, Logs, Inspect and Stats act on that selection.\n'
            '5. Double-click a row to view its logs.\n'
            '6. Use Docker Compose and Volumes tabs for additional tools.\n\n'
            'Removing a container requires confirmation.'))
        modebar.addWidget(help_button)
        self.docker_connection_label=QLabel('Local Docker Desktop: not checked')
        modebar.addWidget(self.docker_connection_label,1)
        lay.addLayout(modebar)
        intro=QHBoxLayout()
        guide=QLabel('1. Refresh   →   2. Select a container   →   3. Choose an action')
        guide.setWordWrap(True)
        intro.addWidget(guide,1)
        self.docker_search=QLineEdit()
        self.docker_search.setPlaceholderText('Search containers...')
        self.docker_search.setMinimumWidth(170)
        self.docker_search.textChanged.connect(self.docker_filter_rows)
        intro.addWidget(self.docker_search)
        lay.addLayout(intro)
        # Compact, responsive toolbar: keep original text size and wrap when narrow.
        toolbar=QWidget()
        self.docker_toolbar_layout=QVBoxLayout(toolbar)
        self.docker_toolbar_layout.setContentsMargins(2,2,2,2)
        self.docker_toolbar_layout.setSpacing(5)
        self.docker_toolbar_buttons=[]
        for label,action in [('Refresh','refresh'),('Start','start'),('Stop','stop'),('Restart','restart'),('Logs','logs'),('Inspect','inspect'),('Stats','stats'),('Create Container','create'),('Docker Compose','compose'),('Remove','remove')]:
            button=QPushButton(label)
            button.setMinimumSize(0,0)
            button.setSizePolicy(QSizePolicy.Policy.Fixed,QSizePolicy.Policy.Fixed)
            button.setStyleSheet('padding: 3px 7px; min-height: 0px; min-width: 0px;')
            button.setToolTip({
                'refresh':'Reload containers', 'start':'Start selected container',
                'stop':'Stop selected container', 'restart':'Restart selected container',
                'logs':'Show container logs', 'inspect':'Inspect container configuration',
                'stats':'Show container usage', 'create':'Create a new container',
                'compose':'Manage Compose services', 'remove':'Remove selected container'
            }.get(action,''))
            button.clicked.connect(lambda checked=False,a=action:self.docker_action(a))
            if action in ('stop','restart','remove'):
                button.setToolTip('Changes the selected container; confirmation required')
            self.docker_toolbar_buttons.append(button)
        lay.addWidget(toolbar)
        self.docker_toolbar_widget=toolbar

        self.docker_table=QTableWidget(0,6)
        self.docker_table.setHorizontalHeaderLabels(['Name','Image','State','Status','Ports','Created'])
        self.docker_table.setToolTip('Select a row for actions. Double-click a row to see its logs.')
        self.docker_table.cellDoubleClicked.connect(lambda row,col:self.docker_action('logs'))
        for col in (0,1,2,4,5):
            self.docker_table.horizontalHeader().setSectionResizeMode(col,QHeaderView.ResizeMode.Interactive)
        self.docker_table.horizontalHeader().setSectionResizeMode(3,QHeaderView.ResizeMode.Stretch)
        for col,width in enumerate((150,170,100,270,135,165)):
            self.docker_table.setColumnWidth(col,width)
        self.docker_table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.docker_table.setAlternatingRowColors(True)
        self.docker_table.verticalHeader().setDefaultSectionSize(35)
        self.docker_table.setMinimumHeight(226)
        self.docker_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.docker_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.docker_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.docker_table.itemSelectionChanged.connect(self.docker_selection_changed)

        self.docker_tabs=QTabWidget()
        self.docker_details=QPlainTextEdit()
        self.docker_details.setReadOnly(True)
        self.docker_details.setPlainText('Select a container to view its details.')
        management=QWidget()
        mg=QHBoxLayout(management)
        mg.setContentsMargins(8,8,8,8)
        mg.setSpacing(8)
        details_box=QGroupBox('Container Details')
        db=QVBoxLayout(details_box)
        db.addWidget(self.docker_details)
        mg.addWidget(details_box,4)
        action_panel=QGroupBox('Actions')
        self.docker_action_grid=QVBoxLayout(action_panel)
        self.docker_action_grid.setContentsMargins(6,8,6,6)
        self.docker_action_grid.setSpacing(5)
        self.docker_action_buttons=[]
        for label,action in [('Start','start'),('Stop','stop'),('Restart','restart'),('Logs','logs'),('Inspect','inspect'),('Stats','stats'),('Remove Container','remove')]:
            btn=QPushButton(label)
            btn.setMinimumSize(0,0)
            btn.setSizePolicy(QSizePolicy.Policy.Fixed,QSizePolicy.Policy.Fixed)
            btn.setStyleSheet('padding: 3px 7px; min-height: 0px; min-width: 0px;')
            btn.clicked.connect(lambda checked=False,a=action:self.docker_action(a))
            self.docker_action_buttons.append(btn)
        self.docker_action_panel=action_panel
        QTimer.singleShot(0,self._layout_compact_buttons)
        mg.addWidget(action_panel,3)
        quick_box=QGroupBox('Quick Commands')
        ql=QVBoxLayout(quick_box)
        self.docker_quick=QPlainTextEdit()
        self.docker_quick.setReadOnly(True)
        self.docker_quick.setPlaceholderText('Select a container for Docker command examples')
        ql.addWidget(self.docker_quick)
        mg.addWidget(quick_box,3)
        self.docker_tabs.addTab(management,'Container Management')
        compose=QWidget()
        cl=QVBoxLayout(compose)
        compose_help=QLabel('Project directory: ~/sftp-server • Existing compose.yaml or docker-compose.yml required')
        compose_help.setWordWrap(True)
        cl.addWidget(compose_help)
        compose_actions=QHBoxLayout()
        for label,action in [('Check Config','compose_check'),('Deploy / Up','compose_up'),('Stop / Down','compose_down'),('List Services','compose_ps')]:
            btn=QPushButton(label)
            btn.clicked.connect(lambda checked=False,a=action:self.docker_action(a))
            compose_actions.addWidget(btn)
        compose_actions.addStretch()
        cl.addLayout(compose_actions)
        cl.addWidget(QLabel('Compose operates only in ~/sftp-server; Down does not remove volumes.'))
        cl.addStretch()
        self.docker_tabs.addTab(compose,'Docker Compose')
        volumes=QWidget()
        vl=QVBoxLayout(volumes)
        vb=QPushButton('Refresh Volumes')
        vb.clicked.connect(lambda:self.docker_action('volumes'))
        vl.addWidget(vb)
        vl.addWidget(QLabel('Docker volumes on the Debian host (read-only listing).'))
        vl.addStretch()
        self.docker_tabs.addTab(volumes,'Volumes')

        self.docker_output=QPlainTextEdit()
        self.docker_output.setReadOnly(True)
        self.docker_output.setPlaceholderText('Docker command output and errors')
        self.docker_output.setMinimumHeight(55)
        self.docker_output.setMaximumHeight(110)

        middle=QSplitter(Qt.Orientation.Vertical)
        middle.addWidget(self.docker_table)
        details_panel=QWidget()
        details_layout=QVBoxLayout(details_panel)
        details_layout.setContentsMargins(0,0,0,0)
        details_layout.setSpacing(5)
        details_layout.addWidget(self.docker_tabs,3)
        details_layout.addWidget(self.docker_output,1)
        middle.addWidget(details_panel)
        middle.setChildrenCollapsible(False)
        middle.setStretchFactor(0,2)
        middle.setStretchFactor(1,3)
        middle.setSizes([270,340])
        self.docker_splitter=middle
        lay.addWidget(middle,1)

        self.docker_monitor_label=QLabel('Select a running container for live statistics in the sidebar.')
        self.docker_monitor_label.setWordWrap(True)
        lay.addWidget(self.docker_monitor_label)
        self.docker_note=QLabel('Connect to Debian, then click Refresh.')
        lay.addWidget(self.docker_note)
        self.pages.addWidget(docker)
        self.docker_page = docker
        self.docker_resolution_warning = QFrame(docker)
        self.docker_resolution_warning.setObjectName('dockerResolutionWarning')
        self.docker_resolution_warning.setStyleSheet("""
            QFrame#dockerResolutionWarning { background: #171225; border: 1px solid #74639a; }
            QFrame#dockerResolutionWarning QLabel { color: #f3eaff; background: transparent; }
        """)
        warning_layout = QVBoxLayout(self.docker_resolution_warning)
        warning_layout.setContentsMargins(30, 30, 30, 30)
        warning_layout.addStretch(1)
        warning_title = QLabel('Higher Resolution Required')
        warning_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        warning_title.setStyleSheet('font-size: 21px; font-weight: bold; color: white;')
        warning_layout.addWidget(warning_title)
        warning_text = QLabel(
            'The Docker interface needs more available screen space to display correctly.\n\n'
            'Enlarge or maximize this window, reduce display scaling, or use a higher-resolution display.\n'
            'Recommended display resolution: 1280 x 1024 or higher.')
        warning_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        warning_text.setWordWrap(True)
        warning_layout.addWidget(warning_text)
        warning_layout.addStretch(1)
        self.docker_resolution_warning.hide()
        docker.installEventFilter(self)
        QTimer.singleShot(0, self._update_docker_resolution)
        settings,lay=self.page('Settings','Connection, transfers, security, appearance, and logging')
        lay.addWidget(QLabel('CONNECTION'))
        lay.addWidget(QLabel('Saved host, port, and username are reused in the Connect dialog. Passwords are never saved.'))
        lay.addWidget(QLabel('TRANSFERS'))
        self.overwrite_check=QCheckBox('Confirm before overwriting files')
        self.overwrite_check.setChecked(self.confirm_overwrites)
        self.overwrite_check.toggled.connect(self.set_confirm_overwrites)
        lay.addWidget(self.overwrite_check)
        lay.addWidget(QLabel('SECURITY'))
        lay.addWidget(QLabel('SSH host-key verification is always enabled. Unknown keys require approval.'))
        lay.addWidget(QLabel('APPEARANCE'))
        self.theme_check=QCheckBox('Dark purple mode')
        self.theme_check.setChecked(self.dark)
        self.theme_check.toggled.connect(self.set_dark)
        lay.addWidget(self.theme_check)
        self.graph_check=QCheckBox('Show network transfer graph')
        self.graph_check.setChecked(self.show_graph)
        self.graph_check.toggled.connect(self.set_show_graph)
        lay.addWidget(self.graph_check)
        self.globe_check=QCheckBox('Animate globe while connecting or transferring')
        self.globe_check.setChecked(self.animate_globe)
        self.globe_check.toggled.connect(self.set_animate_globe)
        lay.addWidget(self.globe_check)
        lay.addWidget(QLabel('LOGGING'))
        self.log_check=QCheckBox('Save activity events to a local log file')
        self.log_check.setChecked(self.log_to_file)
        self.log_check.toggled.connect(self.set_log_to_file)
        lay.addWidget(self.log_check)
        lay.addWidget(QLabel('Logs are stored under your user profile; passwords are not logged.'))
        reset=QPushButton('Reset Preferences')
        reset.clicked.connect(self.reset_preferences)
        lay.addWidget(reset)
        lay.addStretch();self.pages.addWidget(settings)

    def record_event(self,message,result='OK'):
        timestamp=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.activity_events.append((timestamp,message,result))
        if hasattr(self,'activity_table'):
            row=self.activity_table.rowCount()
            self.activity_table.insertRow(row)
            for col,value in enumerate((timestamp,message,result)):
                self.activity_table.setItem(row,col,QTableWidgetItem(value))
            self.activity_table.scrollToBottom()
        if hasattr(self,'recent_activity'):
            self.recent_activity.setText('\n'.join(f'{t}  {m}' for t,m,_ in self.activity_events[-5:]))
        if self.log_to_file:
            try:
                path=Path.home()/'.sftp_manager'/'activity.log'
                path.parent.mkdir(parents=True,exist_ok=True)
                with path.open('a',encoding='utf-8') as f:f.write(f'{timestamp} [{result}] {message}\n')
            except OSError:pass

    def clear_activity(self):
        self.activity_events.clear()
        self.activity_table.setRowCount(0)
        self.recent_activity.setText('No activity yet')

    def export_activity(self):
        path,_=QFileDialog.getSaveFileName(self,'Export activity log','sftp_activity.txt','Text Files (*.txt)')
        if not path:return
        try:
            with open(path,'w',encoding='utf-8') as f:
                for t,m,r in self.activity_events:f.write(f'{t} [{r}] {m}\n')
        except OSError as exc:QMessageBox.warning(self,'Export failed',str(exc))

    def network_tick(self):
        self.network_graph.add_sample(self.transfer_rate)
        self.net_title.setText(f'Network   •   {self.transfer_rate/1024:.1f} KB/s')

    def update_dashboard(self):
        if not hasattr(self,'dashboard_values'):return
        self.dashboard_values['SERVER'].setText('ONLINE' if self.sftp else 'OFFLINE')
        self.dashboard_values['STORAGE'].setText(self.storage_summary if self.sftp else 'N/A')
        self.dashboard_values['USERS'].setText(self.connected_user if self.sftp else 'N/A')
        active=int(bool(self.transfer_worker and self.transfer_worker.isRunning()))
        self.dashboard_values['TRANSFERS'].setText(f'{active} active')
        self.storage_label.setText(self.storage_detail if self.sftp else 'Disk capacity: unavailable until connected')
        self.users_note.setText(f'Connected as: {self.connected_user}' if self.sftp else 'Not connected')
        self.transfer_note.setText('Transfer in progress' if active else f'{self.transfer_count} transfers initiated this session')

    def update_storage(self):
        if not self.ssh:
            self.storage_summary='N/A'
            self.storage_detail='Storage information unavailable'
            self.storage_bar.setValue(0)
            self.storage_bar.setFormat('Storage usage unavailable')
            self.update_dashboard()
            return
        try:
            # Read-only disk usage query. This is filesystem capacity, not a user quota.
            _,stdout,stderr=self.ssh.exec_command('df -Pk -- "$HOME"',timeout=6)
            lines=stdout.read(8192).decode('utf-8','replace').splitlines()
            if len(lines)<2:raise ValueError('df returned no filesystem data')
            fields=lines[-1].split()
            total,used,available=(int(fields[i])*1024 for i in (1,2,3))
            pct=min(100,round(used/total*100)) if total else 0
            self.storage_summary=f'{used/1024**3:.1f} GB'
            self.storage_detail=f'Filesystem: {used/1024**3:.1f} GB used / {total/1024**3:.1f} GB total • {available/1024**3:.1f} GB available (not a user quota)'
            self.storage_bar.setValue(pct)
            self.storage_bar.setFormat(f'{pct}% used')
        except Exception as exc:
            self.storage_summary='N/A'
            self.storage_detail='Storage unavailable: '+str(exc)
            self.storage_bar.setValue(0)
            self.storage_bar.setFormat('Storage usage unavailable')
        self.update_dashboard()

    def set_confirm_overwrites(self,value):
        self.confirm_overwrites=bool(value)
        self.preferences.setValue('confirm_overwrites',self.confirm_overwrites)

    def set_show_graph(self,value):
        self.show_graph=bool(value)
        self.network_box.setVisible(self.show_graph)
        self.preferences.setValue('show_graph',self.show_graph)

    def set_animate_globe(self,value):
        self.animate_globe=bool(value)
        self.preferences.setValue('animate_globe',self.animate_globe)
        if not value:self.globe_movie.setPaused(True)

    def set_log_to_file(self,value):
        self.log_to_file=bool(value)
        self.preferences.setValue('log_to_file',self.log_to_file)

    def reset_preferences(self):
        self.preferences.clear()
        self.set_dark(False)
        self.overwrite_check.setChecked(True)
        self.graph_check.setChecked(True)
        self.globe_check.setChecked(True)
        self.log_check.setChecked(False)
        self.record_event('Preferences reset')

    def make_menus(self):
        specs={
         'File':['Connect to Server…','Disconnect','-', 'Upload Files…','Download Files…','New Folder','-','Exit'],
         'Edit':['Cut','Copy','Paste','Rename','Delete','-','Select All','File Properties'],
         'View':['Refresh','-','Large Icons','Small Icons','List View','Details View','-','Toggle Dark / Light Mode','Fullscreen'],
         'Server':['Server Status','Connection Settings','-','User Management','File Permissions','Transfer Activity','-','Backup Manager','Server Logs','Administration Settings'],
         'Help':['Getting Started','User Guide','Keyboard Shortcuts','-','About SFTP Manager']}
        for name,entries in specs.items():
            menu=self.menuBar().addMenu(name)
            for label in entries:
                if label=='-':menu.addSeparator();continue
                action=QAction(label,self)
                shortcuts={'Connect to Server…':'Ctrl+O','Upload Files…':'Ctrl+U','Download Files…':'Ctrl+D','New Folder':'Ctrl+N','Rename':'F2','Delete':'Delete','Select All':'Ctrl+A','Refresh':'F5','User Guide':'F1','Fullscreen':'F11'}
                if label in shortcuts:action.setShortcut(shortcuts[label])
                if label=='Large Icons':action.setIcon(icon('large_icons'))
                elif label=='Small Icons':action.setIcon(icon('small_icons'))
                action.triggered.connect(lambda checked=False,n=label:self.menu_action(n))
                menu.addAction(action)

    def menu_action(self,name):
        if name=='Connect to Server…':self.begin_connection_attempt()
        elif name=='Disconnect':self.disconnect_demo()
        elif name=='Exit':self.close()
        elif name=='Toggle Dark / Light Mode':self.set_dark(not self.dark)
        elif name=='Fullscreen':self.showNormal() if self.isFullScreen() else self.showFullScreen()
        elif name=='Refresh':self.refresh_remote()
        elif name=='Large Icons':self.set_file_icon_size(True)
        elif name=='Small Icons':self.set_file_icon_size(False)
        elif name=='Upload Files…':self.upload_file()
        elif name=='Download Files…':self.download_file()
        elif name=='New Folder':self.new_folder()
        elif name=='File Permissions':self.show_permissions()
        elif name=='Select All':self.file_table.selectAll()
        elif name=='File Properties':self.file_properties()
        elif name=='Rename':self.rename_remote()
        elif name=='Delete':self.delete_remote()
        elif name in ('Cut','Copy','Paste'):self.clipboard_action(name)
        elif name in ('List View','Details View'):self.set_file_icon_size(False)

        elif name=='Connection Settings':self.begin_connection_attempt()
        elif name=='Getting Started':self.help_dialog('Getting Started',GETTING_STARTED)
        elif name=='User Guide':self.help_dialog('User Guide',USER_GUIDE)
        elif name=='Keyboard Shortcuts':self.help_dialog('Keyboard Shortcuts',SHORTCUTS)
        elif name=='Server Status':self.change_page(0);self.update_storage()
        elif name=='Server Logs':self.change_page(4)
        elif name=='Backup Manager':self.help_dialog('Backup Manager','Automated backup and restore require a separately configured server-side service. This client does not have backup privileges.')
        elif name=='Administration Settings':self.help_dialog('Administration Settings','Privileged Debian administration is intentionally unavailable through ordinary SFTP. Configure restricted administrative access before enabling it.')
        elif name=='Docker':self.change_page(5)
        elif name=='User Management':self.change_page(3)
        elif name=='Transfer Activity':self.change_page(2)
        elif name=='About SFTP Manager':QMessageBox.about(self,'About SFTP Manager','Secure File Transfer Protocol (SFTP) Manager\nSFTP Manager v0.8.2\nIT610 Project - Jonathan Lachman - 2026\nSFTP Client.')
        else:self.demo_action(name)

    def help_dialog(self,title,body):
        dialog=QDialog(self)
        dialog.setWindowTitle(title+' — SFTP Manager')
        dialog.resize(485 if title=='Keyboard Shortcuts' else 700, 380 if title=='Keyboard Shortcuts' else 520)
        layout=QVBoxLayout(dialog)
        browser=QTextBrowser()
        browser.setMarkdown(body)
        layout.addWidget(browser)
        close=QPushButton('Close')
        if title=='Keyboard Shortcuts':
            close.setFixedWidth(100)
            close.setFixedHeight(29)
        close.clicked.connect(dialog.accept)
        layout.addWidget(close)
        dialog.exec()

    def sidebar_refresh(self):
        if self.pages.currentIndex()==5:
            self.docker_action('refresh')
        self.docker_poll_stats()

    def docker_filter_rows(self, query):
        needle=query.strip().casefold()
        for row in range(self.docker_table.rowCount()):
            match=not needle or any(
                needle in (self.docker_table.item(row,col).text().casefold()
                           if self.docker_table.item(row,col) else '')
                for col in (0,1,2,3)
            )
            self.docker_table.setRowHidden(row,not match)

    def docker_mode_changed(self):
        self.docker_poll.stop()
        self.docker_containers=[]
        self.docker_table.setRowCount(0)
        self.docker_selection_changed()
        labels=['Local Docker Desktop: click Test connection',
                'Remote Docker: connect using the SFTP Connect button',
                'Docker Hub login: planned for a later release']
        self.docker_connection_label.setText(labels[self.docker_mode.currentIndex()])
        if self.docker_mode.currentIndex()==0:
            self.docker_action('refresh')

    def docker_test_connection(self):
        if self.docker_mode.currentIndex()==2:
            QMessageBox.information(self,'Docker Hub','Docker Hub authentication is planned, not implemented in v0.8.2.')
            return
        if self.docker_mode.currentIndex()==1 and not self.ssh:
            QMessageBox.information(self,'Remote Docker','Connect to your SSH server first using the main Connect button.')
            return
        self.docker_action('refresh')

    def docker_status(self):
        self.docker_action('refresh')

    def docker_selected(self):
        row=self.docker_table.currentRow()
        if row<0:return None
        item=self.docker_table.item(row,0)
        if item is None:return None
        cid=item.data(Qt.ItemDataRole.UserRole)
        return next((c for c in self.docker_containers if c.get('ID')==cid),None)

    def docker_selection_changed(self):
        c=self.docker_selected()
        if c:
            self.docker_details.setPlainText('\n'.join(f'{k}: {c.get(k, "")}' for k in ('Names','ID','Image','State','Status','Ports','Command','CreatedAt')))
            name=shlex.quote(str(c.get('Names','')))
            self.docker_quick.setPlainText('\n'.join('docker '+action+' '+name for action in ('start','stop','restart','logs','inspect','stats','rm')))
        else:
            self.docker_details.setPlainText('Select a container to view its details.')
            self.docker_quick.clear()
        self.docker_stats_history.clear()
        for val,bar,graph in self.docker_metrics.values():val.setText('—');bar.setValue(0);graph.clear()
        self.docker_monitor_interval()

    def docker_monitor_interval(self):
        self.docker_poll.stop()
        c=self.docker_selected()
        if c and c.get('State')=='running' and (self.docker_mode.currentIndex()==0 or self.ssh) and self.docker_interval.currentIndex()>0:
            self.docker_poll.setInterval({1:3000,2:5000,3:10000}[self.docker_interval.currentIndex()])
            self.docker_poll.start()
            self.docker_poll_stats()

    def docker_poll_stats(self):
        c=self.docker_selected()
        if c and c.get('State')=='running' and self.pages.currentIndex()==5:
            self.docker_action('stats_live')

    def docker_create_dialog(self):
        dlg=QDialog(self);dlg.setWindowTitle('Create Docker Container');dlg.resize(425,240)
        form=QFormLayout(dlg)
        name=QLineEdit('my-container');image=QLineEdit('alpine:latest')
        command=QLineEdit('sleep 3600')
        form.addRow('Container name:',name);form.addRow('Image:',image);form.addRow('Command (optional):',command)
        form.addRow(QLabel('No privileged mode, host networking, or host mounts.'))
        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Ok|QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dlg.accept);buttons.rejected.connect(dlg.reject);form.addRow(buttons)
        if dlg.exec()!=QDialog.DialogCode.Accepted:return None
        n=name.text().strip();img=image.text().strip();cmd=command.text().strip()
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}',n) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_./:@-]{0,180}',img):
            QMessageBox.warning(self,'Invalid container','Check the container name and image reference.');return None
        if len(cmd)>256 or any(x in cmd for x in ('\n','\r')):
            QMessageBox.warning(self,'Invalid command','Command too long or contains line breaks.');return None
        args=['docker','run','-d','--name',n,'--restart','no',img]+(shlex.split(cmd) if cmd else [])
        return ' '.join(shlex.quote(x) for x in args)

    def _layout_compact_buttons(self):
        """Group buttons at the left; wrap before Inspect at narrower widths."""
        if not hasattr(self, 'docker_action_buttons'):
            return

        def arrange(layout, buttons, available, split_at_inspect=False):
            # Remove old row widgets and return buttons to the layout's parent.
            while layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    for button in buttons:
                        if button.parent() is widget:
                            button.setParent(layout.parentWidget())
                    widget.deleteLater()

            widths = [button.sizeHint().width() for button in buttons]
            gap = 5
            full = sum(widths) + gap * (len(buttons) - 1)
            groups = [buttons[:4], buttons[4:]] if split_at_inspect and available < full + 12 else [buttons]
            for group in groups:
                row_buttons = []
                used = 0
                for button in group:
                    width = button.sizeHint().width()
                    if row_buttons and used + gap + width > available:
                        add_row(row_buttons)
                        row_buttons = []
                        used = 0
                    used += (gap if row_buttons else 0) + width
                    row_buttons.append(button)
                if row_buttons:
                    add_row(row_buttons)

            def_unused = None  # Keep the surrounding layout height stable.
            layout.addStretch(1)

        def add_row(buttons):
            # Each row gets one stretch AFTER its last button, never between buttons.
            parent = buttons[0].parentWidget()
            row_widget = QWidget()
            row_layout = QHBoxLayout(row_widget)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(5)
            for button in buttons:
                row_layout.addWidget(button)
            row_layout.addStretch(1)
            active_layout.addWidget(row_widget)

        for active_layout, buttons, available, split in (
            (self.docker_action_grid, self.docker_action_buttons,
             max(100, self.docker_action_panel.contentsRect().width()-16), True),
            (self.docker_toolbar_layout, self.docker_toolbar_buttons,
             max(100, self.docker_toolbar_widget.contentsRect().width()-8), False),
        ):
            arrange(active_layout, buttons, available, split)

    def _update_docker_resolution(self):
        if not hasattr(self, 'docker_resolution_warning'):
            return
        page = self.docker_page
        warning = self.docker_resolution_warning
        warning.setGeometry(page.rect())
        too_small = page.width() < 1000 or page.height() < 650
        warning.setVisible(too_small and self.pages.currentWidget() is page)
        if warning.isVisible():
            warning.raise_()

    def eventFilter(self, watched, event):
        if (hasattr(self, 'docker_page') and watched is self.docker_page
                and event.type() in (QEvent.Type.Resize, QEvent.Type.Show)):
            QTimer.singleShot(0, self._update_docker_resolution)
        return super().eventFilter(watched, event)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, 'docker_action_buttons'):
            QTimer.singleShot(0,self._layout_compact_buttons)
        if hasattr(self, 'docker_resolution_warning'):
            QTimer.singleShot(0, self._update_docker_resolution)

    def docker_action(self, action):
        mode=self.docker_mode.currentIndex()
        if mode==2:
            self.docker_note.setText('Docker Hub authentication is planned, not available yet.');return
        if mode==1 and (not self.ssh or not self.ssh.get_transport() or not self.ssh.get_transport().is_active()):
            self.docker_note.setText('Connect to your remote SSH server first.');return
        if self.docker_worker is not None and self.docker_worker.isRunning():
            if action!='stats_live':self.docker_note.setText('Docker operation already running; please wait.')
            return
        if action=='refresh':command="docker ps -a --no-trunc --format '{{json .}}'"
        elif action=='create':
            command=self.docker_create_dialog()
            if not command:return
        elif action=='volumes':command='docker volume ls'
        elif action.startswith('compose_') or action=='compose':
            if action=='compose':self.docker_tabs.setCurrentIndex(1);return
            commands={'compose_check':'config -q','compose_up':'up -d','compose_down':'down','compose_ps':'ps'}
            if action not in commands:return
            if action in ('compose_up','compose_down'):
                answer=QMessageBox.question(self,'Confirm Docker Compose',f'Run docker compose {commands[action]} in ~/sftp-server?',QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,QMessageBox.StandardButton.No)
                if answer!=QMessageBox.StandardButton.Yes:return
            if mode==0:
                self.docker_note.setText('Local Compose management is not available yet. Use Docker Desktop or Remote SSH.')
                return
            command='cd "$HOME/sftp-server" && docker compose '+commands[action]
        else:
            c=self.docker_selected()
            if not c:
                if action!='stats_live':self.docker_note.setText('Select a container first.')
                return
            cid=c.get('ID','')
            if not re.fullmatch(r'[a-f0-9]{12,64}',cid):
                self.docker_note.setText('Invalid container identifier.');return
            q=shlex.quote(cid)
            if action in ('start','stop','restart','remove'):
                answer=QMessageBox.question(self,'Confirm Docker '+action,
                    f'{action.capitalize()} {c.get("Names",cid)}?'+('\nThis permanently removes the container (not its named volumes).' if action=='remove' else ''),
                    QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,QMessageBox.StandardButton.No)
                if answer!=QMessageBox.StandardButton.Yes:return
                command=f'docker container {"rm" if action=="remove" else action} {q}'
            elif action=='logs':command=f'docker logs --tail 120 --timestamps {q}'
            elif action=='inspect':command=f'docker container inspect --format "{{{{json .}}}}" {q}'
            elif action in ('stats','stats_live'):command=f'docker stats --no-stream --format "{{{{json .}}}}" {q}'
            else:return
        if action!='stats_live':self.docker_note.setText('Working: '+action+'...')
        self.docker_worker=(LocalDockerWorker(action,command,self) if mode==0
                            else DockerCommandWorker(self.ssh,action,command,self))
        self.docker_worker.finished_command.connect(self.docker_result)
        self.docker_worker.start()

    def docker_result(self,action,out,err,code):
        if code!=0:
            msg=(err or out or 'Docker command failed').strip()
            if action!='stats_live':
                if action=='refresh':
                    self.docker_connection_label.setText('Connection failed: '+msg[:130])
                self.docker_output.setPlainText(msg)
                self.docker_note.setText(f'{action} failed (exit {code})')
                self.record_event('Docker '+action+' failed: '+msg[:180],'ERROR')
            return
        if action=='refresh':
            try:containers=[json.loads(line) for line in out.splitlines() if line.strip()]
            except ValueError as exc:
                self.docker_output.setPlainText('Invalid Docker response: '+str(exc));return
            previous=self.docker_selected()
            old_id=previous.get('ID') if previous else None
            self.docker_containers=containers
            self.docker_table.blockSignals(True)
            self.docker_table.setRowCount(len(containers))
            selected_row=None
            for row,c in enumerate(containers):
                for col,key in enumerate(('Names','Image','State','Status','Ports','CreatedAt')):
                    item=QTableWidgetItem(str(c.get(key,'')))
                    if col==0:item.setData(Qt.ItemDataRole.UserRole,str(c.get('ID','')))
                    self.docker_table.setItem(row,col,item)
                if c.get('ID')==old_id:selected_row=row
            if selected_row is not None:self.docker_table.selectRow(selected_row)
            self.docker_table.blockSignals(False)
            self.docker_filter_rows(self.docker_search.text())
            if old_id != (self.docker_selected() or {}).get('ID'):
                self.docker_selection_changed()
            elif selected_row is not None:
                self.docker_details.setPlainText('\n'.join(f'{k}: {containers[selected_row].get(k, "")}' for k in ('Names','ID','Image','State','Status','Ports','Command','CreatedAt')))
            self.docker_note.setText(f'{len(containers)} container(s), including stopped containers')
            self.docker_connection_label.setText('Connected: '+('Local Docker Desktop' if self.docker_mode.currentIndex()==0 else 'Remote Docker (SSH)'))
            if not containers:self.docker_output.setPlainText('No containers found. Docker is available, but none have been created.')
        elif action in ('stats','stats_live'):
            try:
                d=json.loads(out.strip().splitlines()[-1])
                cpu=float(str(d.get('CPUPerc','0')).replace('%',''))
                mem=str(d.get('MemUsage','—'));net=str(d.get('NetIO','—'));disk=str(d.get('BlockIO','—'))
                used=str(d.get('MemPerc','0')).replace('%','')
                values={'CPU':(f'{cpu:.1f}%',cpu),'Memory':(mem,float(used)),'Network I/O':(net,0),'Disk I/O':(disk,0)}
                for key,(label,pct) in values.items():
                    val,bar,graph=self.docker_metrics[key];val.setText(label);bar.setValue(max(0,min(100,int(pct))))
                    if key in ('Network I/O','Disk I/O'):
                        # Plot received/read total as a per-poll delta, never claim whole-system network traffic.
                        token=label.split('/')[0].strip()
                        match=re.match(r'([\d.]+)\s*([kMGT]?B)',token)
                        scale={'B':1,'kB':1e3,'MB':1e6,'GB':1e9,'TB':1e12}
                        total=float(match.group(1))*scale.get(match.group(2),1) if match else 0
                        previous=getattr(graph,'last_total',None)
                        graph.add_value(max(0,total-previous) if previous is not None else 0)
                        graph.last_total=total
                    else:graph.add_value(pct)
                self.docker_monitor_label.setText('Live snapshot • '+str(d.get('Name','container'))+' • '+datetime.datetime.now().strftime('%H:%M:%S'))
                self.docker_stats_history.append(d)
            except (ValueError,IndexError,TypeError) as exc:
                if action!='stats_live':self.docker_output.setPlainText('Could not parse stats: '+str(exc))
        else:
            if action=='inspect':
                try:out=json.dumps(json.loads(out),indent=2)
                except ValueError:pass
            self.docker_output.setPlainText(out.strip() or '(No output)')
            self.docker_note.setText(action.replace('_',' ').capitalize()+' completed')
            if action in ('start','stop','restart','remove','create','compose_up','compose_down'):
                QTimer.singleShot(350,self.docker_status)
        if action!='stats_live':self.record_event('Docker '+action+' completed')

    def file_properties(self):
        if not self.require_connection():return
        name=self.selected_remote()
        if not name:return
        try:
            entry=self.sftp.stat(posixpath.join(self.remote_path,name))
            QMessageBox.information(self,'File Properties',f'Name: {name}\nSize: {entry.st_size:,} bytes\nPermissions: {stat.S_IMODE(entry.st_mode):04o}\nOwner UID: {entry.st_uid}\nGroup GID: {entry.st_gid}')
        except Exception as exc:QMessageBox.warning(self,'Properties unavailable',str(exc))

    def rename_remote(self):
        if not self.require_connection():return
        name=self.selected_remote()
        if not name:return
        new,ok=QInputDialog.getText(self,'Rename','New name:',text=name)
        if not ok or not new or new==name:return
        if new in ('.','..') or '/' in new or '\\' in new:
            QMessageBox.warning(self,'Invalid name','Enter a file or folder name only.');return
        source=posixpath.join(self.remote_path,name)
        target=posixpath.join(self.remote_path,new)
        try:
            try:self.sftp.stat(target)
            except IOError:pass
            else:
                QMessageBox.warning(self,'Already exists','Destination already exists.');return
            self.sftp.rename(source,target)
            self.record_event(f'Renamed {name} to {new}')
            self.refresh_remote()
        except Exception as exc:QMessageBox.warning(self,'Rename failed',str(exc))

    def delete_remote(self):
        if not self.require_connection():return
        name=self.selected_remote()
        if not name:return
        path=posixpath.join(self.remote_path,name)
        if QMessageBox.question(self,'Delete remote item?',f'Permanently delete {path}?\nNonempty folders cannot be deleted here.',QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,QMessageBox.StandardButton.No)!=QMessageBox.StandardButton.Yes:return
        try:
            entry=self.sftp.stat(path)
            if stat.S_ISDIR(entry.st_mode):self.sftp.rmdir(path)
            else:self.sftp.remove(path)
            self.record_event('Deleted '+path)
            self.refresh_remote()
        except Exception as exc:QMessageBox.warning(self,'Delete failed',str(exc))

    def clipboard_action(self,name):
        QMessageBox.information(self,name,'Remote clipboard operations are not implemented yet. Use Rename for a single-item move in the current directory.')

    def set_file_icon_size(self, large):
        self.file_icons_large = bool(large)
        self.file_table.setIconSize(QSize(32, 32) if large else QSize(16, 16))
        self.file_table.verticalHeader().setDefaultSectionSize(42 if large else 28)
        self.status.setText(('Large' if large else 'Small') + ' file icons')
        self.change_page(1)

    def change_page(self,index):
        self.pages.setCurrentIndex(index)
        if hasattr(self, 'docker_resolution_warning'):
            QTimer.singleShot(0, self._update_docker_resolution)
        for i,b in enumerate(self.nav_buttons):b.setChecked(i==index)
        self.status.setText(f'{PAGES[index]}  |  ' + ('Connected to SFTP server' if self.sftp else 'Not connected'))

    def filter_files(self,query):
        if self.sftp:
            entries=[e for e in self.remote_entries if query.casefold() in e.filename.casefold()]
            rows=[]
            for e in entries:
                folder=stat.S_ISDIR(e.st_mode)
                size='—' if folder else (f'{e.st_size:,} B' if e.st_size<1024 else f'{e.st_size/1024:.1f} KB')
                modified=datetime.datetime.fromtimestamp(e.st_mtime).strftime('%Y-%m-%d %H:%M')
                rows.append((e.filename,size,'Folder' if folder else 'File',modified))
        else:
            rows=[]
        self.offline_notice.setVisible(not bool(self.sftp))
        self.file_table.setVisible(bool(self.sftp))
        self.file_table.setSortingEnabled(False)
        self.file_table.setRowCount(len(rows))
        for row,values in enumerate(rows):
            for col,value in enumerate(values):
                cell=QTableWidgetItem(str(value))
                if col==0:
                    cell.setIcon(icon('folder' if values[2]=='Folder' else 'file_small'))
                    cell.setData(Qt.ItemDataRole.UserRole,values[0])
                self.file_table.setItem(row,col,cell)
        self.file_table.setSortingEnabled(True)
        if hasattr(self,'status'):self.status.setText(f'{len(rows)} items  |  '+('SFTP connected' if self.sftp else 'Not connected'))

    def set_dark(self,value):
        self.dark=bool(value)
        self.theme_check.blockSignals(True)
        self.theme_check.setChecked(self.dark)
        self.theme_check.blockSignals(False)
        self.preferences.setValue('dark_mode',self.dark)
        self.apply_theme()

    def apply_theme(self):
        if self.dark:
            bg='#171225';surface='#272039';text='#f3eaff';border='#74639a';panel='#201930';hover='#493071';select='#50229a';entry='#120e1e'
        else:
            bg='#c4c4ce';surface='#e1e1e7';text='#171322';border='#777482';panel='#d5d5df';hover='#d1baf1';select='#5a12a1';entry='#ffffff'
        self.setStyleSheet("""
        QMainWindow, QWidget {background:%s;color:%s;font-family:"MS Shell Dlg 2", "Segoe UI";font-size:12px;}
        QMenuBar {background:%s;border:1px solid %s;padding:3px;}
        QMenuBar::item:selected {background:%s;}
        QMenu {background:%s;color:%s;border:2px outset %s;}
        QMenu::item:selected {background:%s;color:white;}
        QFrame#globeIndicator {background:%s;border:2px inset %s;}
        QLabel#globeLabel {font-size:9px;font-weight:bold;}
        QFrame#sidebar,QFrame#toolbar,QFrame#card {background:%s;border:2px outset %s;}
        QLabel#banner,QLabel#sectionTitle {background:#380083;color:white;font-weight:bold;border:2px outset #a78be0;padding:4px;}
        QLabel#banner {font-size:15px;}
        QLabel#status,QLabel#clock,QLabel#sideNote,QLabel#event {background:%s;border:2px inset %s;padding:5px;}
        QLabel#caption {color:%s;}
        QLabel#bigValue {font-size:21px;font-weight:bold;color:%s;}
        QPushButton {background:%s;color:%s;border:2px outset %s;padding:5px;text-align:center;min-height:25px;}
        QPushButton:hover {background:%s;}
        QPushButton:pressed {border:2px inset %s;}
        QPushButton#nav {text-align:left;padding:5px;}
        QPushButton#nav:checked {background:%s;color:white;border:2px inset #c8a5ff;}
        QPushButton#toolButton {min-height:70px;min-width:80px;}
        QPushButton#quickTransferButton {padding:2px 6px;min-height:0px;font-size:11px;}
        QLabel#offlineNotice {font-size:14px;color:%s;border:2px inset %s;background:%s;}
        QLineEdit,QTableWidget {background:%s;color:%s;border:2px inset %s;selection-background-color:#6330ae;selection-color:white;}
        QHeaderView::section {background:%s;color:%s;border:2px outset %s;padding:4px;}
        QCheckBox {padding:8px;}
        """ % (bg,text,surface,border,hover,surface,text,border,select,panel,border,panel,border,entry,border,text,'#c7a3ff' if self.dark else '#380083',surface,text,border,hover,border,select,entry,text,border,surface,text,border,text,border,entry))

        # Light mode: use a softer blue for Docker's alternating rows.
        # Dark mode retains the original navy-blue appearance.
        alternate_row_color = '#001b60' if self.dark else '#7398d0'
        self.setStyleSheet(self.styleSheet() + f'''
        QTableWidget {{alternate-background-color: {alternate_row_color};}}
        ''')

        header_bg = '#302641' if self.dark else '#d8d6df'
        header_fg = '#f5edff' if self.dark else '#171322'
        card_bg = bg
        self.setStyleSheet(self.styleSheet() + f'''
        QTableWidget QHeaderView::section {{
            background-color: {header_bg}; color: {header_fg};
            border: 1px solid {border}; padding: 4px;
        }}
        QFrame#card {{background-color: {card_bg}; border: 2px outset {border};}}
        QFrame#card QLabel {{background-color: {card_bg};}}
        ''')

    def closeEvent(self,event):
        if self.transfer_worker and self.transfer_worker.isRunning():
            QMessageBox.warning(self,'Transfer active','Wait for the transfer to finish before closing.')
            event.ignore()
            return
        self.disconnect_demo()
        event.accept()

    def demo_action(self,name):
        QMessageBox.information(self,'Feature not available',f'{name} is not implemented in v0.8.2.')

def main():
    if sys.platform == 'win32':
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('SFTPManager.Desktop')
        except (AttributeError, OSError):
            pass
    app=QApplication(sys.argv)
    app.setWindowIcon(QIcon(str(ASSETS / 'app.ico')))
    app.setApplicationName('SFTP Manager')
    app.setStyle('Fusion')
    window=Manager()
    window.show()
    sys.exit(app.exec())
