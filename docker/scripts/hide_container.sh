#!/bin/bash


mkdir -p /opt/.system/runtime
mkdir -p /usr/local/sbin

cat > /opt/.system/runtime/cgroup << EOF
0::/init.scope
1:name=systemd:/system.slice/sshd.service
2:cpuset:/
3:cpu,cpuacct:/system.slice/sshd.service
4:blkio:/system.slice
5:memory:/system.slice/sshd.service
6:devices:/system.slice
7:freezer:/
8:net_cls,net_prio:/
9:perf_event:/
10:hugetlb:/
11:pids:/system.slice/sshd.service
EOF


cat > /opt/.system/runtime/mounts << EOF
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
devtmpfs /dev devtmpfs rw,nosuid,size=4096k,nr_inodes=65536,mode=755 0 0
/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0
tmpfs /run tmpfs rw,nosuid,noexec,relatime,size=1048576k,mode=755 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0
EOF


cat > /opt/.system/runtime/version_signature << EOF
5.15.0-89-generic
EOF


cat > /opt/.system/runtime/cmdline << EOF
BOOT_IMAGE=/vmlinuz-5.15.0-89-generic root=UUID=8868abf6-e17f-4296-8d69-1b280b23c0f2 ro quiet splash
EOF


cat > /opt/.system/runtime/environ << EOF
HOME=/ USER=root LANG=en_US.UTF-8 TERM=xterm-256color
EOF


uptime_value="$((RANDOM * 100 + 10000)).$(RANDOM)"
echo "$uptime_value $uptime_value" > /opt/.system/runtime/uptime


ERROR_MSG="Error: Writing to files is restricted on this system.
To transfer files use: scp -O [file] admin@[ip]:/tmp/"


cat > /usr/local/sbin/fecho << 'EOF'
if [[ "$*" == *">"* ]] || [[ "$*" == *">>"* ]] || [[ -n "$BASH_COMMAND" ]]; then
    echo "Error: Writing to files is restricted on this system." >&2
    echo "To transfer files use: scp -O [file] admin@[ip]:/tmp/" >&2
    exit 1
fi
printf '%s\n' "$*"
EOF

chmod +x /usr/local/sbin/fecho

rm -f /bin/echo /usr/bin/echo
ln -sf /usr/local/sbin/fecho /bin/echo
ln -sf /usr/local/sbin/fecho /usr/bin/echo

ALIAS_ECHO="alias echo='/usr/local/sbin/fecho'"
SHOPT_CMD="shopt -s expand_aliases"


for file in /etc/bash.bashrc /etc/profile /root/.bashrc /home/admin/.bashrc /etc/profile.d/00-aliases.sh; do
    [ ! -f "$file" ] && touch "$file"
    
    sed -i '/alias echo=/d' "$file"
    sed -i '/shopt -s expand_aliases/d' "$file"
    
    echo "$SHOPT_CMD" >> "$file"
    echo "$ALIAS_ECHO" >> "$file"
done

cat > /etc/profile.d/00-block-echo.sh << 'EOF'
shopt -s expand_aliases
alias echo='/usr/local/sbin/fecho'
export PATH="/usr/local/sbin:$PATH"

echo() {
    /usr/local/sbin/fecho "$@"
}
export -f echo
EOF

chmod +x /etc/profile.d/00-block-echo.sh

cat > /bin/sh.wrapper << 'EOF'
#!/bin/bash

export PATH="/usr/local/sbin:$PATH"
alias echo='/usr/local/sbin/fecho'
shopt -s expand_aliases
exec /bin/bash "$@"
EOF

chmod +x /bin/sh.wrapper

if [ -f /bin/sh ] && [ ! -L /bin/sh ]; then
    mv /bin/sh /bin/sh.original
    ln -sf /bin/sh.wrapper /bin/sh
fi

cat > /usr/local/sbin/touch << 'EOF'
#!/bin/bash
echo "Error: Writing to files is restricted on this system." >&2
echo "To transfer files use: scp -O [file] admin@[ip]:/tmp/" >&2
exit 1
EOF

cat > /usr/local/sbin/mkdir << 'EOF'
#!/bin/bash
echo "Error: Writing to files is restricted on this system." >&2
echo "To transfer files use: scp -O [file] admin@[ip]:/tmp/" >&2
exit 1
EOF


cat > /usr/local/sbin/cat << 'EOF'
#!/bin/bash
# Pentru citire normală, rulează cat original
if [ $# -gt 0 ] && [ ! "$*" == *">"* ]; then
    exec /bin/cat.original "$@"
fi

echo "Error: Writing to files is restricted on this system." >&2
echo "To transfer files use: scp -O [file] admin@[ip]:/tmp/" >&2
exit 1
EOF

cat > /usr/local/sbin/cp << 'EOF'
#!/bin/bash
echo "Error: Copying files is restricted on this system." >&2
echo "To transfer files use: scp -O [file] admin@[ip]:/tmp/" >&2
exit 1
EOF


cat > /usr/local/sbin/mv << 'EOF'
#!/bin/bash
echo "Error: Moving files is restricted on this system." >&2
echo "To transfer files use: scp -O [file] admin@[ip]:/tmp/" >&2
exit 1
EOF


cat > /usr/local/sbin/nano << 'EOF'
#!/bin/bash
echo "Error: Editing files is restricted on this system." >&2
echo "To transfer files use: scp -O [file] admin@[ip]:/tmp/" >&2
exit 1
EOF


cat > /usr/local/sbin/vim << 'EOF'
#!/bin/bash
echo "Error: Editing files is restricted on this system." >&2
echo "To transfer files use: scp -O [file] admin@[ip]:/tmp/" >&2
exit 1
EOF


cat > /usr/local/sbin/vi << 'EOF'
#!/bin/bash
echo "Error: Editing files is restricted on this system." >&2
echo "To transfer files use: scp -O [file] admin@[ip]:/tmp/" >&2
exit 1
EOF


cat > /usr/local/sbin/systemctl << 'EOF'
#!/bin/bash

show_unit() {
    echo "● $1 - ${2:-Service}"
    echo "   Loaded: loaded (/lib/systemd/system/$1; enabled; vendor preset: enabled)"
    echo "   Active: active (running) since $(date -d '5 hours ago' '+%a %Y-%m-%d %H:%M:%S %Z'); 5h ago"
    echo "   Process: 1234 ExecStart=/usr/sbin/${1%.service} (code=exited, status=0/SUCCESS)"
    echo "   Main PID: 5678 (${1%.service})"
    echo "   Tasks: 12"
    echo "   CGroup: /system.slice/$1"
    echo "           └─5678 /usr/sbin/${1%.service}"
    echo ""
}

case "$1" in
    status)
        if [ -n "$2" ]; then
            show_unit "$2"
        else
            echo "systemctl: command requires a unit name"
        fi
        ;;
    list-units|list-unit-files)
        echo "UNIT                                   LOAD   ACTIVE SUB     DESCRIPTION"
        echo "sshd.service                          loaded active running OpenSSH server daemon"
        echo "rsyslog.service                       loaded active running System Logging Service"
        echo "cron.service                          loaded active running Regular background program processing daemon"
        echo "networking.service                    loaded active running Network management"
        echo "systemd-logind.service                loaded active running Login Service"
        echo "systemd-journald.service              loaded active running Journal Service"
        echo "dbus.service                          loaded active running D-Bus System Message Bus"
        echo "systemd-udevd.service                 loaded active running udev Kernel Device Manager"
        echo ""
        echo "LOAD   = Reflects whether the unit definition was properly loaded."
        echo "ACTIVE = The high-level unit activation state."
        echo "SUB    = The low-level unit activation state."
        ;;
    *)
        echo "Unknown systemctl command: $1"
        echo "Try 'systemctl --help' for more information."
        exit 1
        ;;
esac
exit 0
EOF


cat > /usr/local/sbin/lsblk << 'EOF'
#!/bin/bash

echo "NAME        MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS"
echo "sda           8:0    0   40G  0 disk "
echo "├─sda1        8:1    0    1M  0 part "
echo "├─sda2        8:2    0  512M  0 part /boot/efi"
echo "└─sda3        8:3    0 39.5G  0 part /"
echo "sr0          11:0    1 1024M  0 rom  "
EOF


chmod +x /usr/local/sbin/echo
chmod +x /usr/local/sbin/touch
chmod +x /usr/local/sbin/mkdir
chmod +x /usr/local/sbin/cat
chmod +x /usr/local/sbin/cp
chmod +x /usr/local/sbin/mv
chmod +x /usr/local/sbin/nano
chmod +x /usr/local/sbin/vim
chmod +x /usr/local/sbin/vi
chmod +x /usr/local/sbin/systemctl
chmod +x /usr/local/sbin/ps
chmod +x /usr/local/sbin/lsblk


mount_fake_files() {
    mount --bind /opt/.system/runtime/cgroup /proc/1/cgroup
    mount --bind /opt/.system/runtime/cgroup /proc/self/cgroup
    mount --bind /opt/.system/runtime/mounts /proc/mounts
    mount --bind /opt/.system/runtime/version_signature /proc/version_signature
    mount --bind /opt/.system/runtime/cmdline /proc/cmdline
    mount --bind /opt/.system/runtime/uptime /proc/uptime
    mount --bind /opt/.system/runtime/environ /proc/1/environ
    
    
    if [ -f /.dockerenv ]; then
        rm -f /.dockerenv
    fi
}

install_wrappers() {
    if [ -f /sbin/cat ] && [ ! -f /bin/cat.original ]; then
        cp /sbin/cat /bin/cat.original
    fi
    
    ln -sf /usr/local/sbin/echo /bin/echo
    ln -sf /usr/local/sbin/echo /usr/bin/echo
    ln -sf /usr/local/sbin/touch /bin/touch
    ln -sf /usr/local/sbin/touch /usr/bin/touch
    ln -sf /usr/local/sbin/mkdir /bin/mkdir
    ln -sf /usr/local/sbin/mkdir /usr/bin/mkdir
    ln -sf /usr/local/sbin/cat /bin/cat
    ln -sf /usr/local/sbin/cat /usr/bin/cat
    ln -sf /usr/local/sbin/cp /bin/cp
    ln -sf /usr/local/sbin/cp /usr/bin/cp
    ln -sf /usr/local/sbin/mv /bin/mv
    ln -sf /usr/local/sbin/mv /usr/bin/mv
    ln -sf /usr/local/sbin/nano /bin/nano
    ln -sf /usr/local/sbin/nano /usr/bin/nano
    ln -sf /usr/local/sbin/vim /bin/vim
    ln -sf /usr/local/sbin/vim /usr/bin/vim
    ln -sf /usr/local/sbin/vi /bin/vi
    ln -sf /usr/local/sbin/vi /usr/bin/vi
    ln -sf /usr/local/sbin/systemctl /bin/systemctl
    ln -sf /usr/local/sbin/systemctl /usr/bin/systemctl
    ln -sf /usr/local/sbin/lsblk /bin/lsblk
    ln -sf /usr/local/sbin/lsblk /usr/sbin/lsblk
    
    echo 'enable -n echo' >> /etc/bash.bashrc
    echo 'enable -n echo' >> /root/.bashrc
    echo 'enable -n echo' >> /home/admin/.bashrc
    
    echo 'export PATH=/usr/local/sbin:$PATH' >> /etc/bash.bashrc
}

mount_fake_files

install_wrappers


mkdir -p /run/systemd/system
mkdir -p /lib/systemd/system

export PATH="/usr/local/sbin:$PATH"
hash -r 2>/dev/null || true


cat > /lib/systemd/system/sshd.service << EOF
[Unit]
Description=OpenSSH server daemon
After=network.target

[Service]
ExecStart=/usr/sbin/sshd -D
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartPreventExitStatus=255

[Install]
WantedBy=multi-user.target
EOF


hostname srv-web-03
exit 0