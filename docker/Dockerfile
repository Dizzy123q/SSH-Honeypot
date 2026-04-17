# imagine  Debian 12 
FROM debian:12

# instalam pachetele necesare
RUN apt-get update && apt-get install -y \
    openssh-server \
    bash \
    coreutils \
    net-tools \
    procps \
    iputils-ping \
    curl \
    wget \
    less \
    grep \
    sed \
    gawk \
    tar \
    gzip \
    sudo \
    man-db \
    lsof \
    iptables \
    psmisc \
    sysvinit-utils \
    netcat-openbsd \
    iproute2 \
    apt-utils \
    sqlite3 \
    python3 \
    python3-pip \
    rsyslog \
    locales \
    ca-certificates \
    git \
    unzip \
    openssl \
    tmux \
    file \
    findutils \
    && rm -rf /var/lib/apt/lists/*

# configurare locala
RUN sed -i 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    locale-gen
ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8

# configurare serviciu SSH
RUN mkdir -p /var/run/sshd /root/.ssh
RUN echo 'root:password' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# crearea utilizatorilor fictivi
RUN useradd -m -s /bin/bash admin && echo 'admin:admin' | chpasswd && \
    useradd -m -s /bin/bash developer && echo 'developer:dev' | chpasswd && \
    useradd -m -s /bin/bash support && echo 'support:support' | chpasswd

# blocare completa schimbare parole si management utilizatori
RUN chmod 000 /usr/bin/passwd /usr/sbin/chpasswd && \
    chmod 000 /usr/sbin/useradd /usr/sbin/adduser /usr/sbin/userdel /usr/sbin/usermod && \
    chmod 000 /usr/sbin/groupadd /usr/sbin/groupdel

# protejare fisiere sistem critice
RUN chmod 444 /etc/passwd && \
    chmod 400 /etc/shadow && \
    chmod 444 /etc/group

# creare wrapper-uri cu mesaje de eroare realiste
RUN echo '#!/bin/bash\necho "passwd: Permission denied (you must be root)"\nexit 1' > /usr/bin/passwd && \
    echo '#!/bin/bash\necho "useradd: Permission denied (you must be root)"\nexit 1' > /usr/sbin/useradd && \
    echo '#!/bin/bash\necho "adduser: Permission denied (you must be root)"\nexit 1' > /usr/sbin/adduser && \
    chmod +x /usr/bin/passwd /usr/sbin/useradd /usr/sbin/adduser

# blocare si alte comenzi de management
RUN echo '#!/bin/bash\necho "su: Permission denied"\nexit 1' > /bin/su && \
    chmod +x /bin/su

# blocheaza accesul direct la root prin SSH
RUN sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# blocheaza su complet
RUN chmod 000 /bin/su /usr/bin/su

# crearea structurii de directoare pentru fisiere capcana
RUN mkdir -p /usr/local/share/app-data/.config/ \
    /etc/systemd/system.private.d/ \
    /var/cache/apt-archives/partial/.old/ \
    /srv/data/.archive/ \
    /var/local/backup-history/ \
    /usr/local/share/app-data/.ssh_backup/ \
    /opt/.maintenance/scripts/

# copierea fisierelor capcana
COPY config/honeypot_files/passwords.txt /usr/local/share/app-data/.config/credentials.txt
COPY config/honeypot_files/server_config.yaml /etc/systemd/system.private.d/service-config.yaml
COPY config/honeypot_files/credentials.db /var/cache/apt-archives/partial/.old/cache.db
COPY config/honeypot_files/client_list.csv /srv/data/.archive/customers_2023.csv
COPY config/honeypot_files/backup.tar.gz /var/local/backup-history/.system-backup.tar.gz
COPY config/honeypot_files/ssh_keys.txt /usr/local/share/app-data/.ssh_backup
COPY config/honeypot_files/daemon.conf /opt/.maintenance/scripts/services.conf

# copierea fisierelor bash history
COPY config/honeypot_files/.bash_history /root/.bash_history
COPY config/honeypot_files/.bash_history /home/admin/.bash_history
RUN chown admin:admin /home/admin/.bash_history

# copierea scripturilor in container
COPY docker/scripts/hide_container.sh /usr/local/bin/hide_container.sh
COPY docker/scripts/network_restrictions.sh /usr/local/bin/network_restrictions.sh
COPY docker/scripts/block_network.sh /usr/local/bin/block_network.sh
COPY docker/scripts/monitor_iptables.sh /usr/local/bin/monitor_iptables.sh
COPY docker/scripts/startup.sh /usr/local/bin/startup.sh
RUN chmod +x /usr/local/bin/*.sh


# prompt PS1 pentru utilizatori
RUN echo "export PS1='\u@srv-web-03:\w\$ '" >> /etc/bash.bashrc
RUN echo "export PS1='\u@srv-web-03:\w\$ '" >> /root/.bashrc
RUN echo "export PS1='\u@srv-web-03:\w\$ '" >> /home/admin/.bashrc


# configurare bash history 
RUN echo 'export HISTCONTROL=""' >> /etc/bash.bashrc && \
    echo 'export HISTSIZE=10000' >> /etc/bash.bashrc && \
    echo 'export HISTFILESIZE=10000' >> /etc/bash.bashrc && \
    echo 'shopt -s histappend' >> /etc/bash.bashrc && \
    echo 'PROMPT_COMMAND="history -a"' >> /etc/bash.bashrc

# aplicam si pentru root
RUN echo 'export HISTCONTROL=""' >> /root/.bashrc && \
    echo 'export HISTSIZE=10000' >> /root/.bashrc && \
    echo 'export HISTFILESIZE=10000' >> /root/.bashrc && \
    echo 'shopt -s histappend' >> /root/.bashrc && \
    echo 'PROMPT_COMMAND="history -a"' >> /root/.bashrc

# aplicam si pentru admin
RUN echo 'export HISTCONTROL=""' >> /home/admin/.bashrc && \
    echo 'export HISTSIZE=10000' >> /home/admin/.bashrc && \
    echo 'export HISTFILESIZE=10000' >> /home/admin/.bashrc && \
    echo 'shopt -s histappend' >> /home/admin/.bashrc && \
    echo 'PROMPT_COMMAND="history -a"' >> /home/admin/.bashrc

    

# configurare fisiere logs false
RUN touch /var/log/syslog /var/log/auth.log /var/log/kern.log
RUN echo "Dec 10 08:45:13 srv-web-03 systemd[1]: Started System Logging Service." >> /var/log/syslog
RUN echo "Dec 10 08:45:14 srv-web-03 systemd[1]: Starting System Logging Service..." >> /var/log/syslog
RUN echo "Dec 10 08:48:22 srv-web-03 kernel: [    0.000000] Linux version 5.15.0-89-generic" >> /var/log/syslog
RUN echo "Dec 10 08:50:33 srv-web-03 sshd[1234]: Server listening on 0.0.0.0 port 22." >> /var/log/syslog

# setare hostname
RUN echo "srv-web-03" > /etc/hostname

# Expune portul SSH
EXPOSE 22

# Pornire servicii la start
CMD ["/usr/local/bin/startup.sh"]