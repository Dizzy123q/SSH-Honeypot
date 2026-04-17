#!/bin/bash

# creare director pentru fisierele capcana
mkdir -p honeypot_files

# fisier cu parole
cat > honeypot_files/passwords.txt << EOF
# Credentiale server producție
admin_prod: Sup3rS3cur3P@ss2023!
database_root: DBm@st3rK3y2023
backup_service: B@ckupSyst3m!2023
vpn_access: VPN@cc3ss2023!
cloud_admin: Cl0udM@n@g3r#2023

# API Keys
AWS_SECRET_KEY: AKIAJSIE8DJFNIE1D8JF
AZURE_API_KEY: Az928dJdnDKS39sskKSj38DjSKdj
GITHUB_TOKEN: ghp_Kd8dJdn3jDnei8DjdJdn38djDkd9dJDN

# SSH Keys (hashed)
dev_server: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDV+38n9g6vM9QuUnH6CnkeDCZ[...]
EOF

# fisier de configurare 
cat > honeypot_files/server_config.yaml << EOF
# Server Configuration
server:
  host: 192.168.1.100
  port: 5432
  debug: false
  environment: production

database:
  host: db.internal.company.com
  port: 5432
  username: dbadmin
  password: Pr0d@dm1nDB!
  database: customer_records

api:
  secret_key: "sk_live_Kd83jDnekDm39DkeKd83jD"
  endpoint: 
  rate_limit: 100

backup:
  schedule: "0 2 * * *"  # Daily at 2 AM
  target: "s3://company-backups/production/"
  retention: 30  # days
EOF

# baza de date
cat > honeypot_files/credentials.db << EOF
SQLite format 3\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT);
EOF

# lista clienti fictiva
cat > honeypot_files/client_list.csv << EOF
ID,Name,Email,Phone,Address,Card,CVV,ExpiredDate

EOF

# arhivă de backup
echo "..." > honeypot_files/backup_data.txt
tar -czf honeypot_files/backup.tar.gz honeypot_files/backup_data.txt
rm honeypot_files/backup_data.txt

# istoric bash cu comenzi
cat > honeypot_files/.bash_history << EOF
ls -la
cd /home/admin
mysql -u root -p
sudo cat /etc/shadow
grep -r "password" /etc/
ssh-keygen -t rsa
scp backup.tar.gz admin@backup-server:/backups/
mysql -u admin -p"AdminP@ss123" customer_db
git clone git@github.com:company/private-repo.git
curl -X POST -d "username=admin&password=Admin123" https://api.internal.company/login
python3 -c "import os; os.system('cat /etc/passwd')"
cd important_files
ls -la
cat passwords.txt
sudo netstat -tulpn
vim server_config.yaml
sqlite3 credentials.db
tar -xzf backup.tar.gz
exit
EOF

# fisier cu chei SSH
cat > honeypot_files/ssh_keys.txt << EOF
# Private SSH keys backup - DO NOT SHARE
# Development server
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAtSi4K1xvZ+jRrJz4DjV7LoCtB7gYP8sBLCQNUPbLpbXErcJuOzfO
ScRgI77HW3OI9qUkKvQM/x1R3ZsQEjpq0lYnraBrYQF5kFkgCmj2pBZ/WQnR4YlCk0XsYY
6tQHsLhANE4UWnDKqoJ0rJd/zK9oVCCakHsXe5EwDRaRDuDqcHKM13A+v3w8eBbO5Lp7/5
Qvvb47iVxcuMFJ4DYzTbU5kBRQe1JbYcmh+tCCv0pyIzRJoHgC3jxKHyg3yZZxnCNUQQjX
TOTT+nPVZc8NRY
-----END OPENSSH PRIVATE KEY-----

# Production server
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAw5ffoL5GbUGNsXVxCzd/Oq7rJFxrIHe6FkZjuuBJWs0ARrpj5fK1
MlDfJHeFzBfiO6ukTFaLZV0YrF8Ica0U6J2hJ3esV9ZuZ5TVMPVQYt1tQyi2Cyo8xKcUPw
NQJ4M4QH28C0Wsou4hdZjmL2TIm8zG8l2EZlYYmXhFVOJDsKNRzIReUR9ZVnzl936OQyOB
-----END OPENSSH PRIVATE KEY-----
EOF

# configuratie pentru un demon
cat > honeypot_files/daemon.conf << EOF
# Configuration for internal service
# Last updated: 2023-03-15

[Service]
User=service_user
Group=service_group
WorkingDirectory=/var/service
ExecStart=/usr/bin/service --config /etc/service/config.json

[Credentials]
Username=service_admin
Password=S3rv1c3_Adm1n!
TokenExpiry=86400

[Database]
Host=192.168.10.50
Port=5432
Database=service_db
User=db_service_user
Password=dbS3rv1c3P@ss!

[API]
Endpoint=
Key=svc_api_key_39d8e7f2cba
Secret=svc_secret_key_83jen3j38dj3
EOF

