import re
from urlextract import URLExtract

def extractDomains(text):
    extractor = URLExtract()
    urls = extractor.find_urls(text)
    if len(urls) == 0: 
        return False
    else:
        return urls

def sqlstr(s):
    return '"' + str(s) + '"'

def extractIPAddresses(text):
    ipv4_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)'
    ipv4_addresses = re.findall(ipv4_pattern, text)
    if len(ipv4_addresses) == 0: 
        return False
    else:
        return ipv4_addresses


sensitive_files = ['/var/log/nginx/error.log', '/proc/self/fd/26', '/usr/local/nginx/conf/nginx.conf', '/var/log/nginx/access.log', '/var/www/html/xxe/index.php', '/home2/bin/stable/apache/php.ini', '/usr/local/lib/php.ini', '/etc/nginx/nginx.conf', '/usr/local/apache/conf/httpd.conf', '/etc/php5/fpm/php.ini', '/proc/net/route', '/var/log/ufw.log', '/etc/php/7.2/fpm/php.ini', '/etc/httpd/conf.d/httpd.conf', '/etc/php/7.3/fpm/pool.d/www.conf', '/etc/aliases', '.config/google-chrome-beta/Default/databases/Databases.db', '/proc/net/fib_trie', '/etc/php/7.2/fpm/pool.d/www.conf', '/etc/resolv.conf', '/etc/httpd/conf/httpd.conf', '/www/main.py', '/etc/ssh/id_ecdsa', '/var/log/mysql/mysql.log', '/proc/self/fd/20', '/proc/self/fd/19', '/proc/self/cwd', '/etc/php/7.4/fpm/php.ini', '/etc/apache2/sites-available/000-default.conf', '/etc/mail/aliases', '/etc/xinetd.conf', '/etc/rc.local', '/var/www/index.php', '/usr/local/apache/conf/extra/httpd-vhost.conf', '/usr/local/nginx/conf.d/default', '/etc/redis/redis.conf', '/var/log/samba/log.nmbd', '/www/index.php', '/var/log/apache2/error.log', '/etc/nginx/conf.d/default', '/var/log/error_log', '/etc/apt/sources.list', '/www/php4/php.ini', '/xampp/apache/conf/httpd.conf', '/proc/self/fd/6', '/root/.psql_history', '/etc/my.cnf', '/etc/hosts', '/home/www/htdocs/index.php', '/proc/self/stat', '/var/log/mail.info', '/var/log/postgresql/postgresql.log', '/var/www/html/index.html', '.config/google-chrome/Default/Session\\ Storage/LOG', '/home/www/htdocs/index.html', '/var/log/daemon.log', '/etc/hostname', 'id_rsa', '/etc/ssh/known_hosts', '/etc/nginx/sites-enabled/default', '/etc/apache/httpd.conf', '/etc/logrotate.conf', '/proc/self/fd/2', '/etc/ssh/ssh_config', '/proc/self/fd/30', '/etc/php/7.4/apache2/php.ini', '/home/httpd/conf/httpd.conf', '/etc/php/7.4/cli/php.ini', '/proc/self/fd/16', '/app/main.py', '/usr/share/pear/pearcmd.php', '/var/log/access_log', '/etc/ssh/id_ed25519', '/proc/self/fd/14', '/var/log/sshd.log', '/usr/bin/php5/bin/php.ini', '/etc/init.d/mysql', '/etc/termcap', '/etc/nginx/sites-available/default', '/etc/apache2/httpd.conf', '/etc/php5/apache2/php.ini', '/var/log/mysqlderror.log', '/proc/self/fd/8', '/var/www/html/index.php', '/usr/local/httpd/conf/httpd.conf', '/etc/php/7.1/fpm/php.ini', '/var/www/htdocs/index.html', '/proc/self/fd/18', '/usr/local/mysql/my.cnf', '/etc/httpd/logs/access_log', '/etc/php.ini', '/var/log/wtmp', '/var/log/httpd/access_log', '/var/log/apache2/access.log', '/usr/local/app/apache2/conf/extra/httpd-vhosts.conf', '/proc/self/fd/15', '/proc/self/fd/31', '/etc/php/7.0/fpm/pool.d/www.conf', '/etc/mysql/my.cnf', '/etc/issue', '/var/www/html/ssrf/index.php', '/proc/self/fd/0', '/proc/self/fd/34', '/etc/sendmail.cw\t', '/var/www/html/ssrf/ssrf.php', '/etc/gshadow', '/etc/apache2/conf-enabled/docker-php.conf', '/etc/php/php.ini', '/etc/php/7.3/fpm/php.ini', '/var/log/secure', '/var/www/html/xxe/xxe.php', '/var/log/samba/log.smbd', '/var/log/maillog', '/proc/sched_debug', '.config/google-chrome/Default/Web\\ Data', '/etc/phpmyadmin/config.inc.php', '/var/www/htdocs/index.php', '/var/log/boot.log', '/etc/httpd/conf.d/php.conf', '/etc/php5/fpm/conf.d', '/usr/local/nginx/sites-available/default', '.config/google-chrome/Default/Preferences', '/proc/self/fd/1', '/etc/samba/smb.conf', '/etc/inputrc', '/etc/hosts.allow', '/var/www/index.html', '.config/Code/databases/Databases.db', '/etc/host.conf', '/var/log/user.log', '/etc/sysconfig/network', '/var/log/audit/audit.log', '/proc/self/fd/10', '/var/log/ntp.log', '/etc/hosts.deny', '/etc/httpd/httpd.conf', '/etc/sudoers', '/data/www/index.php', '/etc/xinetd.d', '/usr/share/php/pearcmd.php', '.config/google-chrome/Default/Session Storage/LOG', '/etc/lsb-release', '/proc/self/fd/9', '/etc/php/7.0/fpm/php-fpm.conf', '/var/log/cups/error_log', '/etc/php/7.1/fpm/php-fpm.conf', '/var/log/mysql/mysql-slow.log', '/etc/init.d/httpd', '/etc/sendmail.cf', '/var/log/lastlog', '/proc/verison', '/etc/php/7.3/fpm/php-fpm.conf', '/var/log/kern.log', '/etc/nginx/conf.d/error2.conf', '/var/log/dpkg.log', '/var/www/xxe/xxe.php', '/etc/sysconfig/network-scripts/ifcfg-eth1', '/var/www/xxe/index.php', '/etc/fstab', '/var/www/ssrf/ssrf.php', '/proc/cmdline', '/NetServer/bin/stable/apache/php.ini', '/root/.pgpass', '/proc/self/fd/25', '.ssh', '/home/wwwroot/default/index.php', '/proc/self/fd/29', '/.dockerenv', '.config/google-chrome/Default/Login\\ Data', '/var/log/faillog', '/etc/ssh/id_rsa', '/proc/self/fd/17', '/etc/dovecot/dovecot.conf', '/proc/self/fd/24', '/etc/rsyncd.conf', '/etc/ld.so.conf', '/web/index.html', '/proc/self/fd/21', '/etc/bashrc', '.config/google-chrome-beta/Default/Login\\ Data', '/proc/self/fd/27', '/etc/php/7.2/fpm/php-fpm.conf', '/usr/local/apache/conf/php.ini', '/var/log/mysql.log', '/usr/local/php56/etc/php-fpm.conf', '/home/wwwroot/default/index.html', '/var/log/xorg.log', '/etc/php/7.1/fpm/pool.d/www.conf', '/www/uwsgi.ini', '/etc/php5/fpm/pool.d/www.conf', '/var/tmp/php-fpm.pid', '/etc/postfix/main.cf', '/etc/wgetrc', '/proc/self/fd/23', '/proc/self/cmdline', '/var/www/ssrf/index.php', '.config/Code/Cookies', '/www/index.html', '/usr/local/nginx/sites-enabled/default', '/home/www/logs/php-fpm.log', '/proc/self/fd/5', '/home/www/htdocs', '/var/mysql.log', '/etc/shadow', '/etc/environment', '/etc/network/interfaces', '/etc/sysctl.conf', '/www/app.py', '/etc/apache2/conf-available/docker-php.conf', '/var/log/btmp', '/var/log/mysql/error.log', '/proc/self/fd/11', '/proc/self/fd/35', '/etc/motd', '/etc/httpd/logs/error_log', '/var/log/acpid', '/app/uwsgi.ini', '/web/html/index.php', '/etc/mime.types', '/var/log/alternatives.log', '/web/index.php', '.config/google-chrome/Default/databases/Databases.db', '/etc/apache2/apache2.conf', '/proc/self/fd/3', '/proc/net/tcp', '/etc/ssh/sshd_config', '/xampp/apache/bin/php.ini', 'id_rsa.pub', '/var/log/httpd/error_log', '/etc/php/7.0/fpm/php.ini', '/proc/self/fd/7', '/var/www/html/apache/conf/httpd.conf', '/etc/mongodb.conf', '/etc/mail/sendmail.cf', '/usr/local/apache2/conf/httpd.conf', '/var/log/clamav/clamav.log', '/www/htdocs/index.php', '/proc/self/fd/28', '/usr/local/app/apache2/conf/httpd.conf', '/var/log/yum.log', '/var/log/messages', '/www/php5/php.ini', '/etc/nsswitch.conf', '/web/html/index.html', '/var/log/dmesg', '/var/log/auth.log', '.config/Code/CachedProfilesData/__default__profile__/extensions.user.cache', 'known_hosts', '/etc/apache2/sites-enabled/000-default.conf', '/usr/local/nginx/conf.d/error2.conf', '/usr/share/lib/php.ini', '/www/php/php.ini', '/etc/os-release', '/root/.bash_history', '/root/.my.cnf', '/proc/self/fd/12', '/app/app.py', '/etc/issue/net', '/var/log/access.log', '/var/spool/cron/crontabs/root', '/etc/group', '/etc/redhat-release', '/proc/self/fd/33', '/etc/protocols', '/www/conf/httpd.conf', '/etc/vsftpd/vsftpd.conf', 'authorized_keys', '/usr/local/apache2/conf/extra/httpd-vhosts.conf', '/proc/self/environ', '/proc/self/fd/32', '/proc/version', '/proc/self/fd/4', '/usr/local/app/php5/lib/php.ini', '/var/log/cron', '/proc/self/status', '/usr/local/apache2/conf/php.ini', '/usr/share/mysql/my.cnf', '/etc/ssh/id_dsa', '/proc/self/fd/13', '/etc/sysconfig/network-scripts/ifcfg-eth0', '/proc/net/udp', '/etc/sysconfig/iptables', '/etc/passwd', '/etc/httpd/logs/error.log', '/proc/mounts', '/var/log/error.log', '/etc/mtab', '/usr/local/nginx/nginx.conf', '/data/www/index.html', '/etc/apache2/ports.conf', '/usr/local/php56/etc/php.ini', '/proc/self/fd/22', '/proc/net/arp', '/usr/local/lib/php/pearcmd.php']

sensitive_semantics = {
    "Resource_Development": [
        "git clone", "svn checkout", "hg clone", "bzr branch", "apt-get install", "yum install", "dnf install", "zypper install",
        "pip install", "npm install", "composer install", "gem install", "cargo install", "conda install", "apk add",
        "brew install", "choco install", "pacman -S", "xbps-install", "emerge", "pkg install", "guix package", "port install",
        "spack install", "nix-env -iA", "scoop install", "winget install", "dotnet tool install", "luarocks install",
        "stack install", "vcpkg install"
    ],
    "Persistence": [
        "crontab -e", "systemctl enable", "systemctl start", "service --status-all",
        "update-rc.d", "init.d", "rc.local", "bashrc", "bash_profile", "zshrc", "profile", "login.defs", "sshd_config",
        "inetd.conf", "xinetd.conf", "hosts.allow", "hosts.deny", "sysctl.conf", "limits.conf", "pam.d", "security", "auditd",
        "authorized_keys"
    ],
    "Privilege_Escalation": [
        "su root", "sudo -i", "sudo su", "sudo -l", "find / -perm -4000", "find / -perm -2000"
    ],
    "Defense_Evasion": [
        "service auditd stop", "systemctl stop auditd", "iptables -F", "iptables -X", "iptables -Z", "ip6tables -F", "ip6tables -X",
        "ip6tables -Z", "firewall-cmd --reload", "setenforce 0", "permissive", "unconfined", "apparmor_status", "ulimit -u unlimited"
    ],
    "Discovery": [
        "http_proxy=", "nc -l", "ip a", "ip r"
    ],
    "Lateral_Movement": [
        " smb ", "smb-brute", "smb-enum-shares", "smb-vuln-ms17-010",
    ],
    "Collection": [
        "ps aux", "ps aux | grep", "ps -ef", "ps -ef | grep", "lsof", "lsof -i", "lsof -i :", "route",
    ],
    "Command_and_Control": [
        "-i >& /dev/tcp", "-e /bin/bash", "-e /bin/sh", "nc -lvp", "nc -nvlp", "nc -e", "nc -c", "ncat -lv", "ncat -lvnp", "ncat -e",
        "ncat -c"
    ],
    "Impact": [
        "HISTFILESIZE=0", "HISTSIZE=0", "> .bash_history", "> .zsh_history", "echo > /var/log/auth.log", "service auditd stop", "systemctl stop auditd", "firewall-cmd --reload","setenforce 0"]
}

sensitive_operations = {
    "Reconnaissance": [
        "whois", "dig", "nslookup", "host", "nmap", "masscan", "theharvester", "recon-ng", "maltego", "amass", "dnsenum", 
        "fierce", "shodan", "censys", "smbclient", "curl", "httping", "nikto", "dmitry", "onesixtyone", 
        "snmpwalk", "snmpget", "snmpset", "snmpbulkwalk", "snmpcheck", "nessuscli", "openvas-cli", "whatweb", "httprobe"
    ],
    "Resource_Development": [
        "wget", "gcc", "g++", "cc"
    ],
    "Initial_Access": [
        "medusa", "crackmapexec", "responder", "evil-winrm", "certutil", "bitsadmin"
    ],
    "Execution": [
        "bash", "sh", "zsh", "ksh", "tcsh", "dash", "fish", "ash", "busybox", "python", "perl", "ruby", "lua", "python3"
    ],
    "Persistence": [
        "crontab", "at", "cron", "anacron", "fcron", "chkconfig", "rsyslog", "syslog", "iptables", "ip6tables", "firewalld", "ufw", "selinux", "apparmor", "fail2ban", "knockd", "denyhosts", "sshguard", "ssh-keygen", "ssh-copy-id"
    ],
    "Privilege_Escalation": [
        "sudo", "chmod", "chown", "passwd", "useradd", "usermod", "groupadd"
    ],
    "Defense_Evasion": [
        "sestatus", "permissive", "unconfined", "apparmor_status", "aa-disable", "aa-teardown"
    ],
    "Credential_Access": [
        "ssh-keygen", "ssh-add", "ssh-copy-id", "john", "hydra", "hashcat", "cewl", "patator", "ncrack", "smbclient", "rpcclient", "smbmap", "nbtscan", "enum4linux", "ldapdomaindump", "bloodhound", "sharpHound", "kerbrute", "Rubeus", "Seatbelt"
    ],
    "Discovery": [
        "dirb", "dirsearch", "ldapsearch", "wfuzz", "ping", "netstat", "arp", "nmcli", "ss", "ffuf", "traceroute", "ifconfig", "ip a", "ip r", "route", "last", "lastlog", "w", "finger"
    ],
    "Lateral_Movement": [
        "ssh", "scp", "telnet", "openssl", "sshuttle", "rlogin", "rsh", "rexec", "rsh-server", "rexec-server", "rlogin-server", "rshd", "rexecd", "rlogind", "telnetd"
    ],
    "Collection": [
         "find", "locate", "whoami", "uname", "lsb_release", "id", "groups", "top", "htop"
    ],
    "Command_and_Control": [
        "socat", "nc", "netcat", "metasploit"
    ],
    "Exfiltration": [
        "mysql", "psql", "redis-cli", "mysqladmin", "bsondump", "mongo", "mongodump", "ftp", "mongoexport", "pg_dump", "redis-cli", "tftp", "lftp", "ncat", "rsync", "sqlmap"
    ],
    "Impact": [
        "systemctl", "init", "systemd", "service", "reboot"
    ]
}