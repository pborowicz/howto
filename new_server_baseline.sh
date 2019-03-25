#!/bin/bash
### UNCOMMENT NEXT 2 LINES FOR DEBUGGING
#set -x
#trap read debug
logsterr=/var/log/baselinesterr
logstout=/var/log/baselinestout
MESSAGE=''
MYSQL=0
PSQL=0
BASE=0
AWEB=0
NWEB=0
SSLT=0

#Function to exit with error

err ()
{
    echo $MESSAGE
    echo $MESSAGE >> $logsterr
    echo "Please check $logsterr or $logstout for more information"
    exit 1;
}

HELP ()
{
    echo "USAGE: baseline.sh [OPTIONS]..."
    echo "-h displays this listing"
    echo "-b for basic server requirements"
    echo "-p for plsql"
    echo "-m for mysql"
    echo "-n for a nginx web server"
    echo "-a for an apache web server"
    exit 0
}

#Generate a sysadmin user and set random temp password to be changed at first login

USR ()
{
echo "Adding sysadmin user"
useradd sysadmin >> $logstout 2>> $logsterr
if [ -e /home/sysadmin/tmppass.txt ]
then
rm -f /home/sysadmin/tmppass.txt
fi
cat /dev/urandom|tr -dc 'a-zA-Z0-9!@#$%^&*()_+?><~\;'|fold -w 12|head -n 1 >> /home/sysadmin/tmppass.txt
chown sysadmin:sysadmin /home/sysadmin/tmppass.txt >> $logstout 2>> $logsterr
if ! cat /home/sysadmin/tmppass.txt|passwd --stdin sysadmin
then
    MESSAGE="An error has occured while setting the sysadmin password, please set this manually"
    err
fi
#chage -d 0 sysadmin >> $logstout 2>> $logsterr

#ssh setup for pub key on ssh and 2 factor auth

echo "Begining configuration for sysadmin user whose password is $(cat /home/sysadmin/tmppass.txt)"
mkdir /home/sysadmin/.ssh >> $logstout 2>> $logsterr
chmod 700 /home/sysadmin/.ssh >> $logstout 2>> $logsterr
chown sysadmin:sysadmin /home/sysadmin/.ssh >> $logstout 2>> $logsterr
echo "" >> /home/sysadmin/.ssh/authorized_keys
echo '# Paul Borrowicz
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUd3WqaajEsJMr/i0+OMnJWvi6jTlIh5OkL/+2WqpuUU5aOt0+HYa8nPvISOgOROuceKfzl7a4qpX9G0mS8mWpLVMnuFS8BPNbPlIWLpieFRHbKckldv7WJKv4Ra3iZiU/aOyOw/OV/8GfsibX99Ah35QwjLLbpaA7/CI+Hykz/IJb67q1JxgQsc847xQPOu1w21PvZXRNFg57yIIHFT2GuTFAeGH7cjnGCyPOzZsh8D4eO2cU2PhJdyTsOHxWq2xLxZJdC4nHtKYF3vCLjWm6oWkLCgQOz2Ve8VcILZIWbL6I9P/eEt+r2DV63wgAMswJa88o3M0PdLAqa+ie8/Nd paul@linux-fxyz.suse' >> /home/sysadmin/.ssh/authorized_keys

echo "sysadmin configuration complete"
}

#Add epel

UPDATES ()
{
echo "Adding EPEL repositories"
if ! rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm >> $logstout 2>> $logsterr
then
    MESSAGE="An error has occured while adding the epel repositories"
    err
fi
yum -y clean metadata >> $logstout 2>> $logsterr
yum -y clean dbcache >> $logstout 2>> $logsterr
yum -y makecache >> $logstout 2>> $logsterr
echo "Succesfully added EPEL repositories"

#System update and required package installation

echo "Begining updates"
if ! yum -y update >> $logstout 2>> $logsterr
then
    MESSAGE="An error has occured during package updates"
    err
fi
echo "Updates complete"
echo "Adding Developement Tools"
if ! yum -y groupinstall "Development Tools" >> $logstout 2>> $logsterr
then
    MESSAGE="An error has occured adding the developement tools"
    err
fi
echo "Development tools have been succesfully added"
echo "Adding supplimentary packages"
if ! yum -y install pam-devel ssldump screen fail2ban setools policycoreutils-python.x86_64 selinux-policy-targeted.noarch bind-utils.x86_64 vim dstat.noarch tcpdump.x86_64 >> $logstout 2>> $logsterr
then
    MESSAGE="An error has occured adding supplimentary packages"
    err
fi
echo "Succesfully added supplimentary packages"

#Initiate services on boot

echo "Setting up boot preferences and initializing services"
chkconfig fail2ban on >> $logstout 2>> $logsterr
chkconfig restorecond on >> $logstout 2>> $logsterr
chkconfig ntpd on >> $logstout 2>> $logsterr
service fail2ban start >> $logstout 2>> $logsterr
service restorecond start >> $logstout 2>> $logsterr
service ntpd start >> $logstout 2>> $logsterr
echo "Boot preferences and service initialization complete"
}

#Firewall setup

FIREWALL ()
{
echo "Setting up iptables"
if ! iptables -F >> $logstout 2>> $logsterr
then
    MESSAGE="Error occured flushing old iptables"
    err
fi
if ! iptables -P INPUT DROP >> $logstout 2>> $logsterr
then
    MESSAGE="An error has occured setting drop to the input policy chain"
    err
fi
if ! iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT -m comment --comment "Handling Session States" >> $logstout 2>> $logsterr
then
    MESSAGE="An error has occured adding tcp session handling a rule"
    err
fi
if ! iptables -A INPUT -p tcp --dport 22 -j ACCEPT -m comment --comment "SSH Rule" >> $logstout 2>> $logsterr
then
    MESSAGE="An error has occured creating a rule for ssh sessions"
    err
fi
if ! service iptables save >> $logstout 2>> $logsterr
then
    MESSAGE="An error has occured saving iptables rule"
    err
fi
if ! service iptables restart >> $logstout 2>> $logsterr
then
    MESSAGE="An error has occured restarting iptables"
    err
fi
echo "iptables setup complete"
echo "Begining ip6tables setup"
if ! ip6tables -F >> $logstout 2>> $logsterr
then
    MESSAGE="An error has occured flushing old ip6tables"
    err
fi
if ! ip6tables -P INPUT DROP >> $logstout 2>> $logsterr
then
    MESSAGE="An error has occured setting drop to the input policy chain for ipv6"
    err
fi
if ! ip6tables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT -m comment --comment "Handling Session States" >> $logstout 2>> $logsterr
then
    MESSAGE="An error has occured adding tcp session handling rule for ipv6"
    err
fi
if ! ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT -m comment --comment "SSH Rule" >> $logstout 2>> $logsterr
then
    MESSAGE="An error has occured adding a ssh rule for ipv6"
    err
fi
if ! service ip6tables save >> $logstout 2>> $logsterr
then
    MESSAGE="An error has occured saving the ip6tables rules"
    err
fi
if ! service ip6tables restart >> $logstout 2>> $logsterr
then
    MESSAGE="An error has occured restarting ip6tables"
    err
fi
echo "ip6tables setup complete"
}

FAIL2 ()
{

#Fail2ban setup

echo "fail2ban setup begining"
if ! sed -i 's/blocktype = REJECT --reject-with icmp-port-unreachable/blocktype = DROP/g' /etc/fail2ban/action.d/iptables-common.conf
then
    MESSAGE="An error has occured modifying reject to drop for fail2ban"
    err
fi
cat > /etc/fail2ban/jail.d/jail.local <<\EOF
[sshd]
enabled = true
filter = sshd
logpath = /var/log/secure
maxretry = 3
findtime = 600
bantime = 3600
EOF
echo "fail2ban setup complete"
}

CONFIGS ()
{
    
#SSHD Configuration

echo "Begining sshd configuration"
if ! sed -i 's/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/g' /etc/ssh/sshd_config >> $logstout 2>> $logsterr
then
    MESSAGE="Error configuring sshd_config"
    err
fi
if ! sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config >> $logstout 2>> $logsterr
then
    MESSAGE="Error configuring sshd_config"
    err
fi
if ! sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config >> $logstout 2>> $logsterr
then
    MESSAGE="Error configuring sshd_config"
    err
fi
echo "sshd configuration complete"

#Limit max logins

echo "Configuring max concurrent logins"
if ! sed -i 's/4$/4\nsysadmin	hard	maxlogins	2/g' /etc/security/limits.conf >> $logstout 2>> $logsterr
then
    MESSAGE="Error setting up the max logins"
    err
fi
echo "Max concurrent logins configured"
}

CLEANUP ()
{
    
#Relabel selinux because of make installation not adding secontext

echo "Finalizing the baseline installation"
restorecon -Rv /home/sysadmin/.ssh >> $logstout 2>> $logsterr
service sshd restart >> $logstout 2>> $logsterr
echo "Temporary password is $(cat /home/sysadmin/tmppass.txt)"
rm -f /home/sysadmin/tmppass.txt >> $logstout 2>> $logsterr
echo "Finalization of baseline installation complete"
}

fPSQL ()
{
 
#INSTALL Postgresql-9.6

echo "Begining postgresql installation"
echo "Adding repositories for postgresql"
 if ! sed -i 's/releasever - Base$/releasever - Base\nexclude=postgresql\*/g' /etc/yum.repos.d/CentOS-Base.repo >> $logstout 2>> $logsterr
 then
     MESSAGE="Error removing postgres from base repo"
     err
 fi
 if ! sed -i 's/releasever - Updates$/releasever - Updates\nexclude=postgresql\*/g' /etc/yum.repos.d/CentOS-Base.repo >> $logstout 2>> $logsterr
 then
     MESSAGE="Error removing postgres from base repo"
     err
 fi
 if ! rpm -Uvh https://yum.postgresql.org/9.6/redhat/rhel-6-x86_64/pgdg-centos96-9.6-3.noarch.rpm >> $logstout 2>> $logsterr
 then
     MESSAGE="Error adding postgres 9.6 repo"
     err
 fi
 yum clean metadata >> $logstout 2>> $logsterr
 yum clean dbcache >> $logstout 2>> $logsterr
 yum makecache >> $logstout 2>> $logsterr
echo "Postgres repos succesfully added"

echo "Begining installation of postgresql"
 yum -y install postgresql96-server >> $logstout 2>> $logsterr
echo "Postgresql installation complete"
}

fMYSQL ()
{
    
#INSTALL mysql5.6

    echo "Adding msql repo"
    if ! rpm -Uvh http://dev.mysql.com/get/mysql57-community-release-el6-7.noarch.rpm >> $logstout 2>> $logsterr
    then
        MESSAGE="Error adding Mysql repo"
        err
    fi
    rm -f /etc/yum.repos.d/mysql-community* >> $logstout 2>> $logsterr
    
#Modify repo for 5.6 instead of 5.7

    cat > /etc/yum.repos.d/mysql-community.repo <<EOF
[mysql56-community]
name=MySQL 5.6 Community Server
baseurl=http://repo.mysql.com/yum/mysql-5.6-community/el/6/$(uname -m)/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-mysql
EOF
    yum clean dbcache >> $logstout 2>> $logsterr
    yum clean metadata >> $logstout 2>> $logsterr
    yum makecache >> $logstout 2>> $logsterr
    echo "mysql repo succefully added"
    
    echo "Begining installation of mysql"
    if ! yum -y install mysql-community-common mysql-community-client mysql-community-server >> $logstout 2>> $logsterr
    then
        MESSAGE="Error downloading and installing mysql"
        err
    fi
    echo "mysql installation complete"
}

fAWEB ()
{
    
#Install httpd, modssl, and openssl

    echo "Begining installation of httpd"
    yum -y install httpd >> $logstout 2>> $logsterr
    if ! rpm -q openssl >> $logstout 2>> $logsterr
    then
        yum -y install openssl.$(uname -m) >> $logstout 2>> $logsterr
    fi
    yum -y install mod_ssl >> $logstout 2>> $logsterr
    if ! rpm -q openssl mod_ssl httpd >> $logstout 2>> $logsterr
    then
        MESSAGE="An error has occured installing openssl mod_ssl or httpd"
        err
    fi
    echo "Installation of httpd complete"
}
fNWEB ()
{
    
#Install nginx and openssl

    echo "Begining installation of openssl and nginx"
    yum -y install nginx >> $logstout 2>> $logsterr
    if ! rpm -q openssl >> $logstout 2>> $logsterr
    then
        yum -y install openssl.$(uname -m) >> $logstout 2>> $logsterr
    fi
    if ! rpm -q nginx openssl >> $logstout 2>> $logsterr
    then
        MESSAGE="An error has occured installing nginx or openssl"
    fi
    echo "Installation of nginx and openssl complete"
}

fSSL ()
{
    
#Generate RSA Token with hostname name

    echo "Creating SSL certificates"
    openssl genrsa -out /etc/pki/tls/private/$(hostname).mobiwm.com.key 2048 >> $logstout 2>> $logsterr
    openssl req -new -sha256 -key /etc/pki/tls/private/$(hostname).mobiwm.com.key -out /etc/pki/tls/private/$(hostname).mobiwm.com.csr -subj "/C=US/ST=Indiana/L=Indianapolis/O='Mobi Wireless Management'/OU=Infastructure/CN=$(hostname).tld/emailAddress='domains.mobiwm.com'" >> $logstout 2>> $logsterr
    openssl req -x509 -nodes -days 365 -sha256 -key /etc/pki/tls/private/$(hostname).mobiwm.com.key -in /etc/pki/tls/private/$(hostname).mobiwm.com.csr -out /etc/pki/tls/certs/$(hostname).mobiwm.com.crt >> $logstout 2>> $logsterr
    echo "SSL certificates have been added"
}

fPSQLConf ()
{

#Postgres configurations

    echo "Begining postgres configuration"
    service postgresql-9.6 initdb >> $logstout 2>> $logsterr
    service postgresql-9.6 start >> $logstout 2>> $logsterr
    chkconfig postgresql-9.6 on >> $logstout 2>> $logsterr
    echo "postgres services started, added to startup, and db initialized"
    
#Generate two passwords for -U postgres and -U skywalker

    cat /dev/urandom|tr -dc 'a-zA-Z0-9'|fold -w 12|head -n 1 >> /root/postgressqltmp.txt
    cat /dev/urandom|tr -dc 'a-zA-Z0-9'|fold -w 12|head -n 1 >> /root/postgressqltmp2.txt

#Add password to postgres account

    echo "ALTER ROLE postgres WITH PASSWORD 'CHANGEME';" >> /tmp/postgresinit.sql
    sed -i "s/CHANGEME/$(cat /root/postgressqltmp.txt)/" /tmp/postgresinit.sql >> $logstout 2>> $logsterr

#Can also be done with createuser -EP $username

    echo "CREATE USER skywalker WITH PASSWORD 'CHANGEM32';" >> /tmp/postgresinit.sql
    sed -i "s/CHANGEM32/$(cat /root/postgressqltmp2.txt)/" /tmp/postgresinit.sql >> $logstout 2>> $logsterr

#Can also be done with createdb -O $username $databasename

    echo "CREATE DATABASE enterprise WITH OWNER = skywalker;" >> /tmp/postgresinit.sql 
    chown postgres:postgres /tmp/postgresinit.sql >> $logstout 2>> $logsterr
    chmod 700 /tmp/postgresinit.sql >> $logstout 2>> $logsterr

#Apply changes above to db

    su - postgres -c "psql -a -f /tmp/postgresinit.sql" >> $logstout 2>> $logsterr

#Comment out uncommented lines

    sed -i "s/^local/#local/g" /var/lib/pgsql/9.6/data/pg_hba.conf >> $logstout 2>> $logsterr
    sed -i "s/^host/#host/g" /var/lib/pgsql/9.6/data/pg_hba.conf >> $logstout 2>> $logsterr

#Encrypt passwords during auth from unix socket

    sed -i "0,/ *peer$/s/peer$/peer\nlocal    all    all    md5/" /var/lib/pgsql/9.6/data/pg_hba.conf >> $logstout 2>> $logsterr

#Encrypt passwords auth and only allow local connections

    sed -i "0,/32 *ident$/s/ ident/ ident\nhost    all    all    127.0.0.1\/32    md5/" /var/lib/pgsql/9.6/data/pg_hba.conf >> $logstout 2>> $logsterr
    service postgresql-9.6 restart >> $logstout 2>> $logsterr
    echo "postgres configuration complete"
}

fMYSQLConf ()
{

#   This is for the next version
#   grep 'temporary password' /var/log/mysqld.log > ~/mysqltemppass.txt
#   mysql -uroot -p$(cat ~/mysqltemppass.txt|awk '{ print $11 }')
#   Generate random password for mysql sysadmin user

    echo "Begining mysql configuration"
    service mysqld start >> $logstout 2>> $logsterr
    chkconfig mysqld on >> $logstout 2>> $logsterr
    echo "mysql service started and added to initialization"
    cat /dev/urandom|tr -dc 'a-zA-Z0-9'|fold -w 12|head -n 1 >> /root/mysqltmp.txt
    mysqladmin -u root password $(cat /root/mysqltmp.txt) >> $logstout 2>> $logsterr
    
#Delete users other than root@localhost and add a sysadmin user with password from above

    cat > /root/mysqlinit.sql << EOF
DELETE FROM mysql.user WHERE User != 'root';
DELETE FROM mysql.user WHERE Host != '127.0.0.1';
SELECT User, Host FROM mysql.user;
GRANT ALL PRIVILEGES ON *.* to 'sysadmin'@'localhost' IDENTIFIED BY 'CHANGEME' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF
    cat /dev/urandom|tr -dc 'a-zA-Z0-9'|fold -w 12|head -n 1 >> /home/sysadmin/mysqltmp.txt
    chown sysadmin:sysadmin /home/sysadmin/mysqltmp.txt >> $logstout 2>> $logsterr
    sed -i "s/CHANGEME/$(cat /home/sysadmin/mysqltmp.txt)/g" /root/mysqlinit.sql >> $logstout 2>> $logsterr
    mysql -u root -p$(cat /root/mysqltmp.txt) < /root/mysqlinit.sql

#Create deathstar database and assign RO access to picard

    cat > /root/mysqlinit2.sql << EOF
SHOW GRANTS;
CREATE DATABASE deathstar;
SHOW DATABASES;
GRANT USAGE, SELECT ON deathstar.* to 'picard'@'localhost' IDENTIFIED BY 'ncc1701';
FLUSH PRIVILEGES;
SHOW GRANTS FOR 'picard'@'localhost';
EOF
    mysql -u sysadmin -p$(cat /home/sysadmin/mysqltmp.txt) < /root/mysqlinit2.sql
    echo "ncc1701" > /root/picard
    cat > /root/mysqlinit3.sql << EOF
SHOW GRANTS;
SHOW DATABASES;
EOF
    mysql -u picard -p$(cat /root/picard) < /root/mysqlinit3.sql
    echo "mysql configuration complete"

}

fNWEBConf ()
{

#Firewall rules for http and https
    echo "Begining configuration for nginx"
    service fail2ban stop >> $logstout 2>> $logsterr
    echo "Adding http and https rules to iptables and ip6tables"
    if ! iptables -A INPUT -p tcp --dport 80 -j ACCEPT -m comment --comment "HTTP Rule" >> $logstout 2>> $logsterr
    then
        MESSAGE="An error has occured adding http rule to iptables"
        err
    fi
    if ! iptables -A INPUT -p tcp --dport 443 -j ACCEPT -m comment --comment "HTTPS Rule" >> $logstout 2>> $logsterr
    then
        MESSAGE="An error has occured adding https rule to iptables"
        err
    fi

    if ! ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT -m comment --comment "HTTP Rule" >> $logstout 2>> $logsterr
    then
        MESSAGE="An error has occured adding http rule to ip6tables"
        err
    fi
    if ! ip6tables -A INPUT -p tcp --dport 443 -j ACCEPT -m comment --comment "HTTPS Rule" >> $logstout 2>> $logsterr
    then
        MESSAGE="An error has occured adding https rule to ip6tables"
        err
    fi
    if ! service iptables save >> $logstout 2>> $logsterr
    then
        MESSAGE="An error has occured saving iptables"
        err
    fi
    if ! service ip6tables save >> $logstout 2>> $logsterr
    then
        MESSAGE="An error has occured saving ip6tables"
        err
    fi
    if ! service fail2ban start >> $logstout 2>> $logsterr
    then
        MESSAGE="An error has occured starting fail2ban"
        err
    fi
    if ! service iptables restart >> $logstout 2>> $logsterr
    then
        MESSAGE="An error has occured restarting iptables"
        err
    fi
    if ! service ip6tables restart >> $logstout 2>> $logsterr
    then
        MESSAGE="An error has occured restarting ip6tables"
        err
    fi
    echo "iptables configuration complete"
    if [ $AWEB -eq 0 ]
    then
        chkconfig nginx on >> $logstout 2>> $logsterr
        echo "nginx added to initalization"
    fi

#Variable for path to file and index for web site

    HTMLFILE="index.html"
    HTMLPATH="/usr/share/nginx/mobihtml/"
    mkdir -p $HTMLPATH
    cat > $HTMLPATH$HTMLFILE << "EOF"
<head>
Hello Mobi
</head>
EOF

#Remove old configs

mv /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.org >> $logstout 2>> $logsterr
mv /etc/nginx/conf.d/ssl.conf /etc/nginx/conf.d/ssl.org >> $logstout 2>> $logsterr
mv /etc/nginx/conf.d/virtual.conf /etc/nginx/conf.d/virtual.org >> $logstout 2>> $logsterr

#Generate new config for index above
#Enables port 80 and sends 301 to https
#loads ssl modules onto 443 and configurations for them

cat > /etc/nginx/conf.d/mobi.conf << EOF
#
# Test web site for configurations
#
server {
    listen  80;
    server_name _;
    return 301 https://$(ifconfig eth0|awk '{ print $2 }'|grep -m1 addr|sed s/^.*r://g);
    }
server {
    listen  443 ssl;
    server_name _;
    
    ssl on;
    ssl_certificate /etc/pki/tls/certs/$(hostname).mobiwm.com.crt;
    ssl_certificate_key /etc/pki/tls/private/$(hostname).mobiwm.com.key;
    
    ssl_session_timeout 5m;
    
    ssl_protocols   SSLv2 SSLv3 TLSv1;
    
    ssl_ciphers SSLv3:!RC4+RSA:+HIGH:+MEDIUM:+SSLv2:!aNULL:!MD5;
    ssl_prefer_server_ciphers   on;
    
    location / {
        root    /usr/share/nginx/mobihtml;
        index   index.html;
    }
}
EOF
    if ! nginx -t >> $logstout 2>> $logsterr
    then
        echo "Nginx has a configuration error"
        err
    fi
if [ $AWEB -eq 0 ]
then
    service nginx stop >> $logstout 2>> $logsterr
    sleep 5
    if [ -e /var/run/nginx.pid ]
    then
        rm -f /var/run/nginx.pid >> $logstout 2>> $logsterr
    fi
    service nginx start >> $logstout 2>> $logsterr
    echo "nginx service started"
fi
}

fAWEBConf ()
{
    
#Firewall rules if nginx is not also being installed

    if [ $NWEB -eq 0 ]
    then
        echo "Configuring iptables and ip6tables for http and https"
        service fail2ban stop >> $logstout 2>> $logsterr
        if ! iptables -A INPUT -p tcp --dport 80 -j ACCEPT -m comment --comment "HTTP Rule" >> $logstout 2>> $logsterr
        then
            MESSAGE="Error adding HTTP rule to iptables"
            err
        fi
        if ! iptables -A INPUT -p tcp --dport 443 -j ACCEPT -m comment --comment "HTTPS Rule" >> $logstout 2>> $logsterr
        then
            MESSAGE="Error adding HTTPS rule to iptables"
            err
        fi
        if ! ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT -m comment --comment "HTTP Rule" >> $logstout 2>> $logsterr
        then
            MESSAGE="Error adding HTTP rule to ip6tables"
            err
        fi
        if ! ip6tables -A INPUT -p tcp --dport 443 -j ACCEPT -m comment --comment "HTTPS Rule" >> $logstout 2>> $logsterr
        then
            MESSAGE="Error adding HTTPS rule to ip6tables"
            err
        fi
    if ! service iptables save >> $logstout 2>> $logsterr
    then
        MESSAGE="Error saving iptables"
        err
    fi
    if ! service ip6tables save >> $logstout 2>> $logsterr
    then
        MESSAGE="Error saving ip6tables"
        err
    fi
    if ! service fail2ban start >> $logstout 2>> $logsterr
    then
        MESSAGE="Error starting fail2ban"
        err
    fi
    if ! service iptables restart >> $logstout 2>> $logsterr
    then
        MESSAGE="Error restarting iptables"
        err
    fi
    if ! service ip6tables restart >> $logstout 2>> $logsterr
    then
        MESSAGE="Error restarting ip6tables"
        err
    fi
    fi
    if [ $NWEB -eq 0 ]
    then
        chkconfig httpd on >> $logstout 2>> $logsterr
        echo "httpd configured for initialization"
    fi
    
#Path to web site and new html file

    HTMLFILE="index.html"
    HTMLPATH="/var/www/mobihtml/"
    mkdir -p $HTMLPATH
    mkdir -p $HTMLPATH
    cat > $HTMLPATH$HTMLFILE << "EOF"
<head>
Hello Mobi
</head>
EOF

#Remove old configurations

    mv /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/ssl.org >> $logstout 2>> $logsterr
    mv /etc/httpd/conf.d/welcome.conf /etc/httpd/conf.d/welcome.org >> $logstout 2>> $logsterr

#Generate new config file for the web site
#Send 301 redirect to http for https
#Load SSL modules and bind to 443

    cat > /etc/httpd/conf.d/mobi.conf << EOF
#
# Test web site for configurations
#
#Listen 80
<VirtualHost *:80>
    DocumentRoot "/var/www/mobihtml"
    servername $(hostname)
    redirect permanent / https://$(ifconfig eth0|awk '{ print $2 }'|grep -m1 addr|sed s/^.*r://g)/
</VirtualHost>

LoadModule ssl_module modules/mod_ssl.so
Listen 443
<VirtualHost *:443>
	DocumentRoot "/var/www/mobihtml"
	SSLEngine On
	SSLCertificateFile "/etc/pki/tls/certs/$(hostname).mobiwm.com.crt"
	SSLCertificateKeyFile "/etc/pki/tls/private/$(hostname).mobiwm.com.key"
	servername $(hostname)
</VirtualHost>
EOF
if ! apachectl -t >> $logstout 2>> $logsterr
then
    echo "Apache has encountered a configuration error"
    err
fi
if [ $NWEB -eq 0 ]
then
    service httpd stop >> $logstout 2>> $logsterr
    sleep 5
    service httpd start >> $logstout 2>> $logsterr
    echo "httpd service started"
fi
}

while getopts 'banpmh?' OPT ; do
    case $OPT in
        b) BASE=1 ;;
        a) AWEB=1 ;;
        n) NWEB=1 ;;
        p) PSQL=1 ;;
        m) MYSQL=1 ;;
        h|\?|*) HELP ;;
    esac
done
if [ $BASE -eq 1 ]
then
    USR
    UPDATES
    FIREWALL
    FAIL2
    #AUTH
    CONFIGS
    CLEANUP
fi
if [ $PSQL -eq 1 ]
then
    fPSQL
    service fail2ban stop >> $logstout 2>> $logsterr
    echo "Allowing localhost on iptables and ip6tables"
    if ! iptables -A INPUT -s 127.0.0.1/32 -j ACCEPT -m comment --comment "Local Traffic" >> $logstout 2>> $logsterr
    then
        MESSAGE="An error has occured adding localhost to iptables"
      err
    fi
    if ! ip6tables -A INPUT -s ::1/128 -j ACCEPT -m comment --comment "Local Traffic" >> $logstout 2>> $logsterr
    then
        MESSAGE="An error has occured adding localhost to ip6tables"
      err
    fi
    if ! service iptables save >> $logstout 2>> $logsterr
    then
        MESSAGE="An error has occured saving iptables"
        err
    fi
    if ! service ip6tables save >> $logstout 2>> $logsterr
    then
        MESSAGE="An errro has occured saving ip6tables"
        err
    fi
    if ! service iptables restart >> $logstout 2>> $logsterr
    then
        MESSAGE="An error has occured restarting iptables"
        err
    fi
    if ! service ip6tables restart >> $logstout 2>> $logsterr
    then
        MESSAGE="An error has occured restarting ip6tables"
        err
    fi
    if ! service fail2ban start >> $logstout 2>> $logsterr
    then
        MESSAGE="An error has occured starting fail2ban"
        err
    fi
    echo "localhost has been added to iptables and ip6tables"
    fPSQLConf
fi    
if [ $MYSQL -eq 1 ]
then
    fMYSQL
    if [ $PSQL -eq 0 ]
    then
        echo "Adding localhost to iptables and ip6tables"
        service fail2ban stop >> $logstout 2>> $logsterr
        if ! iptables -A INPUT -s 127.0.0.1/32 -j ACCEPT -m comment --comment "Local Traffic" >> $logstout 2>> $logsterr
        then
            MESSAGE="An error has occured adding localhost to iptables"
            err
        fi
        if ! ip6tables -A INPUT -s ::1/128 -j ACCEPT -m comment --comment "Local Traffic" >> $logstout 2>> $logsterr
        then
            MESSAGE="An error has occured adding localhost to ip6tables"
            err
        fi
        if ! service iptables save >> $logstout 2>> $logsterr
        then
            MESSAGE="An error has occured saving iptables"
            err
        fi
        if ! service ip6tables save >> $logstout 2>> $logsterr
        then
            MESSAGE="An error has occured saving ip6tables"
            err
        fi
        if ! service iptables restart >> $logstout 2>> $logsterr
        then
            MESSAGE="An error has occured restarting iptables"
            err
        fi
        if ! service ip6tables restart >> $logstout 2>> $logsterr
        then
            MESSAGE="An error has occured restarting iptables"
            err
        fi
        if ! service fail2ban start >> $logstout 2>> $logsterr
        then
            MESSAGE="An error has occured starting fail2ban"
            err
        fi
        echo "Succesfully updated iptables and ip6tables for localhost"
    fi
    fMYSQLConf
fi
if [ $NWEB -eq 1 ]
then
    fNWEB
    fSSL
    fNWEBConf
fi
if [ $AWEB -eq 1 ]
then
    fAWEB
    if [ $NWEB -eq 0 ]
    then
        fSSL
    fi
    fAWEBConf
fi
exit 0
