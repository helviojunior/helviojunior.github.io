---
layout: post
title: Installing OpenVPN with MySQL Authentication
date: 2020-06-22 16:38:05.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
tags: 
- OpenVPN
- VPN
author: Helvio Junior (m4v3r1ck)
permalink: "/en/it/installing-openvpn-with-mysql-authentication/"
---

OpenVPN is a Linux software used for creating VPN tunnels. In this article, I will demonstrate step-by-step how to install OpenVPN with the following prerequisites:

- The updated version of the OpenVPN repository itself;
- Use of a digital certificate;
- Authentication via MySQL database;
- Python scripts for real-time data updating (connected user, disconnected user, and data traffic)

More information and documentation on OpenVPN can be obtained at this address: [https://openvpn.net/](https://openvpn.net/)

<!--more-->

## Installing Packages and Dependencies

First of all, it is necessary to install all the dependencies required for the correct functioning of the environment.

Adding OpenVPN Repository to the Environment

```shell
root@M4v3r1ck:~# echo "deb http://build.openvpn.net/debian/openvpn/stable `lsb_release --codename --short` main" > /etc/apt/sources.list.d/openvpn-aptrepo.list
root@M4v3r1ck:~# curl -s https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
```

> At the time I created this tutorial, the installation was on an Ubuntu 20.04, but the OpenVPN repository was not yet accepting its codename `focal`. Therefore, I used the Ubuntu 18.04 repository, as shown in the command line below.
{: .prompt-warning }


```shell
root@M4v3r1ck:~# echo "deb http://build.openvpn.net/debian/openvpn/stable bionic main" > /etc/apt/sources.list.d/openvpn-aptrepo.list
```

Updating the Environment

```shell
root@M4v3r1ck:~# apt-get update && apt-get -y upgrade
```

Installing Packages and Dependencies

```shell
root@M4v3r1ck:~# apt install -y openvpn easy-rsa libpam-mysql python python3 python3-pip libmariadb-dev python3-dev mariadb-client mariadb-server iptables-persistent
root@M4v3r1ck:~# pip3 install mysqlclient
```

## Configuring the Certificate Authority (CA)

OpenVPN is a TLS/SSL VPN. This means that it uses certificates to encrypt traffic between the server and clients. To issue reliable certificates, we need to set up our own simple certificate authority (CA).

Before starting the commands per se, I believe it's very important to understand what we are doing. Since the topic of certificate authority is complex, I recommend reading this article I wrote on the subject ([https://www.helviojunior.com.br/it/security/introducao-criptografia/](https://www.helviojunior.com.br/it/security/introducao-criptografia/)). To illustrate what we will be doing in terms of certificate authority (CA), observe the image below:

![Certificates](http://www.helviojunior.com.br/wp-content/uploads/2020/06/Certificados.png)
Note that in the image we illustrate four certificates:

1. **Root CA**: This is the highest authority in our structure. It's from this that all other certificates are generated, so it will be the first certificate to be created, and the most important. Therefore, when creating a password for its private keys, create a complex password and keep it safe.
2. **Server**: This will be the second certificate to be generated. It is used exclusively on the server and serves the function of allowing clients (OpenVPN) to trust your server.
3. **Client n**: The client certificates are so the server can trust and be sure that the client was authorized by you to connect to your environment. It is recommended to have one certificate for each client, but depending on the criticality of your environment, you can use a single certificate for all clients since the authentication (in our case) will be through username and password. With the use of one certificate per client, you will have in practice two factors of authentication (one being the certificate and the other the username/password).

To start, we can copy the easy-rsa template directory to our home directory with the make-cadir command:

```shell
root@M4v3r1ck:~# make-cadir ~/openvpn-ca
```

Let's go to the newly created directory to start configuring the CA:

```shell
root@M4v3r1ck:~# cd ~/openvpn-ca
```

To configure the values our CA will use, we need to edit the **vars** file within the directory. Open this file (**~/openvpn-ca/vars**) now in your text editor.

Inside, you'll find some variables that can be adjusted to determine how your certificates will be created. We only need to worry about some of them.

At the bottom of the file, locate the settings that define field standards for new certificates. It should look something like this:


```shell
...
#set_var EASYRSA_REQ_COUNTRY    "US"
#set_var EASYRSA_REQ_PROVINCE   "California"
#set_var EASYRSA_REQ_CITY       "San Francisco"
#set_var EASYRSA_REQ_ORG        "Copyleft Certificate Co"
#set_var EASYRSA_REQ_EMAIL      "me@example.net"
#set_var EASYRSA_REQ_OU         "My Organizational Unit"
...
```

Edit the values to whatever you prefer, but don't leave them blank:

```shell
...
set_var EASYRSA_REQ_COUNTRY    "BR"
set_var EASYRSA_REQ_PROVINCE   "SP"
set_var EASYRSA_REQ_CITY       "Sao Paulo"
set_var EASYRSA_REQ_ORG        "Helvio Junior"
set_var EASYRSA_REQ_EMAIL      "contato@helviojunior.com.br"
set_var EASYRSA_REQ_OU         "Helvio Junior Treinamentos"
...
```

When you're finished, save and close the file.

## Building the Root Certificate Authority (Root-CA)

Now, we can use the variables we defined and the easy-rsa utilities to build our certificate authority.

Make sure you're in your CA directory, and then create your PKI and CA structure:

```shell
root@M4v3r1ck:~# cd ~/openvpn-ca
root@M4v3r1ck:~/openvpn-ca# ./easyrsa init-pki
root@M4v3r1ck:~/openvpn-ca# ./easyrsa build-ca
```

At this point, you will be asked for a passphrase for your CA's keys, as well as the name of your CA.

```shell
Note: using Easy-RSA configuration from: ./vars

Using SSL: openssl OpenSSL 1.1.1f 31 Mar 2020

Enter New CA Key Passphrase:
Re-Enter New CA Key Passphrase:
Generating RSA private key, 2048 bit long modulus (2 primes)
......................................................+++++
..................+++++
e is 65537 (0x010001)
Can't load /root/openvpn-ca/pki/.rnd into RNG
140290726450496:error:2406F079:random number generator:RAND_load_file:Cannot open file:../crypto/rand/randfile.c:98:Filename=/root/openvpn-ca/pki/.rnd
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Common Name (eg: your user, host, or server name) [Easy-RSA CA]:Helvio Junior CA

CA creation complete and you may now import and sign cert requests.
Your new CA certificate file for publishing is at:
/root/openvpn-ca/pki/ca.crt
```

At the end of this process, we have the public certificate of our CA (Public key within an X509 certificate) in the file `~/openvpn-ca/pki/ca.crt` and its respective private key in the file `~/openvpn-ca/pki/private/ca.key`. Later, when we are creating the configuration file for our OpenVPN client, we will use the content of this X509 certificate file `~/openvpn-ca/pki/ca.crt`.

## Creating Key and Encryption Files

Next, we will generate some additional files used during the encryption process.

First, we'll generate strong Diffie-Hellman keys to use during the key exchange by typing:

```shell
root@M4v3r1ck:~/openvpn-ca# ./easyrsa gen-dh
```

Afterwards, we can generate an HMAC signature to strengthen the server's TLS integrity verification features:

```shell
root@M4v3r1ck:~/openvpn-ca# openvpn --genkey --secret ~/openvpn-ca/pki/private/ta.key
```

This process will result in the file `~/openvpn-ca/pki/private/ta.key`, which we will also use when generating the OpenVPN client configuration.

## Creating the Server Certificate

Next, we will generate our server certificate and its respective private key.

> If you choose a different name than `server` here, you will need to adjust some of the instructions below. For example, when copying the generated files to the `/etc/openvpn` directory, you will have to replace them with the correct names. You will also need to modify the `/etc/openvpn/server.conf` file later to point to the correct `.crt` and `.key` files.
{: .prompt-warning }

Start by generating the OpenVPN server certificate and key pair. We can do this by typing:

```shell
root@M4v3r1ck:~/openvpn-ca# ./easyrsa build-server-full server nopass
```

This process generated 2 files `~/openvpn-ca/pki/issued/server.crt` and `~/openvpn-ca/pki/private/server.key`.

> Note that in this command we pass the `nopass` parameter which will leave our server's private key without a password. This poses a certain security risk but is necessary because if this key had a password, you would have to enter the password on the console every server reboot or OpenVPN service restart, which could cause a service failure.
{: .prompt-warning }

## Creating the Client Certificate

Next, we will generate our client certificate and its respective private key. As previously mentioned, you have 2 models of client deployment, the first less secure where you generate only 1 certificate for all clients, and another more secure where you generate a certificate for each client. Each model has its advantages and disadvantages, some of which are listed below:

- One certificate for ALL clients:
  1. Low cost of creating new clients, as it is enough to add them in the database (since the configuration file is the same for all);
  2. If unauthorized people have access to the configuration file, they can carry out a brute force attack on the username and password in such a way that there is no way to trace which client leaked the configuration;
  3. Very much in line with the item above, if it is necessary to revoke the digital client certificate, you will have to resend the configuration to all clients;

- One certificate for EACH client:
  1. Medium cost of creating new clients, as for each new client it is necessary to generate the digital certificate, private key, and create a new configuration file with this certificate and key;
  2. Easy traceability in case of configuration leakage as the certificate is unique for each client;
  3. Easy revocation of the digital certificate, as the regeneration of the configuration is for only one client, without impacting the others.

Thus, the technical procedure for generating new clients will always be the same, just change the client name in the following commands.

```shell
root@M4v3r1ck:~/openvpn-ca# ./easyrsa build-client-full cliente1 nopass
```

This process generated 2 files `~/openvpn-ca/pki/issued/cliente1.crt` and `~/openvpn-ca/pki/private/cliente1.key`. These two files will be used later when creating the OpenVPN client configuration file.

## Configuring the OpenVPN Service

Finally, we can start configuring the OpenVPN service using the credentials and files we generated.

### Copying Files to the OpenVPN Directory

To start, we need to copy the necessary files to the configuration directory `/etc/openvpn`.

We can begin with all the files we just generated. They were placed inside the `~/openvpn-ca/pki/` directory when they were created. We need to copy the certificate and key from our CA, the certificate and key from our server, the HMAC signature, and the Diffie-Hellman file.

```shell
root@M4v3r1ck:~# cd ~/openvpn-ca/pki
root@M4v3r1ck:~/openvpn-ca/pki# cp ca.crt private/ca.key issued/server.crt private/server.key private/ta.key dh.pem /etc/openvpn
```
### OpenVPN Server Configuration

Now that our files are in place, we can create the server configuration file. Create the file `/etc/openvpn/server.conf` with the following content:

```shell
## General Settings
port 4321
proto udp
dev tun
sndbuf 0
rcvbuf 0
topology subnet
duplicate-cn
status-version 2
keepalive 10 120
persist-key
persist-tun
verb 3
comp-lzo no

## Keys
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0

## Network
server 192.168.50.0 255.255.255.0
ifconfig-pool-persist ipp_server.txt
#push "redirect-gateway def1 bypass-dhcp" # Optional to route all network traffic through VPN
#push "route 192.168.1.0 255.255.252.0" # Additional routes

## Authentication
cipher AES-128-CBC
ncp-ciphers AES-256-GCM:AES-128-GCM
auth SHA1
user nobody
group nogroup
client-to-client
username-as-common-name

## User/pass auth from mysql
plugin /usr/lib/openvpn/openvpn-auth-pam.so openvpn

## Connect-disconnect script (optional)
script-security 2
client-connect /etc/openvpn/connected.py
client-disconnect /etc/openvpn/disconnected.py

## Specific client configurations (optional)
#client-config-dir /etc/openvpn/static_clients_server

## Connected users status file (optional)
status openvpn-status.log
```

Make sure to check the location of the `openvpn-auth-pam.so` plugin to ensure that the path specified in the configuration above is correct.

```shell
root@M4v3r1ck:~# find / -name "*pam*" | grep -ioE ".*openvpn.*so"
```

In my environment, the file was located at `/usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so`. Therefore, let's create a symbolic link to the configuration location.

```shell
root@M4v3r1ck:~# mkdir /usr/lib/openvpn/
root@M4v3r1ck:~# ln -s /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /usr/lib/openvpn/openvpn-auth-pam.so
```

## Creating the Database and Configuring the PAM Connector for MySQL

To allow the PAM module to connect and authenticate users, you need to create the database where users and passwords will be stored, as well as a connector configuration file. Follow these steps to create the database:

1. Log in to MySQL as the root user:

```shell
root@M4v3r1ck:~# mysql -u root
```

2. Create the "openvpn" database and user:

```shell
CREATE DATABASE openvpn;
USE openvpn;

CREATE USER 'openvpn'@'localhost' IDENTIFIED BY 'MySuperSecurePassword';
GRANT ALL PRIVILEGES ON `openvpn`.* TO 'openvpn'@'localhost';
FLUSH PRIVILEGES;
```

3. Create the "users" and "log" tables within the "openvpn" database by running the following SQL script:

```shell
CREATE TABLE IF NOT EXISTS `users` (
    `user_id` varchar(32) COLLATE utf8_unicode_ci NOT NULL,
    `user_pass` varchar(32) COLLATE utf8_unicode_ci NOT NULL,
    `user_mail` varchar(64) COLLATE utf8_unicode_ci DEFAULT NULL,
    `user_start_date` date NOT NULL,
    `user_end_date` date NOT NULL,
    `user_online` enum('yes','no') NOT NULL DEFAULT 'no',
    `user_enable` enum('yes','no') NOT NULL DEFAULT 'yes',
PRIMARY KEY (`user_id`),
KEY `user_pass` (`user_pass`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

CREATE TABLE IF NOT EXISTS `log` (
    `log_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
    `user_id` varchar(32) COLLATE utf8_unicode_ci NOT NULL,
    `log_trusted_ip` varchar(32) COLLATE utf8_unicode_ci DEFAULT NULL,
    `log_trusted_port` varchar(16) COLLATE utf8_unicode_ci DEFAULT NULL,
    `log_remote_ip` varchar(32) COLLATE utf8_unicode_ci DEFAULT NULL,
    `log_remote_port` varchar(16) COLLATE utf8_unicode_ci DEFAULT NULL,
    `log_start_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `log_end_time` timestamp NULL,
    `log_received` float NOT NULL DEFAULT '0',
    `log_send` float NOT NULL DEFAULT '0',
PRIMARY KEY (`log_id`),
KEY `user_id` (`user_id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
```

If you wish to create a test user, execute the following commands:

```shell
root@M4v3r1ck:~# mysql -u root
mysql> use openvpn;
Database changed
mysql> INSERT INTO users (user_id, user_pass, user_start_date, user_end_date) VALUES ('helvio_junior','@Pass123', '2020-05-27', '2021-05-27');
Query OK, 1 row affected (0.00 sec)
```

4. Create the PAM configuration file `/etc/pam.d/openvpn` with the following content:

```shell
auth sufficient pam_mysql.so user=openvpn passwd=MySuperSecurePassword host=localhost db=openvpn [table=users] usercolumn=users.user_id passwdcolumn=users.user_pass [where=users.user_enable=1 AND users.user_start_date!=users.user_end_date AND TO_DAYS(now()) >= TO_DAYS(users.user_start_date) AND (TO_DAYS(now()) <= TO_DAYS(users.user_end_date))] sqllog=0 crypt=0

account required pam_mysql.so user=openvpn passwd=MySuperSecurePassword host=localhost db=openvpn [table=users] usercolumn=users.user_id passwdcolumn=users.user_pass [where=users.user_enable=1 AND users.user_start_date!=users.user_end_date AND TO_DAYS(now()) >= TO_DAYS(users.user_start_date) AND (TO_DAYS(now()) <= TO_DAYS(users.user_end_date))] sqllog=0 crypt=0
```

Make sure to replace `MySuperSecurePassword` with the actual password you set for the "openvpn" user in MySQL.

Sure, here's the translation:

## Status Scripts

We have 2 scripts responsible for updating the user's status immediately after their connection and disconnection.

Create the file `/etc/openvpn/connected.py` with the following content:

```python
#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import MySQLdb, posix, time;
import logging
import logging.handlers
import sys, datetime, os

my_logger = logging.getLogger('MyLogger')
my_logger.setLevel(logging.DEBUG)

handler = logging.handlers.SysLogHandler(address = '/dev/log')

my_logger.addHandler(handler)

now = time.time()
ts = int(now)
timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

try:
    db=MySQLdb.connect(host="localhost",
                user="openvpn",
                passwd="MySuperSecurePassword",
                db="openvpn")
    c = db.cursor()

    for i in posix.environ:
        my_logger.debug("%s => %s" % (i, posix.environ[i].decode("utf-8")))

    c.execute("UPDATE users SET user_online = 'yes' WHERE user_id = %s",(posix.environ[b'username'].decode("utf-8"),))
    c.execute("INSERT INTO log (user_id, log_trusted_ip, log_trusted_port, log_remote_ip, log_remote_port) VALUES (%s, %s, %s, %s, %s)",(posix.environ[b'username'].decode("utf-8"),posix.environ[b'trusted_ip'].decode("utf-8"),posix.environ[b'trusted_port'].decode("utf-8"),posix.environ[b'ifconfig_pool_remote_ip'].decode("utf-8"),posix.environ[b'remote_port_1'].decode("utf-8"),))

    db.commit()

except MySQLdb.Error as e:
        try:
            my_logger.critical("MySQL Error [%d]: %s" % (e.args[0], e.args[1]))
        except IndexError:
            my_logger.critical("MySQL Error: %s" % str(e))
except TypeError as e:
    my_logger.critical(e)
except ValueError as e:
        my_logger.critical(e)
except Exception as e:
        my_logger.critical(str(e))
        my_logger.critical(str(sys.exc_info()[0]))
```
{: file='/etc/openvpn/connected.py'}

Also, create the file `/etc/openvpn/disconnected.py` with the following content:

```python
#!/usr/bin/env python3

import MySQLdb, posix, time;
import logging
import logging.handlers
import sys, datetime

my_logger = logging.getLogger('MyLogger')
my_logger.setLevel(logging.DEBUG)

handler = logging.handlers.SysLogHandler(address = '/dev/log')

my_logger.addHandler(handler)

now = time.time()
time = int(now)
timestamp = datetime.datetime.fromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S')

try:
        db=MySQLdb.connect(host="localhost",
                user="openvpn",
                passwd="MySuperSecurePassword",
                db="openvpn")
        c = db.cursor()

        for i in posix.environ:
            my_logger.debug("%s => %s" % (i, posix.environ[i].decode("utf-8")))

        c.execute("UPDATE users SET user_online = 'no' WHERE user_id = %s",(posix.environ[b'username'].decode("utf-8"),))

        c.execute("UPDATE log set log_end_time = CURRENT_TIMESTAMP, log_send = %s, log_received = %s WHERE log_end_time is null and user_id = %s and log_trusted_ip = %s and log_trusted_port = %s",(posix.environ[b'bytes_sent'],posix.environ[b'bytes_received'],posix.environ[b'username'].decode("utf-8"),posix.environ[b'trusted_ip'].decode("utf-8"),posix.environ[b'trusted_port'].decode("utf-8"),))

        db.commit()

except MySQLdb.Error as e:
        try:
            my_logger.critical("MySQL Error [%d]: %s" % (e.args[0], e.args[1]))
        except IndexError:
            my_logger.critical("MySQL Error: %s" % str(e))
except TypeError as e:
        my_logger.critical(e)
except ValueError as e:
        my_logger.critical(e)
except Exception as e:
    my_logger.critical('Error: %s' % str(e))

    my_logger.critical('Full stack trace below')
    from traceback import format_exc
    err = format_exc().strip()
    err = err.replace('  File', 'File')
    err = err.replace('  Exception: ', 'Exception: ')
    my_logger.critical(err)
```
{: file='/etc/openvpn/disconnected.py'}

Finally, adjust the permissions of the 2 files:

```shell
root@M4v3r1ck:~# cd /etc/openvpn/
root@M4v3r1ck:~# chmod +x *.py
```
## Adjusting Network Configuration

Next, we need to adjust some aspects of the server's network configuration so that OpenVPN can route traffic correctly.

### Allow IP Forwarding

First, we need to allow the server to forward traffic. This is essential for the functionality we want our VPN server to provide.

We can adjust this configuration by modifying the `/etc/sysctl.conf` file. Inside it, look for the line that defines `net.ipv4.ip_forward`. Remove the `#` character at the beginning of the line to uncomment/enable this configuration, making it look like the following:

```shell
...
net.ipv4.ip_forward=1
...
```

Save and close the file when you're done.

To read the file and adjust the values for the current session, type:

```shell
root@M4v3r1ck:~# sudo sysctl -p
```

### Firewall Rules

Now we need to adjust our firewall rules to allow only the desired traffic from the tunnel.

But before opening the configuration file, we need to identify the name of our network interface. To do this, execute the following command:

```shell
root@M4v3r1ck:~# ip route | grep default
```

You will get a result similar to the one below, where in my environment, the name of my public network interface is ens33. Typically, it's the name that appears between the "dev" text and the "proto" text:

```shell
root@M4v3r1ck:~# default via 192.168.255.2 dev ens33 proto dhcp src 192.168.255.81 metric 100
```

Edit/create the Iptables configuration file `/etc/iptables/rules.v4` with the following content:

```shell
# Generated by Helvio Junior M4v3r1ck
*mangle
:PREROUTING ACCEPT [89:22829]
:INPUT ACCEPT [89:22829]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [88:24171]
:POSTROUTING ACCEPT [88:24171]
COMMIT
#
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [15:1119]
:POSTROUTING ACCEPT [15:1119]
-A POSTROUTING -o ens33 -j MASQUERADE
COMMIT
#
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p udp -m udp --sport 1024:65535 --dport 4321 -j ACCEPT
-A INPUT -p tcp -m tcp --sport 1024:65535 --dport 22 -j ACCEPT
-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -d 192.168.50.0/24 -i tun+ -j DROP
-A FORWARD -d 192.168.1.0/24 -i tun+ -j ACCEPT
-A FORWARD -i tun+ -j DROP
-A OUTPUT -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
COMMIT
```
{: file='/etc/iptables/rules.v4'}

Save the Iptables configuration file and load it into the system with the following command:

```shell
root@M4v3r1ck:~# iptables-restore < /etc/iptables/rules.v4
```

## Enabling and Starting OpenVPN

We are finally ready to start the OpenVPN service on our server. We can do this using systemd.

We need to start the OpenVPN server by specifying the name of our configuration file as an instance variable after the systemd unit file name. Our configuration file for the server is named `/etc/openvpn/server.conf`, so we will append `@server` to the end of our unit file when calling it:

```shell
root@M4v3r1ck:~# systemctl enable openvpn@server
root@M4v3r1ck:~# systemctl start openvpn@server
```

To check again if the service started successfully, type:

```shell
root@M4v3r1ck:~# systemctl status openvpn@server
```

If everything went well, your output should look something like this:

```shell
● openvpn@server.service - OpenVPN connection to server
     Loaded: loaded (/lib/systemd/system/openvpn@.service; enabled; vendor preset: enabled)
     Active: active (running) since Tue 2020-06-23 01:46:46 UTC; 2min 

14s ago
       Docs: man:openvpn(8)
             https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage
             https://community.openvpn.net/openvpn/wiki/HOWTO
   Main PID: 1395 (openvpn)
     Status: "Initialization Sequence Completed"
      Tasks: 2 (limit: 2266)
     Memory: 1.6M
     CGroup: /system.slice/system-openvpn.slice/openvpn@server.service
             ├─1395 /usr/sbin/openvpn --daemon ovpn-server --status /run/openvpn/server.status 10 --cd /etc/openvpn --script-security 2 --config /etc/openvpn/server.conf --writepid /run/openvpn/server.pid
             └─1403 /usr/sbin/openvpn --daemon ovpn-server --status /run/openvpn/server.status 10 --cd /etc/openvpn --script-security 2 --config /etc/openvpn/server.conf --writepid /run/openvpn/server.pid
```

You can also check that the OpenVPN tun0 interface is available by typing:

```shell
root@M4v3r1ck:~# ip addr show tun0
```

You should see a configured interface:

```shell
4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 100
    link/none
    inet 192.168.50.1/24 brd 192.168.50.255 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::c80f:a8ef:a4ea:f460/64 scope link stable-privacy
       valid_lft forever preferred_lft forever
```

## Creating Client Configuration Infrastructure

Next, we need to set up a system that will allow us to easily create client configuration files.

### Creating the Client Configuration Directory Structure

Create a directory structure inside your home directory to store the files:

```shell
root@M4v3r1ck:~# mkdir -p ~/client-configs/files
```

Since our client configuration files will have embedded client keys, we should lock down permissions on our inner directory:

```shell
root@M4v3r1ck:~# chmod 700 ~/client-configs/files
```

### Creating a Basic Configuration

Next, let's copy an example client configuration to our directory to use as our base configuration named `~/client-configs/base.conf` with the following content:

```shell
dev tun
persist-tun
persist-key
cipher AES-128-CBC
ncp-ciphers AES-256-GCM:AES-128-GCM
auth SHA1
tls-client
client
resolv-retry infinite
remote 10.10.10.10 4321 udp
verify-x509-name "server" name
auth-user-pass
remote-cert-tls server
comp-lzo no
key-direction 1
```
{: file='base.conf'}

> Change the IP address in the `remote` line from 10.10.10.10 to the external IP address of your server, and replace "server" in the `verify-x509-name` line with the name of your server's digital certificate if it's different.
{: .prompt-warning }

### Creating a Configuration Generation Script

Next, let's create a simple script to compile our basic configuration with the relevant certificate, key, and encryption files. It will place the generated configuration files in the `~/client-configs/files` directory.

Create and open a file named `make_config.sh` inside the `~/client-configs` directory with the following content:

```bash
#!/bin/bash
# First argument: Client identifier

KEY_DIR=~/openvpn-ca/pki
OUTPUT_DIR=~/client-configs/files
BASE_CONFIG=~/client-configs/base.conf

cat ${BASE_CONFIG} \
    <(echo -e '\n<ca>') \
    ${KEY_DIR}/ca.crt \
    <(echo -e '</ca>\n<cert>') \
    ${KEY_DIR}/issued/${1}.crt \
    <(echo -e '</cert>\n<key>') \
    ${KEY_DIR}/private/${1}.key \
    <(echo -e '</key>\n<tls-auth>') \
    ${KEY_DIR}/private/ta.key \
    <(echo -e '</tls-auth>') \
    > ${OUTPUT_DIR}/${1}.ovpn
```
{: file='make_config.sh'}

Save and close the file when you're done.

Make the file executable by typing:

```shell
root@M4v3r1ck:~# chmod 700 ~/client-configs/make_config.sh
```

## Generating the Client Configuration

Now, we can easily generate client configuration files.

If you followed the guide, you created a client certificate and key named `client1.crt` and `client1.key`, respectively, by running the `./build-key client1` command in the "Creating Client Certificate" step. We can generate a configuration for these credentials by moving them into our `~/client-configs` directory and using the script we created:

```shell
root@M4v3r1ck:~# cd ~/client-configs
root@M4v3r1ck:~# ./make_config.sh client1
```

If everything went well, we should have a `client1.ovpn` file in our `~/client-configs/files` directory:

```shell
root@M4v3r1ck:~# ls ~/client-configs/files
client1.ovpn
```

There you go! Now you just need to securely send the `client1.ovpn` file to your client.

Sources:
- [How To Set Up an OpenVPN Server on Ubuntu 16.04](https://www.digitalocean.com/community/tutorials/how-to-set-up-an-openvpn-server-on-ubuntu-16-04)
- [How to install a OpenVPN system based on user/password authentication with MySQL day control](https://sysadmin.compxtreme.ro/how-to-install-a-openvpn-system-based-on-userpassword-authentication-with-mysql-day-control-libpam-mysql/)
- [OpenVPN/easy-rsa README.quickstart.md](https://github.com/OpenVPN/easy-rsa/blob/master/README.quickstart.md)
