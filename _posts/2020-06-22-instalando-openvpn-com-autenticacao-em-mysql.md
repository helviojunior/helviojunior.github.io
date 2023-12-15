---
layout: post
title: Instalando OpenVPN com autenticação em MySQL
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
permalink: "/it/instalando-openvpn-com-autenticacao-em-mysql/"
---

OpenVPN é um software Linux utilizado para criação de túneis VPN. Neste artigo demonstrarei passo-a-passo como instalar o OpenVPN com os seguintes pré-requisitos:

- Versão atualizada do próprio repositório do OpenVPN;
- Utilização de Certificado digital;
- Autenticação via banco de dados MySQL;
- Scripts em python para atualização dos dados em tempo real (usuário conectado, usuário desconectado e dados trafegados)

Maiores informações e documentação do OpenVPN pode ser obtida neste endereço: [https://openvpn.net/](https://openvpn.net/)

<!--more-->

## Instalando pacotes e dependências

Antes de mais nada se faz necessário realizar a instalação de todas as dependências necessárias para o correto funcionamento do ambiente.

Adicionando repositório do OpenVPN no ambiente

```shell
root@M4v3r1ck:~# echo "deb http://build.openvpn.net/debian/openvpn/stable `lsb_release --codename --short` main" > /etc/apt/sources.list.d/openvpn-aptrepo.list
root@M4v3r1ck:~# curl -s https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
```

> No momento que criei este tutorial, a instalação do mesmo foi em um Ubuntu 20.04, mas o repositório do OpenVPN ainda não estava aceitando o seu codinome `focal`, sendo assim, eu utilizei o repositório do Ubuntu 18.04, ficando conforme a linha de comando abaixo.
{: .prompt-warning }


```shell
root@M4v3r1ck:~# echo "deb http://build.openvpn.net/debian/openvpn/stable bionic main" > /etc/apt/sources.list.d/openvpn-aptrepo.list
```

Atualizando o ambiente

```shell
root@M4v3r1ck:~# apt-get update && apt-get -y upgrade
```

Instalando pacotes e dependências

```shell
root@M4v3r1ck:~# apt install -y openvpn easy-rsa libpam-mysql python python3 python3-pip libmariadb-dev python3-dev mariadb-client mariadb-server iptables-persistent
root@M4v3r1ck:~# pip3 install mysqlclient
```

## Configurando a Autoridade Certificadora (CA)

O OpenVPN é uma VPN TLS/SSL. Isso significa que ele utiliza certificados para criptografar o tráfego entre o servidor e os clientes. Para emitir certificados confiáveis, precisaremos configurar nossa própria autoridade de certificação (CA) simples.

Antes de iniciar os comandos propriamente dito creio ser bem importante entendermos o que estamos fazendo, e como esse assunto de autoridade certificadora é algo complexo recomendo a leitura deste artigo que escrevi sobre o assunto ([https://www.helviojunior.com.br/it/security/introducao-criptografia/](https://www.helviojunior.com.br/it/security/introducao-criptografia/)). Para ilustrar o que iremos realizar em termos de autoridade de certificação (CA) observe a imagem abaixo:

![Certificados](http://www.helviojunior.com.br/wp-content/uploads/2020/06/Certificados.png)

Observe que na imagem ilustramos 4 certificados:

1. **Root CA**: Este é a autoridade máxima nessa nossa estrutura, é a partir dela que todos os outros certificados são gerados, sendo assim será o primeiro certificado a ser gerado, e o mais importante, portando no momento que formos criar uma senha para suas chaves provadas, crie uma senha complexa e a guarde com carinho;
2. **Servidor**: Este será o segundo certificado a ser gerado, ele é utilizado exclusivamente no servidor e tem a função de que os clientes (OpenVPN) possam confiar em seu servidor;
3. **Cliente n**: Os certificados de cliente são para que o servidor possa confiar e ter a certeza que o cliente foi autorizado por você a conectar no seu ambiente. O recomendado é que tenha um certificado para cada cliente, mas dependendo da criticidade do seu ambiente você pode utilizar um único certificado para todos os clientes uma vez que a autenticação (neste nosso caso) se dará através de usuário e senha. Com a utilização de um certificado por cliente você terá na prática dois fatores de autenticação (um deles o certificado e outro o usuário/senha);

Para começar, podemos copiar o diretório modelo easy-rsa em nosso diretório home com o comando make-cadir:

```shell
root@M4v3r1ck:~# make-cadir ~/openvpn-ca
```

Vamos para o diretório recém-criado para começar a configuração do CA:

```shell
root@M4v3r1ck:~# cd ~/openvpn-ca
```

Para configurar os valores que nossa CA irá utilizar, precisamos editar o arquivo **var** dentro do diretório. Abra esse arquivo (**~/openvpn-ca/vars**) agora em seu editor de textos.

Dentro, você encontrará algumas variáveis que podem ser ajustadas para determinar como os seus certificados serão criados. Somente precisamos nos preocupar com algumas delas.

Na parte inferior do arquivo, localize as configurações que definem padrões de campo para novos certificados. Deve ser algo como isto:

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

Edite os valores para o que você preferir, mas não os deixe em branco:

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


Quando tiver terminado, salve e feche o arquivo.

## Construindo a autoridade certificadora Raiz (Root-CA)

Agora, podemos utilizar as variáveis que definimos e os utilitários easy-rsa para construir nossa autoridade de certificação.

Assegure-se de estar em seu diretório CA, e então crie sua estrutura de PKI e CA:

```shell
root@M4v3r1ck:~# cd ~/openvpn-ca
root@M4v3r1ck:~/openvpn-ca# ./easyrsa init-pki
root@M4v3r1ck:~/openvpn-ca# ./easyrsa build-ca
```

Neste ponto é solicitado uma senha para as chaves da sua CA, bem como o nome da sua CA.

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

Ao final deste processo temos o certificado público da nossa CA (Chave pública dentro de um certificado X509) dentro do arquivo `~/openvpn-ca/pki/ca.crt` e a sua respectiva chave privada no arquivo `~/openvpn-ca/pki/private/ca.key`. Futuramente, no momento em que formos criar o arquivo de configuração do nosso cliente OpenVPN iremos utilizar o conteúdo deste arquivo do certificado X509 `~/openvpn-ca/pki/ca.crt`.

## Criando chave e arquivos de criptografia

A seguir, vamos gerar alguns arquivos adicionais utilizados durante o processo de criptografia.

Primeiro vamos gerar chaves fortes Diffie-Hellman para usar durante a troca de chaves digitando:

```shell
root@M4v3r1ck:~/openvpn-ca# ./easyrsa gen-dh
```


Posteriormente, podemos gerar uma assinatura HMAC para fortalecer os recursos de verificação de integridade TLS do servidor:

```shell
root@M4v3r1ck:~/openvpn-ca# openvpn --genkey --secret ~/openvpn-ca/pki/private/ta.key
```

Este processo irá gerar como resultado o arquivo `~/openvpn-ca/pki/private/ta.key` no qual também o utilizaremos no momento que formos gerar a configuração do cliente OpenVPN.

## Criando o certificado do servidor

A seguir, vamos gerar nosso certificado de servidor e sua respectiva chave privada.

> Se você escolher um nome diferente de server aqui, você terá que ajustar algumas das instruções abaixo. Por exemplo, quando copiar os arquivos gerados para o diretório /etc/openvpn, você terá que substituir os nomes corretos. Você também terá que modificar o arquivo `/etc/openvpn/server.conf` depois para apontar para os arquivos `.crt` e `.key` corretos.
{: .prompt-warning }

Comece gerando o certificado do servidor OpenVPN e o par de chaves. Podemos fazer isso digitando:

```shell
root@M4v3r1ck:~/openvpn-ca# ./easyrsa build-server-full server nopass
```

Este processo gerou 2 arquivos `~/openvpn-ca/pki/issued/server.crt` e `~/openvpn-ca/pki/private/server.key`.

> Observer que neste comando passamos o parâmetro `nopass` que irá deixar a chave privada do nosso servidor sem senha, isso tem um certo risco de segurança mas se faz necessário pois caso essa chave tenha senha a cada reboot do servidor ou restart do ser serviço OpenVPN você teria que digitar a senha na console o que poderia ocasionar um falha no serviço.
{: .prompt-warning }

## Criando o certificado do cliente

A seguir, vamos gerar nosso certificado de cliente e sua respectiva chave privada. Conforme comentado anteriormente você tem 2 modelos de *deploy* de clientes, o primeiro deles menos seguro onde você gera somente 1 certificado para todos os clientes, e outro mais seguro onde você gera um certificado para cada cliente, cada modelo tem suas vantagens e desvantagens, segue algumas abaixo:

- Um certificado para TODOS os clientes:
  1. Baixo custo de criação de novos clientes, pois basta adicionar no banco de dados (pois o arquivo de configuração é o mesmo para todos);
  2. Caso outras pessoas não autorizadas tenham acesso ao arquivo de configuração, poderão realizar um ataque de força bruta no usuário e senha de forma que não há como ter rastreabilidade qual cliente que vazou a configuração;
  3. Muito em alinhamento que o item acima, caso necessite revogar o certificado digital de cliente, terá que reenviar a configuração para todos os clientes;

- Um certificado para CADA cliente:
  1. Custo médio de criação de novos clientes, pois para cada cliente novo se faz necessário gerar o certificado digital, chave privada e gerar um novo arquivo de configuração com esse certificado e chave;
  2. Fácil rastreabilidade em caso de vazamento de configuração pois o certificado é único para cada cliente;
  3. Fácil revogação do certificado digital, pois a regeração da configuração é para somente um cliente, sem impactar nos demais.


Desta forma o procedimento técnico para geração de novos clientes sempre será o mesmo, bastando alterar o nome cliente nos comandos a seguir.

```shell
root@M4v3r1ck:~/openvpn-ca# ./easyrsa build-client-full cliente1 nopass
```

Este processo gerou 2 arquivos `~/openvpn-ca/pki/issued/cliente1.crt** e **~/openvpn-ca/pki/private/cliente1.key`. Estes dois arquivos serão utilizados futuramente no momento da criação do arquivo de configuração do cliente OpenVPN.

## Configurando o serviço do OpenVPN

Enfim, podemos começar a configuração do serviço OpenVPN utilizando as credenciais e arquivos que geramos.

### Copiar os Arquivos para o Diretório OpenVPN

Para começar, precisamos copiar os arquivos que necessitamos para o diretório de configuração /etc/openvpn.

Podemos começar com todos os arquivos que acabamos de gerar. Eles foram colocados dentro do diretório `~/openvpn-ca/pki/` quando foram criados. Precisamos copiar o certificado e chave de nossa CA, o certificado e chave de nosso servidor, a assinatura HMAC, e o arquivo Diffie-Hellman.

```shell
root@M4v3r1ck:~# cd ~/openvpn-ca/pki
root@M4v3r1ck:~/openvpn-ca/pki# cp ca.crt private/ca.key issued/server.crt private/server.key private/ta.key dh.pem /etc/openvpn
```

### Configuração OpenVPN Server

Agora que nossos arquivos estão no lugar, podemos criar o arquivo de configuração do servidor. Crie o arquivo `/etc/openvpn/server.conf` com o conteúdo abaixo:

```shell
##Configurações gerais
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

##Chaves
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0

##Rede
server 192.168.50.0 255.255.255.0
ifconfig-pool-persist ipp_server.txt
#push "redirect-gateway def1 bypass-dhcp" # Opcional para redirecionar todo tráfego de rede pela VPN
#push "route 192.168.1.0 255.255.252.0" # rotas adicionais

##Autenticação
cipher AES-128-CBC
ncp-ciphers AES-256-GCM:AES-128-GCM
auth SHA1
user nobody
group nogroup
client-to-client
username-as-common-name

##user/pass auth from mysql
plugin /usr/lib/openvpn/openvpn-auth-pam.so openvpn

##script connect-disconnect (opcional)
script-security 2
client-connect /etc/openvpn/connected.py
client-disconnect /etc/openvpn/disconnected.py

##Configurações específicas para cada cliente (opcional)
#client-config-dir /etc/openvpn/static_clients_server

##Arquivo de status de usuários conectados (opcional)
status openvpn-status.log
```
{: file='/etc/openvpn/server.conf'}

Verifique o local do plugin openvpn-auth-pam.so para ter certeza que o caminho apontado na configuração acima está correto.

```shell
root@M4v3r1ck:~# find / -name "*pam*" | grep -ioE ".*openvpn.*so"
```

Em meu ambiente o arquivo foi localizado em `/usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so` sendo assim vamos criar um link simbólico para o local da configuração

```shell
root@M4v3r1ck:~# mkdir /usr/lib/openvpn/
root@M4v3r1ck:~# ln -s /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /usr/lib/openvpn/openvpn-auth-pam.so
```

## Criando a base de dados e configurando o conector do PAM para o MySQL

Para que o módulo do PAM possa se conectar e autenticar os usuários é necessária a criação da base de dados onde os usuários e senhas serão salvos bem como um arquivo de configuração do conector. Desta forma crie a base de dados conforme o script abaixo:

```shell
root@M4v3r1ck:~# mysql -u root

CREATE DATABASE openvpn;
USE openvpn;

CREATE USER 'openvpn'@'localhost' IDENTIFIED BY 'MinhaS3nhASuperSegura';
GRANT ALL PRIVILEGES ON `openvpn`.* TO 'openvpn'@'localhost';
FLUSH PRIVILEGES;

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

Caso deseje criar um usuário de teste execute os comandos abaixo:

```shell
root@M4v3r1ck:~# mysql -u root
mysql> use openvpn;
Database changed
mysql> INSERT INTO users (user_id, user_pass, user_start_date, user_end_date) VALUES ('helvio_junior','@Pass123', '2020-05-27', '2021-05-27');
Query OK, 1 row affected (0.00 sec)
```

Crie o arquivo de configuração do PAM `/etc/pam.d/openvpn` com o seguinte conteúdo:

```shell
auth sufficient pam_mysql.so user=openvpn passwd=MinhaS3nhASuperSegura host=localhost db=openvpn [table=users] usercolumn=users.user_id passwdcolumn=users.user_pass [where=users.user_enable=1 AND users.user_start_date!=users.user_end_date AND TO_DAYS(now()) >= TO_DAYS(users.user_start_date) AND (TO_DAYS(now()) <= TO_DAYS(users.user_end_date))] sqllog=0 crypt=0

account required pam_mysql.so user=openvpn passwd=MinhaS3nhASuperSegura host=localhost db=openvpn [table=users] usercolumn=users.user_id passwdcolumn=users.user_pass [where=users.user_enable=1 AND users.user_start_date!=users.user_end_date AND TO_DAYS(now()) >= TO_DAYS(users.user_start_date) AND (TO_DAYS(now()) <= TO_DAYS(users.user_end_date))] sqllog=0 crypt=0
```
{: file='/etc/pam.d/openvpn'}

## Scripts de status

Temos 2 scripts que têm por responsabilidade atualizar os status do usuário logo após a sua conexão e desconexão.

Crie o arquivo `/etc/openvpn/connected.py` com o conteúdo abaixo:


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
                passwd="MinhaS3nhASuperSegura",
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


Crie também o arquivo `/etc/openvpn/disconnected.py` com o conteúdo abaixo:

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
                passwd="MinhaS3nhASuperSegura",
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


Ajuste a permissão dos 2 arquivos:

```shell
root@M4v3r1ck:~# cd /etc/openvpn/
root@M4v3r1ck:~# chmod +x *.py
```

## Ajustando a configuração de rede

A seguir, precisamos ajustar

 alguns aspectos da rede do servidor para que o OpenVPN possa rotear o tráfego corretamente.

### Permitir o Encaminhamento IP

Primeiro, precisamos permitir ao servidor encaminhar o tráfego. Isso é essencial para a funcionalidade que queremos que nosso servidor de VPN forneça.

Podemos ajustar essa configuração modificando o arquivo `/etc/sysctl.conf`. Dentro dele, procure a linha que define net.ipv4.ip_forward. Remova o caractere `#` do início da linha para descomentar/habilitar essa configuração, ficando conforme abaixo:

```shell
...
net.ipv4.ip_forward=1
...
```

Salve e feche o arquivo quando tiver terminado.

Para ler o arquivo e ajustar os valores para a sessão atual, digite:

```shell
root@M4v3r1ck:~# sudo sysctl -p
```

### Regras de firewall

Agora precisaremos ajustar as nossas regras de firewall para permitir somente o tráfego desejado do túnel.

Mas antes de abrir o arquivo de configuração temos de identificar qual é o nome da nossa interface de rede. Para isso, execute o comando abaixo:

```shell
root@M4v3r1ck:~# ip route | grep default
```

Você terá um resultado parecido com o abaixo, onde no meu ambiente o nome da minha interface de rede pública é ens33. Geralmente é o nome que está entre o texto "dev" e o texto "proto":

```shell
root@M4v3r1ck:~# default via 192.168.255.2 dev ens33 proto dhcp src 192.168.255.81 metric 100
```

Edite/crie o arquivo de configuração do Iptables `/etc/iptables/rules.v4` com o seguinte conteúdo:

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

Salve o arquivo de configuração do Iptables e o carregue no sistema com o comando abaixo:

```shell
root@M4v3r1ck:~# iptables-restore < /etc/iptables/rules.v4
```

## Habilitando e iniciando o OpenVPN

Estamos finalmente prontos para iniciar o serviço OpenVPN em nosso servidor. Podemos fazer isso usando o systemd.

Precisamos iniciar o servidor OpenVPN especificando o nome do nosso arquivo de configuração como uma variável de instância após o nome do arquivo de unidade systemd. Nosso arquivo de configuração para nosso servidor é chamado /etc/openvpn/server.conf, assim vamos adicionar @server ao final de nosso arquivo de unidade ao chamá-lo:

```shell
root@M4v3r1ck:~# systemctl enable openvpn@server
root@M4v3r1ck:~# systemctl start openvpn@server
```

Verifique novamente se o serviço foi iniciado com êxito, digitando:

```shell
root@M4v3r1ck:~# systemctl status openvpn@server
```

Se tudo correu bem, sua saída deve ser algo parecido com isso:

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

Você também pode verificar que a interface OpenVPN tun0 está disponível digitando:

```shell
root@M4v3r1ck:~# ip addr show tun0
```

Você deve ver uma interface configurada:

```shell
4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 100
    link/none
    inet 192.168.50.1/24 brd 192.168.50.255 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::c80f:a8ef:a4ea:f460/64 scope link stable-privacy
       valid_lft forever preferred_lft forever
```

## Criar Infraestrutura de Configuração de Cliente

A seguir, precisamos configurar um sistema que nos permitirá criar arquivos de configuração de cliente facilmente.

### Criando a Estrutura de Diretório de Configuração do Cliente

Crie uma estrutura de diretório dentro do seu diretório home para armazenar os arquivos:

```shell
root@M4v3r1ck:~# mkdir -p ~/client-configs/files
```

Como nossos arquivos de configuração de cliente terão as chaves de cliente embutidas, devemos bloquear as permissões em nosso diretório interno:

```shell
root@M4v3r1ck:~# chmod 700 ~/client-configs/files
```

### Criando uma Configuração Básica

Em seguida, vamos copiar um exemplo de configuração de cliente em nosso diretório para usar como nossa configuração base com nome `~/client-configs/base.conf` com o seguinte conteúdo:

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

> Altere na linha remote o IP 10.10.10.10 para o endereço IP externo do seu servidor e altere na linha verify-x509-name onde está server para o nome do certificado digital do seu servidor, caso tenha colocado diferente.
{: .prompt-warning }


### Criando um Script de Geração de Configuração

A seguir, vamos criar um script simples para compilar nossa configuração básica com o certificado relevante, chave e arquivos de criptografia. Ele irá colocar os arquivos de configuração gerados no diretório `~/client-configs/files`.

Crie e abra um arquivo chamado `make_config.sh` dentro do diretório `~/client-configs` com o seguinte conteúdo:

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

Salve e feche o arquivo quando tiver terminado.

Marque o arquivo como executável digitando:

```shell
root@M4v3r1ck:~# chmod 700 ~/client-configs/make_config.sh
```

## Gerando a configuração do cliente

Agora, podemos gerar facilmente arquivos de configuração de cliente.

Se você acompanhou o guia, você criou um certificado de cliente e uma chave chamados client1.crt e client1.key respectivamente executando o comando `./build-key client1` no passo `Criando certificado do cliente`. Podemos gerar uma configuração para essas credenciais movendo-as para dentro de nosso diretório `~/client-configs` e utilizando o script que fizemos:

```shell
root@M4v3r1ck:~# cd ~/client-configs
root@M4v3r1ck:~# ./make_config.sh cliente1
```

Se tudo correu bem, devemos ter um arquivo client1.ovpn em nosso diretório `~/client-configs/files`:

```shell
root@M4v3r1ck:~# ls ~/client-configs/files
cliente1.ovpn
```

Pronto! Agora basta enviar o arquivo cliente1.ovpn de forma segura ao seu cliente.

Fontes:
- [Como Configurar um Servidor OpenVPN no Ubuntu 16.04](https://www.digitalocean.com/community/tutorials/como-configurar-um-servidor-openvpn-no-ubuntu-16-04-pt)
- [How to install a OpenVPN system based on user/password authentication with MySQL day control](https://sysadmin.compxtreme.ro/how-to-install-a-openvpn-system-based-on-userpassword-authentication-with-mysql-day-control-libpam-mysql/)
- [OpenVPN/easy-rsa README.quickstart.md](https://github.com/OpenVPN/easy-rsa/blob/master/README.quickstart.md)
