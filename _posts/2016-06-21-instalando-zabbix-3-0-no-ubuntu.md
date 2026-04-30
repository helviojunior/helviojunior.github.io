---
layout: post
title: Instalando Zabbix 3.4 no Ubuntu
date: 2016-06-21 14:51:50.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
- Monitoramento
- Zabbix
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/instalando-zabbix-3-0-no-ubuntu/"
---

Aprenda neste post passo-a-passo como instalar o Zabbix 3.x no ubuntu ou debian.

<!--more-->

O primeiro passo, em qualquer instalação de servidor ao meu ver, é garantir que todos os pacotes básicos estejam devidamente atualizados.

```bash
apt-get update;
apt-get upgrade;
```

Na sequência vamos instalar os pacotes básicos para possibilitar a compilação e a gerência do dispositivo. Enquanto o comando abaixo estiver sendo executado aproveite para buscar um café ou ler outros artigos aqui do blog pois devido às características do hardware o comando abaixo irá gastar facilmente uns 10 minutos.

```bash
apt-get -y install gcc g++ build-essential snmp libiksemel-dev libcurl4-gnutls-dev vim libssh2-1-dev libssh2-1 libopenipmi-dev libsnmp-dev wget curl fping snmp-mibs-downloader libldap2-dev libldap2-dev iotop ntp fping mysql-common libmysqlclient18 libmysqlclient-dev libxml2-dev mysql-client apache2 php5 php5-mysql php5-gd libevent-dev libpcre3 libpcre3-dev
```

Crie o usuário do Zabbix.

```bash
groupadd zabbix
useradd -g zabbix zabbix -s /bin/false
```

Agora vamos efetuar o download do source do Zabbix (sim… sempre gosto de instalar a partir dos sources, existem repositórios mas prefiro os sources… velha guarda… ) e descompactar os arquivos.

```bash
wget http://repo.zabbix.com/zabbix/3.4/ubuntu/pool/main/z/zabbix/zabbix_3.4.15.orig.tar.gz
tar -xzvf zabbix_3.4.15.orig.tar.gz -C /usr/src
cd /usr/src/zabbix_3.4.15/
```

Compile e instale o Zabbix.

```bash
./configure --enable-server --enable-agent --with-mysql --with-net-snmp --with-libcurl --with-libxml2
make install
```

O Zabbix-Server irá rodar com MySQL, sendo assim é necessário a criação da estrutura do banco de dados. Crie agora o banco de dados:

```bash
mysql -h 127.0.0.1 -u zabbix -p zabbix < database/mysql/schema.sql
mysql -h 127.0.0.1 -u zabbix -p zabbix < database/mysql/images.sql
mysql -h 127.0.0.1 -u zabbix -p zabbix < database/mysql/data.sql
```

Neste momento temos os binários do Zabbix e a base de dados criados. Vamos configurar o server.

Crie os diretórios para log e execução do zabbix

```bash
mkdir /var/log/zabbix
chown -R zabbix:zabbix /var/log/zabbix
```

Altere as configurações do proxy no arquivo **/usr/local/etc/zabbix_server.conf** conforme exemplo abaixo.

```bash
LogFile=/var/log/zabbix/zabbix_server.log
DBHost=127.0.0.1
DBName=zabbix
DBPassword=zabbix
DBPort=3306
DBUser=zabbix
FpingLocation=/usr/bin/fping
LogFile=/var/log/zabbix_server.log
LogSlowQueries=3000
StartHTTPPollers=150
StartPingers=50
StartPollers=256
StartTimers=30
Timeout=4
```

Verifique o local de instalação do fping, este local de instalação deverá ser colocado no arquivo de configuração, no meu ambiente o local é **/usr/bin/fping**

```bash
whereis fping
```

Altere o arquivo  **/usr/local/etc/zabbix_server.conf** com este caminho conforme exemplo abaixo

```bash
FpingLocation=/usr/sbin/fping
```

Altere as configurações do agente no arquivo **/usr/local/etc/zabbix_agentd.conf** conforme exemplo abaixo.

```bash
LogFile=/var/log/zabbix/zabbix_agentd.log
LogFileSize=10
Server=127.0.0.1
DebugLevel=3
StartAgents=4
Hostname=nomedamaquina
```

Agora precisamos copiar e configurar os arquivos de inicialização do Zabbix.

```bash
cp -v misc/init.d/debian/zabbix-* /etc/init.d/
```

Configure o sistema operacional para possibilitar a carga automática do Proxy e do agente.

```bash
update-rc.d -f zabbix-server defaults
update-rc.d -f zabbix-agent defaults
```

Inicie os serviços do Zabbix

```bash
service zabbix-server start
service zabbix-agent start
```

Edite o arquivo **/etc/php5/apache2/php.ini** conforme abaixo:

```bash
post_max_size=16M
max_execution_time=300
max_input_time=300
date.timezone = 'America/Sao_Paulo'
```

Copie o conte[udo do frontend para o diret[orio do apache

```bash
rsync -av frontends/php/* /var/www/html/
```

Reinicie o Apache e acesse o Zabbix com a URL http://IP_DO_SERVIDOR/
