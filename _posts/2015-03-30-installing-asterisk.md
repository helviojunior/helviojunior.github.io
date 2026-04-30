---
layout: post
title: Instalando o Asterisk 1.8
date: 2015-03-30 20:47:13.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Asterisk
- VoIP
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/voip/installing-asterisk/"
---

O Asterisk é um poderoso software de PBX (central telefônica), free, que possibilita realizar interconexões entre o mundo analógico, digital e possibilita aplicações e recursos que quando vistos em outras centrais telefônicas, são de grande porte.

<!--more-->

## Instalação de dependências

O primeiro passo, em qualquer instalação de servidor ao meu ver, é garantir que todos os pacotes básicos estejam devidamente atualizados.

```bash
apt-get update;
apt-get upgrade;
```

Na sequência vamos instalar os pacotes básicos para possibilitar a compilação e a gerência do dispositivo. Enquanto o comando abaixo estiver sendo executado aproveite para buscar um café ou ler outros artigos aqui do blog pois o comando abaixo irá gastar alguns minutos.

```bash
apt-get install vim openssh-server openssh-client linux-headers-`uname -r` gcc g++ libgtk2.0-dev libnewt-dev libxml2-dev libncurses5-dev subversion bison libssl-dev openssl libusb-dev libc6-dev zlib-bin zlib1g-dev snmp libsnmp-dev snmpd build-essential mysql-common libmysqlclient18 libmysqlclient-dev libcurl4-openssl-dev uuid-dev libjansson-dev sqlite3 libsqlite3-dev
```

Na sequencia vamos instalar o MySQL, que será utilizado para o armazenamento do log de gravações telefônicas (CDR -Call Detail Records). Neste passo será solicitada a senha de root do MySQL, escolha sua senha e anote para utilizações futuras.

```bash
apt-get -y install mysql-server mysql-client
```

## Download e instalação dos pacotes utilizados no Asterisk

```bash
wget http://downloads.asterisk.org/pub/telephony/dahdi-linux/releases/dahdi-linux-2.9.2.tar.gz
wget http://downloads.asterisk.org/pub/telephony/libpri/releases/libpri-1.4.15.tar.gz
wget http://downloads.asterisk.org/pub/telephony/dahdi-tools/releases/dahdi-tools-2.9.2.tar.gz
wget http://downloads.asterisk.org/pub/telephony/asterisk/releases/asterisk-1.8.26.1.tar.gz
tar -xzvf dahdi-linux-2.9.2.tar.gz -C /usr/src/
tar -xzvf libpri-1.4.15.tar.gz -C /usr/src/
tar -xzvf dahdi-tools-2.9.2.tar.gz -C /usr/src/
tar -xzvf asterisk-1.8.26.1.tar.gz -C /usr/src/
```

A compilação do Asterisk deve ser feita em uma ordem específica, pois os módulos são interdependentes, ou seja, a compilação de um módulo interfere diretamente na compilação do outro. Por exemplo, caso seja compilado o módulo Asterisk antes do Libpri, a compilação do asterisk não reconhecerá as funções habilitadas pelo pacote libpri.

Desta forma para a correta compilação dos módulos do Asterisk, siga os passos abaixo:

### DAHDI

```bash
cd /usr/src/dahdi-linux-2.9.2
make clean
make
make install

cd /usr/src/dahdi-tools-2.9.2
make clean
./configure
make
make install
#Não executar o make config
#Caso execute o make config, remova com os comandos update-rc.d -f dahdi remove e rm -rf /etc/init.d/dahdi
```

### LibPRI

```bash
cd /usr/src/libpri-1.4.15
make clean
make
make install
```

### Asterisk

```bash
cd /usr/src/asterisk-1.8.26.1
make clean
./configure
make menuselect
# Verifique se os módulos cdr_mysql e app_mysql estão selecionado em Add-Ons
# Verifique se o módulo res_config_mysql estão selecionado em Add-Ons
# Verifique se o módulo res_snmp esta selecionado em Resource Modules
# Verifique se o módulo func_curl esta selecionado em Dialplan Functions
make
make install
make config
```

Caso essa seja a primeira instalação neste servidor pode ser executado o comando abaixo para gerar os arquivos exemplos de configuração. Caso ja tenha os arquivos neste servidor ou em um backup, não é recomendado realizar este passo, pois ao executa-lo todos os arquivos de configuração serão substituídos pelo padrão do sistema.

```bash
make samples
```

## Configurando CDR no MySQL

Crie um arquivo **/tmp/cdr.sql** com o seguinte conteúdo

```bash
create database asteriskcdrdb;

/* Define a senha do usuário como 123456 */
CREATE USER 'asteriskcdr'@'localhost' IDENTIFIED BY '123456';
GRANT ALL PRIVILEGES ON asteriskcdrdb.* TO 'asteriskcdr'@'%';

use asteriskcdrdb;
/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--

-- Table structure for table `cdr`

--

DROP TABLE IF EXISTS `cdr`;
CREATE TABLE `cdr` (
`calldatestart` datetime NOT NULL default '0000-00-00 00:00:00',
`calldateend` datetime NOT NULL default '0000-00-00 00:00:00',
`calldateanswer` datetime NOT NULL default '0000-00-00 00:00:00',
`clid` varchar(80) NOT NULL default '',
`src` varchar(80) NOT NULL default '',
`dst` varchar(80) NOT NULL default '',
`dcontext` varchar(80) NOT NULL default '',
`channel` varchar(80) NOT NULL default '',
`dstchannel` varchar(80) NOT NULL default '',
`lastapp` varchar(80) NOT NULL default '',
`lastdata` varchar(80) NOT NULL default '',
`duration` int(11) NOT NULL default '0',
`billsec` int(11) NOT NULL default '0',
`disposition` varchar(45) NOT NULL default '',
`amaflags` int(11) NOT NULL default '0',
`accountcode` varchar(20) NOT NULL default '',
`uniqueid` varchar(32) NOT NULL default '',
`userfield` varchar(255) NOT NULL default '',
KEY `calldate` (`calldatestart`),
KEY `dst` (`dst`),
KEY `accountcode` (`accountcode`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
```

Execute este script no MySQL para criar a base, usuário e tabela necessária com o comando abaixo. Este comando solicitará a senha de root do MySQL, a mesma criada no momento da instalação.

```bash
mysql -u root -p < /tmp/cdr.sql
```

Edite o arquivo **/etc/asterisk/cdr.conf** e o mantenha com o seguinte conteúdo

```bash
[general]
enable=yes
unanswered=no
usegmtime=yes
loguniqueid=yes
loguserfield=yes
```

Edite o arquivo **/etc/asterisk/cdr_mysql.conf** e o mantenha com o seguinte conteúdo

```bash
[global]
hostname = localhost
dbname = asteriskcdrdb
table=cdr
user = asteriskcdr
password = 123456
port = 3306

[columns]
alias start => calldatestart
alias end => calldateend
alias answer => calldateanswer
alias callerid => clid
alias src => src
alias dst => dst
alias dcontext => dcontext
alias channel => channel
alias dstchannel => dstchannel
alias lastapp => lastapp
alias lastdata => lastdata
alias duration => duration
alias billsec => billsec
alias disposition => disposition
alias amaflags => amaflags
alias accountcode => accountcode
alias userfield => userfield
alias uniqueid => uniqueid
```

Edite o arquivo **/etc/asterisk/modules.conf** e adicione a seguinte linha

```bash
load => cdr_mysql.so
```

Reinicie o asterisk

Para verificar o status da gravação do CDR utilize os comando **cdr mysql status**

## Alterando a linguagem do Asterisk para pt_BR

Realize o download dos prompts de audio e descompacte em /var/lib/asterisk/sounds/

```bash
wget {{ site.baseurl }}/assets/2015/03/sounds-pt_BR.tgz
tar -xzvf sounds-pt_BR.tgz -C /var/lib/asterisk/sounds/
```

Altere o seu arquivo sip.conf, iax.conf entre outros alterando a language para pt_BR conforme demonstrado abaixo

```bash
language=pt_BR
```
