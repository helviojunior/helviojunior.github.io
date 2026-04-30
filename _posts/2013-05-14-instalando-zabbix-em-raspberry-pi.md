---
layout: post
title: Instalando Zabbix em Raspberry Pi
date: 2013-05-14 17:49:27.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Zabbix
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/monitoramento/zabbix/instalando-zabbix-em-raspberry-pi/"
---

**O que é o Raspberry Pi?**

O Raspberry Pi é um computador do tamanho de um cartão de crédito que se conecta à sua TV e um teclado. É um PC que pode ser usado para muitas das coisas que o seu PC faz, como planilhas cálculo, processamento de texto, jogos e servidores diversos. Ele também reproduz vídeo de alta definição.

Com essa diversidade de opções, uma está sendo útil para mim. Atuando como Proxy do Zabbix server (maiores informações do que é o Zabbix proxy [aqui](http://www.zabbix.com)), quando fui realizar a instalação achei um artigo bem interessante do Adail Spinola com um passo a passo da instalação do Zabbix em um dispositivo Raspberry Pi e resolvi replica-lo aqui.

<!--more-->

Link para o artigo original: [http://spinola.net.br/blog/?p=405](http://spinola.net.br/blog/?p=405)

O Raspberry suporta por padrão algumas distribuições linux como Debian, Arch Linus e Risc OS. Para este post a distribuição de linux escolhida foi o Debian disponível na página oficial do fornecedor do hardware ([clique aqui](http://www.raspberrypi.org/)).

Este tutorial começa após a instalação normal dele, então se precisas de informações sobre como instalar o sistema operacional do raspberry consulte a na página de download existem informações a respeito de como criar a imagem, pois não iremos repetir tais informações para não fugir ao tema.

O primeiro passo, no raspberry ou em qualquer instalação de servidor ao meu ver, é garantir que todos os pacotes básicos estejam devidamente atualizados.

```bash
apt-get update;
apt-get upgrade;
```

Na sequência vamos instalar os pacotes básicos para possibilitar a compilação e a gerência do dispositivo. Enquanto o comando abaixo estiver sendo executado aproveite para buscar um café ou ler outros artigos aqui do blog pois devido às características do hardware o comando abaixo irá gastar facilmente uns 10 minutos.

```bash
apt-get -y install build-essential snmp libiksemel-dev libcurl4-gnutls-dev vim libssh2-1-dev libssh2-1 libopenipmi-dev libsnmp-dev wget curl fping snmp-mibs-downloader libldap2-dev libldap2-dev iotop ntp libsqlite3-dev sqlite3 fping
```

Crie o usuário do Zabbix.

```bash
useradd zabbix -s /bin/false
```

Agora vamos efetuar o download do source do Zabbix (sim… sempre gosto de instalar a partir dos sources, existem repositórios mas prefiro os sources… velha guarda… ) e descompactar os arquivos.

```bash
mkdir /install
cd /install
VERSAO="2.0.6"
rm *.tgz
wget http://downloads.sourceforge.net/project/zabbix/ZABBIX%20Latest%20Stable/$VERSAO/zabbix-$VERSAO.tar.gz?r=http%3A%2F%2Fwww.zabbix.com%2Fdownload.php&ts=1346344892&use_mirror=ufpr -O zabbix.tgz;
mv *.php zabbix.tgz
tar -xzvf zabbix.tgz
cd zabbix-$VERSAO
```

Dependendo de quando você estiver vendo este artigo poderá já existir nova versão do Zabbix disponível então altere o conteúdo da variável VERSAO para refletir a versão que você desejar.

Compile e instale o Zabbix.

```bash
./configure --enable-proxy --enable-agent --with-sqlite3 --with-net-snmp --with-libcurl --with-openipmi
make install
```

O Zabbix-Proxy irá rodar com SQLite, por qual motivo ? Ele é leve e tem baixíssimo custo de IO e o seu raspberry tem um cartão SD que irá rapidamente falhar se você usar algum outro banco com mais recursos e maior consumo de IO. Crie agora o banco de dados e altere o permissionamento para que o usuário Zabbix tenha controle dos arquivos:

```bash
cd database/sqlite3
mkdir /var/lib/sqlite/
sqlite3 /var/lib/sqlite/zabbix.db < schema.sql;
sqlite3 /var/lib/sqlite/zabbix.db < images.sql;
sqlite3 /var/lib/sqlite/zabbix.db < data.sql;
chown -R zabbix:zabbix /var/lib/sqlite/
```

Neste momento temos os binários do Zabbix e a base de dados criados. Vamos configurar o proxy.

Copie o arquivo **conf/zabbix_proxy.conf** localizado dentro do diretório do código fonte do Zabbix para **/usr/local/etc/zabbix_proxy.conf**

```bash
cp conf/zabbix_proxy.conf /usr/local/etc/zabbix_proxy.conf
```

Crie os diretórios para log e execução do zabbix

```bash
mkdir /opt/zabbix
mkdir /opt/zabbix/log
mkdir /opt/zabbix/run
chown zabbix. /opt/zabbix/log -R
chown zabbix. /opt/zabbix/run -R
ln -s /opt/zabbix/log /var/log/zabbix
chown -R zabbix:zabbix /var/lib/sqlite/
```

Altere as configurações do proxy no arquivo **/usr/local/etc/zabbix_proxy.conf** conforme exemplo abaixo. Trocando apenas <IP_SERVIDOR_ZABBIX> pelo respectivo IP.

```bash
ProxyMode=0
Server=<IP_SERVIDOR_ZABBIX>
Hostname=<Nome_do_proxy>
DBName=/var/lib/sqlite/zabbix.db
DBUser=zabbix
LogFile=/opt/zabbix/log/zabbix_proxy.log
PidFile=/opt/zabbix/run/zabbix_proxy.pid
ConfigFrequency=120
```

Verifique o local de instalação do fping, este local de instalação deverá ser colocado no arquivo de configuração, no meu ambiente o local é **/usr/bin/fping**

```bash
whereis fping
```

Altere o arquivo  **/usr/local/etc/zabbix_proxy.conf** com este caminho conforme exemplo abaixo

```bash
FpingLocation=/usr/sbin/fping
```

Altere as configurações do agente no arquivo **/usr/local/etc/zabbix_agentd.conf** conforme exemplo abaixo.

```bash
PidFile=/opt/zabbix/run/zabbix_agentd.pid
LogFile=/opt/zabbix/log/zabbix_agentd.log
LogFileSize=10
Server=127.0.0.1
DebugLevel=3
StartAgents=4
Hostname=nomedamaquina
```

Agora precisamos copiar e configurar os arquivos de inicialização do Zabbix. Algumas linhas especiais deverão ser adicionadas no início dos scripts de inicialização para adequa-los ao padrão do raspberry.

```bash
cp -v misc/init.d/debian/zabbix-* /etc/init.d/
mv /etc/init.d/zabbix-server /etc/init.d/zabbix-proxy
```

Edite o arquivo **/etc/init.d/zabbix-proxy** e adicione as linhas abaixo a partir na linha de número 6.

```bash
### BEGIN INIT INFO
# Provides: zabbix_proxy
# Required-Start: $all
# Required-Stop:
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: Zabbix proxy
# Description: Zabbix proxy daemon
### END INIT INFO
```

Altere as linhas seguintes conforme o exemplo

```bash
NAME=zabbix_proxy
DAEMON=/usr/local/sbin/${NAME}
DESC="Zabbix proxy daemon"
PID=/tmp/$NAME.pid
```

O mesmo procedimento deverá ser executado contra o arquivo **/etc/init.d/zabbix-agent**.

```bash
### BEGIN INIT INFO
# Provides: zabbix_agent
# Required-Start: $all
# Required-Stop:
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: Zabbix agent
# Description: Zabbix agent daemon
### END INIT INFO
```

Configure o sistema operacional para possibilitar a carga automática do Proxy e do agente.

```bash
update-rc.d -f zabbix-proxy defaults
update-rc.d -f zabbix-agent defaults
```

Pronto, seu raspberypi está apto a funcionar como um proxy do Zabbix.

**Aumentando a vida útil do cartão de memória**

Como os cartões de memória tem uma quantidade máxima de gravações por setor, para aumentar sua vida útil é necessário reduzir ao máximo a quantidade de gravações realizadas. Por padrão há uma série de operações que o linux realiza de gravação no disco como journal do ext3 e ext4, memória swap e para o objetivo deste post os arquivos de log e banco de dados do sqlite.

Desta forma os passos a seguir não são obrigatórios porém objetivam aumentar a vida útil do cartão de memória. Sem eles os meus cartões duraram em média 2 semanas de utilização, após estas alterações não tive mais problemas (até o momento 14/08/2013 já se passaram 2 meses dessas configurações).

Com as configurações abaixo será desabilitado a memória swap do sistema, bem como montado alguns diretórios como o /var/log, /var/tmp e os diretórios de log e da base de dados do zabbix (/opt/zabbix e /var/lib/sqlite).

Desabilite e desinstale o sistema de memória swap.

```bash
swapoff --all
apt-get remove dphys-swapfile
```

Edite o arquivo **/etc/rc.local** e adicione as linhas abaixo antes da linha com o conteúdo "exit 0"

```bash
swapoff --all
mkdir /opt/zabbix/log
mkdir /opt/zabbix/run
chown zabbix. /opt/zabbix/log -R
chown zabbix. /opt/zabbix/run -R
ln -s /opt/zabbix/log /var/log/zabbix
chown -R zabbix:zabbix /var/lib/sqlite/
```

Edite o arquivo **/etc/fstab** e adicione as seguintes linhas

```bash
tmpfs /var/tmp tmpfs nodev,nosuid,size=50M 0 0
tmpfs /var/log tmpfs nodev,nosuid,size=50M 0 0
tmpfs /opt/zabbix tmpfs nodev,nosuid,size=5M 0 0
tmpfs /var/lib/sqlite/ tmpfs nodev,nosuid,size=50M 0 0
```

Faça o reboot de seu equipamento e verifique as as partições foram montadas conforme esperado com o comando  **df -h**. Se tudo estiver correto sua tabela de partições estará similar a esta abaixo

[![ssh]({{ site.baseurl }}/assets/2013/05/ssh.png)]({{ site.baseurl }}/assets/2013/05/ssh.png)

Para aumentar mais ainda a vida útil do sdcard e recomendável  desabilitar o journal do ext4, para isso se faz necessário montar o sdcard em uma maquina linux e realizar os procedimentos abaixo.

Primeiramente identifique o device que esta o seu sdcard com o comando **dmesg | grep sd**, no meu caso montou em /dev/sdb.

Agora execute os comandos abaixo

```bash
tune2fs -O ^has_journal /dev/sdb2
e2fsck -f /dev/sdb2
```

`Para verificar se o journal foi desabilitado, após iniciar o raspberry, execute o comando **tune2fs -l /dev/mmcblk0p2 | grep features**, e não deve aparecer o **has_journal**`
