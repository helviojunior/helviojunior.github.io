---
layout: post
title: Instalando Zabbix proxy + OpenWRT
date: 2013-05-13 13:18:46.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Zabbix
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/monitoramento/zabbix/instalando-zabbix-proxy-openwrt/"
---

O que é o Zabbix Proxy?

Zabbix proxy é uma espécie de agente remoto de monitoramento, onde pode-se monitorar ambientes remotos com diversos dispositivos, a vantagem disso é que se os dispositivos forem monitorados diretamente, pode ocasionar perda de dados, alertas falsos, lentidão e etc. Com isso, é comum que o Zabbix apresente gráficos incompletos, triggers acionadas erroneamente, entre outros problemas.

A partir da versão 1.6 o Zabbix disponibiliza o monitoramento por meio do proxy, onde apenas um Agente-Gerente envia as informações para o servidor Zabbix, conforme ilustração abaixo:

[![Proxy00]({{ site.baseurl }}/assets/2013/05/Proxy00.png)]({{ site.baseurl }}/assets/2013/05/Proxy00.png)

Agora que entendemos um pouco mais sobre o Zabbix Proxy, vamos a motivação deste artigo: O proxy pode ser executado em diversas distribuições Linux, mas ter um computador alocado somente para o Zabbix proxy é um recurso caro, desta forma fui atrás de opções mais baratas e descobri que ele pode ser executado no OpenWRT ([https://openwrt.org/](https://openwrt.org/)). O OpenWRT é uma distribuição Linux para dispositivos embarcados, ou seja, uma distribuição super enxuta, e suporta diversos dispositivos de baixo custo como roteadores Wifi (Dlink, Linksys, TP-link e etc).

<!--more-->

Neste ponto começaram os meus desafios, como instalar e fazer isso funcionar. Depois de apanhar um monte consegui fazer tudo rodar em um dispositivo com 4Mb de memória flash (onde os dados são armazenados) e 32 Mb de memória RAM. Desta forma resolvi compartilhar o passo a passo.

Para este post utilizei  o dispositivo Dlink DIR-320, a primeira coisa que fiz foi realizar a instalação padrão do OpenWRT que vem com diversos recursos (wifi, servidor web, dhcp e etc), porém como meu dispositivo dispões de somente 4Mb de memória flash, não houve espaço disponível instalar o Zabbix-Proxy e suas dependências, desta forma tive que personalizar minha própria imagem.

Agora vamos parar de lero, lero e vamos ao que interessa.

**Criando a imagem personalizada para gravar no dispositivo.**

O Howto original de como realizar este procedimento pode ser encontrado em [http://wiki.openwrt.org/doc/howto/obtain.firmware.generate](http://wiki.openwrt.org/doc/howto/obtain.firmware.generate). Como serei bem específico neste post segue abaixo os passos que realizei.

A criação da imagem necessita ser realizada em uma outra maquina que não o nosso dispositivo Dlink. No meu caso a maquina está rodando um Ubuntu server.

Para este ambiente criei um diretório dentro do **/root** nomeado openwrt.

[![001]({{ site.baseurl }}/assets/2013/05/001.png)]({{ site.baseurl }}/assets/2013/05/001.png)

**Download do gerador de imagem OpwnWRT**

- Acesse o endereço [http://backfire.openwrt.org/10.03.1/](http://backfire.openwrt.org/10.03.1/)
- Clique na arquitetura do seu dispositivo. Caso não saiba qual é verifique através deste link [http://wiki.openwrt.org/toh/start](http://wiki.openwrt.org/toh/start). No meu caso brcm47xx
- Realize o download do ImageBuilder (gerador de imagem) para o diretório criado anteriormente. Utilize i686 em sistemas 32 bits ou x86_64 para sistemas 64 bits
- Extraia o conteúdo do arquivo.

```bash
cd /root/openwrt/
wget http://backfire.openwrt.org/10.03.1/brcm47xx/OpenWrt-ImageBuilder-brcm47xx-for-Linux-i686.tar.bz2
tar –xvjf OpenWrt-ImageBuilder-brcm47xx-for-Linux-i686.tar.bz2
cd OpenWrt-ImageBuilder-brcm47xx-for-Linux-i686
```

**Download do pacote do Zabbix-proxy**

- Dentro do diretório **/root/openwrt/OpenWrt-ImageBuilder-brcm47xx-for-Linux-i686** crie um diretório nomeado **pkg**
- Entre no diretório pkg e realize o download do pacote do Zabbix-proxy

```bash
cd /root/openwrt/OpenWrt-ImageBuilder-brcm47xx-for-Linux-i686
mkdir pkg
wget http://downloads.openwrt.org/snapshots/trunk/brcm47xx/packages/zabbix-proxy_2.0.5-1_brcm47xx.ipk
```

[![002]({{ site.baseurl }}/assets/2013/05/002.png)]({{ site.baseurl }}/assets/2013/05/002.png)

- Dentro deste mesmo diretório crie um arquivo nomeado Packages com o seguinte conteúdo. Ou faça o download deste arquivo aqui ([Packages]({{ site.baseurl }}/assets/2013/05/Packages.zip))

```text
Package: zabbix-proxy
Version: 2.0.5-1
Depends: libc, libsqlite3
Source: feeds/packages/admin/zabbix
SourceFile: zabbix-2.0.5.tar.gz
SourceURL: @SF/zabbix
Section: admin
Maintainer: Mirko Vogt <mirko@openwrt.org>
Architecture: brcm47xx
Installed-Size: 222192
Filename: zabbix-proxy_2.0.5-1_brcm47xx.ipk
Size: 222216
MD5Sum: d6e25fdd0a4924f7038248b4b191f649
Description:  Zabbix proxy
```

[![003]({{ site.baseurl }}/assets/2013/05/003.png)]({{ site.baseurl }}/assets/2013/05/003.png)

Configurando o gerador de imagem para utilizar este diretório como repositório adicional de pacotes

- Dentro do diretório **/root/openwrt/OpenWrt-ImageBuilder-brcm47xx-for-Linux-i686** edite o arquivo **repositories.conf**
- Adicione a linha **src custom file:///root/opwndrt/OpenWrt-ImageBuilder-brcm47xx-for-Linux-i686/pkg**

[![005]({{ site.baseurl }}/assets/2013/05/005.png)]({{ site.baseurl }}/assets/2013/05/005.png)

Visualizando os perfis de geração de imagem disponível

Execute o comando

```bash
make info
```

Os perfis disponíveis serão listados.

```text
root@svux-0001:~/openwrt/OpenWrt-ImageBuilder-brcm47xx-for-Linux-i686# make infoCurrent Target: "brcm47xx"
Default Packages: base-files libc libgcc busybox dropbear mtd uci opkg udevtrigger hotplug2 dnsmasq iptables ppp ppp-mod-pppoe kmod-ipt-nathelper firewall wpad-mini kmod-switch kmod-diag nvram

Available Profiles:

Broadcom-b43:
Broadcom BCM43xx WiFi (default)
Packages: kmod-b43 kmod-b43legacy

Atheros:
Atheros WiFi
Packages: kmod-madwifi

Atheros-ath5k:
Atheros WiFi (atk5k)
Packages: kmod-ath5k

None:
No WiFi
Packages: -wpad-mini

WGT634U:
Netgear WGT634U
Packages: kmod-madwifi kmod-usb-core kmod-usb-ohci kmod-usb2 kmod-ocf kmod-crypto-ocf-ubsec-ssb

WL500GPv1:
ASUS WL-500g Premium v1 (Atheros WiFi)
Packages: kmod-madwifi kmod-usb-core kmod-usb-uhci kmod-usb2

WRT350Nv1:
Linksys WRT350Nv1
Packages: kmod-usb-core kmod-usb-ohci kmod-usb2 kmod-ssb-gige kmod-ocf-ubsec-ssb

WRTSL54GS:
Linksys WRTSL54GS
Packages: kmod-usb-core kmod-usb-ohci kmod-usb2 kmod-usb-storage kmod-scsi-core kmod-fs-ext3 e2fsprogs kmod-b43
```

Para a nossa utilização escolhi o perfil **None** por ser o mais enxuto deixando espaço para o que interessa, o Zabbix-proxy.

Gerando a imagem

- Dentro do diretório **/root/openwrt/OpenWrt-ImageBuilder-brcm47xx-for-Linux-i686** execute o comando **make image PROFILE=None PACKAGES="libc libsqlite3 zabbix-proxy fping"**

[![006]({{ site.baseurl }}/assets/2013/05/006.png)]({{ site.baseurl }}/assets/2013/05/006.png)

- Este processo demora alguns

Se tudo ocorreu como esperado será criado um diretório nomeado **bin/brcm47xx/** e haverá dentro dele as imagens.

[![007]({{ site.baseurl }}/assets/2013/05/007.png)]({{ site.baseurl }}/assets/2013/05/007.png)

No meu caso utilizei a imagem **openwrt-brcm47xx-squashfs.trx**  gerada para gravar em meu Dlink DIR-320.

Caso seu dispositivo já esteja com o OpenWRT, copie via SCP a imagem para o /tmp, acesse este diretório e execute o comando abaixo para gravar a imagem

```bash
mtd -r write openwrt-brcm47xx-squashfs.trx Linux
```

Caso seu dispositivo não esteja com o OpenWRT, o procedimento de gravação de imagem no dispositivo não será abordado neste post pois depende do seu dispositivo. No meu caso o próprio menu web do dlink permite essa gravação. A gravação da imagem segue o mesmo padrão de gravação das imagens OpenWRT e DD-WRT e pode ser localizado em diversos fórum pela internet inclusive nos sites oficiais da OpenWrt e DD-DRT.

Basta realizar a gravação e pronto, o dispositivo já está com o **OpenWRT** + **Zabbix-proxy**.

Como a imagem que gravamos é bem enxuta não há configuração web do dispositivo mostrarei como realizar o acesso ao dispositivo, troca de senha padrão do ssh e configuração da interface de rede.

Após a gravação desta imagem e reboot do dispositivo, o mesmo terá configurado em sua interface de rede o ip **192.168.1.1**, e não estará entregando IP via DHCP, desta forma configure um ip desta faixa na sua interface de rede, conforme imagem abaixo:

[![008]({{ site.baseurl }}/assets/2013/05/008.png)]({{ site.baseurl }}/assets/2013/05/008.png)

Acesse o dispositivo através de telnet, no meu caso utilizei o aplicativo Putty para isso.

[![009]({{ site.baseurl }}/assets/2013/05/009.png)]({{ site.baseurl }}/assets/2013/05/009.png)

Se tudo estiver correto a imagem abaixo será apresentada, caso não acesse verifique sua configuração de rede e conectividade até o dispositivo com o OpenWRT.

[![010]({{ site.baseurl }}/assets/2013/05/010.png)]({{ site.baseurl }}/assets/2013/05/010.png)

Digite o comando passwd para alterar a senha de root

Agora o dispositivo já pode ser acessado via SSH com o usuário root e a senha definida no passo anterior.

[![011]({{ site.baseurl }}/assets/2013/05/011.png)]({{ site.baseurl }}/assets/2013/05/011.png)

**Alterando a configuração de rede**

- Edite o arquivo **/etc/config/network**
- Localize a sessão LAN conforme a imagem abaixo:

[![012]({{ site.baseurl }}/assets/2013/05/012.png)]({{ site.baseurl }}/assets/2013/05/012.png)

- Edite a configuração com as informações da sua rede
- No meu caso ficou assim

[![013]({{ site.baseurl }}/assets/2013/05/013.png)]({{ site.baseurl }}/assets/2013/05/013.png)

- Onde meu IP é **192.168.0.30**, roteador padrão **192.168.0.1** e dns **192.168.0.1**
- Reinicie as configurações de rede com o comando **/etc/init.d/network restart** ou reinicie seu dispositivo com o comando **reboot**

**Configuração do Zabbix proxy**

Neste post faremos a configuração básica para funcionamento do Zabbix proxy em modo ativo. Modo este onde o Proxy efetua a comunicação com o Zabbix server, bem como com os hosts a serem verificados. Para outras opções de configuração consulte o manual do Zabbix.

Edite o arquivo de configuração do proxy em **/etc/zabbix_proxy.conf** e altere os seguintes parâmetros:

- **Hostname**: Nome do proxy (este nome deve ser único que o identificará no Zabbiz server e deve ser igual ao configurado no server)

```bash
Hostname=proxy_1
```

- **Server**: IP ou hostname do servidor zabbix

```bash
Server=monitoring.helviojunior.com.br
```

- **LogFile**: Caminho completo do arquivo de log

```bash
LogFile=/tmp/zabbix_proxy.log
```

- **PidFile**: Caminho completo do arquivo de controle

```bash
PidFile=/tmp/zabbix_proxy.pid
```

- **DBName**: Caminho completo do arquivo de base de dados

```bash
DBName=/tmp/zabbix_proxy.db
```

**Correções gerais**

- Copie os executáveis do fping para o diretório que o Zabbix utiliza

```bash
cp /usr/bin/fping* /usr/sbin/
```

- Altere as permissões de execução do fping

```bash
chown root:zabbix /usr/sbin/fping
chmod 710 /usr/sbin/fping
chmod ug+s /usr/sbin/fping
```

**Finalizando configurações de permissão e inicialização**

- Crie o usuário para o zabbix, inserindo a seguinte linha no **/etc/passwd**

```bash
zabbix:*:42223:42223:zabbix:/var:/bin/false
```

- Crie o grupo para o zabbix, inserindo a seguinte linha no **/etc/group**

```bash
zabbix:x:42223:
```

- Crie um arquivo nomeado **/etc/init.d/zabbix_proxy** com o seguinte conteúdo

```bash
#!/bin/sh /etc/rc.common
# Copyright (C) 2013 helviojunior.com.br

START=50

BIN=/usr/sbin/zabbix_proxy
PID=/tmp/zabbix_proxy.pid

start() {
 [ -x $BIN ] || exit 0

[ -x $PID ] || rm -rf $PID

$BIN
}

stop() {
 killall zabbix_proxy
 rm -f $PID
}
```

- Habilite o Zabbix para iniciar no boot com o comando

```bash
/etc/init.d/zabbix_proxy enable
```

- Inicie o Zabbix proxy

```bash
/etc/init.d/zabbix_proxy start
```
