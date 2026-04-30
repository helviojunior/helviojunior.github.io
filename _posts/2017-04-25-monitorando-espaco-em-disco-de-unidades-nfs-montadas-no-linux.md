---
layout: post
title: Monitorando espaço em disco de unidades NFS montadas no Linux
date: 2017-04-25 14:23:50.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Zabbix
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/monitoramento/zabbix/monitorando-espaco-em-disco-de-unidades-nfs-montadas-no-linux/"
---

Aprenda passo-a-passo como descobrir e monitorar as unidades NFS montadas em um servidor Linux.

<!--more-->

Edite o arquivo de configuração do agente, em meu ambiente localizado em /usr/local/etc/zabbix_agentd.conf e adicione no final do arquivo a seguinte linha

```bash
UserParameter=vfs.nfs.discovery,echo "{  \"data\":[" && cnt=1 && cat /etc/mtab | grep -v pipefs | grep nfs | while read -r line; do if [ "$cnt" -gt "1" ]; then echo ","; fi; FSNAME=$(echo $line|awk '{print $2}'|sed -e 's/\\/\\\\/g' -e 's|/|\\/|g') && FSTYPE=$(echo $line|awk '{print $3}') && echo " { \"{#NFSNAME}\":\"${FSNAME}\",\"{#NFSTYPE}\":\"${FSTYPE}\",\"{#NFSDEV}\":\"${FSDEV}\",\"{#BDNAME}\":\"${BDNAME}\"}"; cnt=$(($cnt+1)); done && echo "] }"
```

Reinicie o agente

Agora no servidor Asterisk realize a importação do template ([disponível aqui]({{ site.baseurl }}/assets/2017/04/zbx_template_os_linux.zip)), este arquivo somente irá atualizar o template **Template OS Linux** para adicionar o novo item de discovery (para descobrir as unidades NFS) bem como inserir os itens de monitoramento, alerta e gráfico para essas unidades.

Segue abaixo como realizar a importação:

Clique em Configuration > Templates > Import

[![nfs.import.template]({{ site.baseurl }}/assets/2017/04/nfs.import.template-1030x99.jpg)]({{ site.baseurl }}/assets/2017/04/nfs.import.template-1030x99.jpg)

Realize o download do arquivo, descompacte o conteudo e selecione o arquivo XML.

Logo após clique em Import.

[![nfs.import.template2]({{ site.baseurl }}/assets/2017/04/nfs.import.template2.jpg)]({{ site.baseurl }}/assets/2017/04/nfs.import.template2.jpg)

Pronto!

Caso não tenha dado erro sua importação ocorreu com sucesso, caso deseje ver os itens inseridos basta ir no **Template OS Linux** conforme imagem abaixo.

[![nfs.import.template3]({{ site.baseurl }}/assets/2017/04/nfs.import.template3-1030x274.jpg)]({{ site.baseurl }}/assets/2017/04/nfs.import.template3-1030x274.jpg)
