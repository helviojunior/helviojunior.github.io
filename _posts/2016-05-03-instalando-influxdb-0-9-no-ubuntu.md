---
layout: post
title: Instalando InfluxDB 0.9 no ubuntu
date: 2016-05-03 17:10:11.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- InfluxDB
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/influxdb/instalando-influxdb-0-9-no-ubuntu/"
---

InfluxDB ([https://influxdata.com/](https://influxdata.com/)) é uma base de dados serial, muito utilizada para sistemas de sensores e monitoramamento.

Neste artigo mostraremos como instalar o InfluxDB e configura-lo para salvar as base de dados e informações em um segundo disco. Esta metodologia é comumente utilizada em servidores de produção onde tem-se os dados em um disco separado do sistema operacional.

<!--more-->

Antes de mais nada vamos garantir que o nosso sistema esteja atualizado com os comandos abaixo

```bash
apt-get update;
apt-get upgrade;
```

Instale as dependências necessárias

```bash
apt-get install libaio1 libaio-dev xfsprogs
```

Utilizando o seu aplicativo de preferência, crie uma partição no disco secundário

Formate o disco com o comando abaixo, apenas trocando **/dev/xpto1** para o nome real do seu disco

```bash
mkfs.xfs -f -d agcount=256 -l size=128m,lazy-count=1,version=2 -L influx_bases /dev/xpto1
```

Localize o UUID da sua partição

```bash
ls -l /dev/disk/by-uuid
```

[![001]({{ site.baseurl }}/assets/2016/05/001.png)]({{ site.baseurl }}/assets/2016/05/001.png)

Edite o arquivo **/etc/fstab** e adicione a linha abaixo, utilizando o UUID do seu disco, para que o seu disco seja montado na inicialização

```bash
UUID=d7d8c63c-7d10-42e0-958c-fdd5c11181ef /databases/influxdb/ xfs allocsize=256m,logbufs=8,noatime,nobarrier,nodiratime,attr2,logbsize=256k 0 0
```

Crie os diretórios necessários

```bash
mkdir -p /databases/influxdb/
```

Monte o sistema de arquivos

```bash
mount -a
```

Faça download do instalador e realize instalação do InfluxDB

```bash
wget https://dl.influxdata.com/influxdb/releases/influxdb_0.9.6_amd64.deb
dpkg -i influxdb_0.9.6_amd64.deb
```

Inicie o serviço

```bash
service influxdb start
```

Crie uma base de dados para se certificar que toda a estrutura de diretório do influx seja criada

```bash
influx
CREATE DATABASE teste
exit
```

Defina as permissões do diretório

```bash
chown -R influxdb:influxdb /databases/influxdb/
```

Pare o serviço do InfluxDB e copie os arquivos/diretórios

```bash
service influxdb stop
rsync -av /var/lib/influxdb/* /databases/influxdb/
mv /var/lib/influxdb /var/lib/influxdb_old
```

Edite o arquivo de configuração **/etc/influxdb/influxdb.conf** para utilizar a nova estrutura de diretórios

```bash
[meta]
 #dir = "/var/lib/influxdb/meta"
 dir = "/databases/influxdb/meta"

[data]
 #dir = "/var/lib/influxdb/data"
 dir = "/databases/influxdb/data"

 #wal-dir = "/var/lib/influxdb/wal"
 wal-dir = "/databases/influxdb/wal"

[hinted-handoff]
 #dir = "/var/lib/influxdb/hh"
 dir = "/databases/influxdb/hh"
```

Inicie o serviço e verifique se o mesmo está rodando

```bash
service influxdb stop
service influxdb status
```

Exclua a base de teste criada durante o processo

```bash
influx
SHOW DATABASES
DROP DATABASE teste
SHOW DATABASES
exit
```

Para maiores informações de como utilizar o InfluxDB favor consultar a referência oficial do fabricante:[https://docs.influxdata.com/influxdb/v0.12/introduction/getting_started/](https://docs.influxdata.com/influxdb/v0.12/introduction/getting_started/)
