---
layout: post
title: Instalando Grafana no Ubuntu 14.04
date: 2016-03-12 17:16:18.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories: []
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/uncategorized/instalando-grafana-no-ubuntu-14-04/"
---

O Grafana é um poderoso e elegante software de dashboard, que possibilita integração com diversas aplicações.

<!--more-->

## Instalação de dependências

O primeiro passo, em qualquer instalação de servidor ao meu ver, é garantir que todos os pacotes básicos estejam devidamente atualizados.

```bash
apt-get update;
apt-get upgrade;
```

Antes de mais nada vamos remover o Apache para ter certeza que não teremos problemas com ele.

```bash
apt-get remove --purge apache2;
apt-get autoclean;
apt-get autoremove;
```

## Instalando o Grafana a partir do repositório oficial

Execute os comandos abaixo para adicionar o repositório do Grafana no Linux.

```bash
echo "deb https://packagecloud.io/grafana/stable/debian/ wheezy main" >> /etc/apt/sources.list
curl https://packagecloud.io/gpg.key | sudo apt-key add -
apt-get update
```

Realize a instalação do Grafana

```bash
apt-get install grafana
```

Atualize a permissão do aplicativo para que o mesmo possa iniciar em outras portas como 80 e 443

```bash
setcap 'cap_net_bind_service=+ep' /usr/sbin/grafana-server
```

Edite o arquivo **/etc/grafana/grafana.ini** alterando os parâmetros de inicialização do mesmo conforme exemplo abaixo

```bash
[server]
protocol = http
http_addr = 0.0.0.0
http_port = 80
```

Inicie o serviço do Grafana com comando abaixo

```bash
service grafana-server start
```
