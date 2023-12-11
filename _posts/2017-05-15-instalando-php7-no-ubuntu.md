---
layout: post
title: Instalando PHP7 no Ubuntu
date: 2017-05-15 17:02:32.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Linux
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/linux/instalando-php7-no-ubuntu/"
---

## Instalação do PHP7 no Ubuntu

Segue um passo a passo para instalação do PHP7 no Ubuntu.

### Preparando Ambiente

Primeiro passo é remover a versão atual do PHP:

```shell
sudo apt-get remove --purge php5*
```

Depois, adicionar o repositório do PHP7 e atualizar a listagem de pacotes:

```shell
wget http://nginx.org/packages/keys/nginx_signing.key
cat nginx_signing.key | sudo apt-key add -
apt-get update
```

### Instalando PHP7 + NGINX

Adicione o repositório do NGINX e atualize a listagem de pacotes:

```shell
echo deb http://nginx.org/packages/mainline/ubuntu/ $(lsb_release --codename --short) nginx >> /etc/apt/sources.list
sudo apt-get update
```

E por fim, instale o NGINX + PHP-FPM:

```shell
sudo apt-get install nginx php7.0-common php7.0-cli php7.0-fpm
```

### Instalando PHP7 + Apache2

Recomendo a utilização do ambiente com NGINX, por ter menos falhas e um desempenho muito melhor. Mas caso precise/deseje utilizar o Apache, basta instalar com os comandos abaixo:

```shell
apt-get install apache2 php7.0-common php7.0-cli php7.0 libapache2-mod-php7.0
```

### Biblioteca para MySQL

Caso vá utilizar o MySQL como base de dados, basta adicionar o pacote do MySQL:

```shell
sudo apt-get install php7.0-mysql
```

Pronto!
