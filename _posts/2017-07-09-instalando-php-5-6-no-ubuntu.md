---
layout: post
title: Instalando PHP 5.6 no ubuntu
date: 2017-07-09 10:22:15.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Linux
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/linux/instalando-php-5-6-no-ubuntu/"
---

## Instalação do PHP5.6 no Ubuntu

Segue um passo a passo para instalação do PHP5.6 no Ubuntu.

### Preparando Ambiente

Primeiro passo é remover a versão atual do PHP:

```shell
sudo apt-get remove --purge php5*
```

Depois, adicionar o repositório do PHP5.6 e atualizar a listagem de pacotes:

```shell
sudo add-apt-repository ppa:ondrej/php
sudo apt-get update
```

### Instalando PHP5.6 + NGINX

Adicione o repositório do NGINX e atualize a listagem de pacotes:

```shell
echo deb http://nginx.org/packages/mainline/ubuntu/ $(lsb_release --codename --short) nginx >> /etc/apt/sources.list
sudo apt-get update
```

E por fim, instale o NGINX + PHP-FPM:

```shell
sudo apt-get install nginx php5.6-common php5.6-cli php5.6-fpm
```

### Instalando PHP5.6 + Apache2

Recomendo a utilização do ambiente com NGINX, por ter menos falhas e um desempenho muito melhor. Mas caso precise/deseje utilizar o Apache, basta instalar com os comandos abaixo:

```shell
apt-get install apache2 php5.6-common php5.6-cli php5.6 libapache2-mod-php5.6
```

### Biblioteca para MySQL

Caso vá utilizar o MySQL como base de dados, basta adicionar o pacote do MySQL:

```shell
sudo apt-get install php5.6-mysql
```

Pronto!

