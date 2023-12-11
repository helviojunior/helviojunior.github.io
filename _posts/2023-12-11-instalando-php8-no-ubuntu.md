---
layout: post
title: Instalando PHP8 no Ubuntu
date: 2023-12-11 15:00:00.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Linux
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/linux/instalando-php8-no-ubuntu/"
---

## Instalação do PHP8 no Ubuntu

Segue um passo a passo para instalação do PHP8 no Ubuntu.

### Preparando Ambiente

Primeiro passo é remover a versão atual do PHP:

```shell
sudo apt remove --purge php5*
```

Depois, adicionar o repositório do PHP8 e atualizar a listagem de pacotes:

```shell
wget http://nginx.org/packages/keys/nginx_signing.key
cat nginx_signing.key | sudo apt-key add -
apt update
```

### Instalando PHP8 + NGINX

Adicione o repositório do NGINX e atualize a listagem de pacotes:

```shell
echo deb http://nginx.org/packages/mainline/ubuntu/ $(lsb_release --codename --short) nginx >> /etc/apt/sources.list
sudo apt update
```

E por fim, instale o NGINX + PHP-FPM:

```shell
sudo apt install nginx php8.1-common php8.1-cli php8.1-fpm
```

### Instalando PHP8 + Apache2

Recomendo a utilização do ambiente com NGINX, por ter menos falhas e um desempenho muito melhor. Mas caso precise/deseje utilizar o Apache, basta instalar com os comandos abaixo:

```shell
apt install apache2 php8.1-common php8.1-cli php8.1 libapache2-mod-php8.1
```

### Biblioteca para MySQL

Caso vá utilizar o MySQL como base de dados, basta adicionar o pacote do MySQL:

```shell
sudo apt install php8.1-mysql
```

Pronto!
