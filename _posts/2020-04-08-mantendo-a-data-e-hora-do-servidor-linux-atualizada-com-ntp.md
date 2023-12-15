---
layout: post
title: Mantendo a data e hora do servidor Linux atualizada com NTP
date: 2020-04-08 17:57:13.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/mantendo-a-data-e-hora-do-servidor-linux-atualizada-com-ntp/"
---


Neste posto veremos como realizar a configuração do cliente NTP para que o servidor sempre mantenha a data e hora atualizada de forma automática.

<!--more-->

Etapa 1: lista de fusos horários disponíveis

```shell
timedatectl list-timezones
```

Etapa 2: definir o fuso horário desejado

```shell
sudo timedatectl set-timezone America/Sao_Paulo
```

Procedimento: configurar o NTPD no Ubuntu 14
configurar o NTP ubuntu

Abra o terminal ou conecte a sua SSH. Você deve logar como o usuário root. Digite o seguinte comando apt para instalar o NTP:

```shell
sudo apt-get update
sudo apt-get install ntp ntpdate
```

Sincronize o relógio do sistema com o servidor a.ntp.br manualmente (use este comando apenas uma vez, ou conforme necessário):

```shell
service ntp stop
ntpdate a.ntp.br
service ntp start
```

Configurar o NTP (opcional)

Abra o arquivo ntp.conf

```shell
sudo vi /etc/ntp.conf
```

Abra o arquivo /etc/ntp.conf e procure pelas linhas:

```shell
server 0.ubuntu.pool.ntp.org
server 1.ubuntu.pool.ntp.org
server 2.ubuntu.pool.ntp.org
server 3.ubuntu.pool.ntp.org
# Use Ubuntu's ntp server as a fallback.
server ntp.ubuntu.com
```

Altere para os servidores públicos do projeto http://ntp.br :

```shell
server a.ntp.br
server b.ntp.br
server c.ntp.br
```

Parar e iniciar o servidor NTP.

Para iniciar, parar, reiniciar o servidor NTP use os comandos abaixo:

```shell
service ntp start
service ntp stop
service ntp restart
```

**Atenção:** Caso o seu servidor esteja atrás de um Firewall é necessário liberar a comunicação do mesmo para a internet através do Protocolo UDP na porta 123.

Fonte: [https://brasilcloud.com.br/tutoriais/instalar-e-configurar-o-ntp-para-sincronizar-o-relogio-do-ubuntu-server-14/](https://brasilcloud.com.br/tutoriais/instalar-e-configurar-o-ntp-para-sincronizar-o-relogio-do-ubuntu-server-14/)
