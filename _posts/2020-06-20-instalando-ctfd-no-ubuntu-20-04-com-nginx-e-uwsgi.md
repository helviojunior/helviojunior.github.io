---
layout: post
title: Instalando CTFd no Ubuntu 20.04 com Nginx e uWSGI
date: 2020-06-20 00:06:44.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Capture The Flag
tags:
- Offensive Security
- Capture The Flag
author: Helvio Junior (m4v3r1ck)
permalink: "/it/instalando-ctfd-no-ubuntu-20-04-com-nginx-e-uwsgi/"
---


CTFd é uma plataforma desenvolvida em Python para organização de jogos no estilo Capture sua Bandeira (Capture The Flag) muito comum em ambientes controlados de Segurança Ofensiva e Defensiva. Segue a url do fabricante ([https://ctfd.io/](https://ctfd.io/))

Como demorei para encontrar tutoriais completos e atualizados resolvi juntar tudo em um só e funcional para vocês. Até a versão 18.04 do Ubuntu há um tutorial funcional utilizando a aplicação gunicorn, porém como este pacote foi descontinuado na versão 20.04 do Ubuntu tive que buscar uma forma de fazer e é este trabalho que trago para vocês de forma organizada e comando por comando.

<!--more-->

## Instalando pacotes e dependências

Antes de mais nada se faz necessário realizar a instalação de todas as dependências necessárias para o correto funcionamento do ambiente.

Adicionando repositório do nginx no ambiente

```shell
root@M4v3r1ck:~# echo deb http://nginx.org/packages/mainline/ubuntu/ `lsb_release --codename --short` nginx > /etc/apt/sources.list.d/nginx.list
root@M4v3r1ck:~# curl -s http://nginx.org/keys/nginx_signing.key | apt-key add -
```

Atualizando o ambiente

```shell
root@M4v3r1ck:~# apt-get update && apt-get -y upgrade
```

Instalando pacotes e dependências

```shell
root@M4v3r1ck:~# apt install nginx python3 python3-pip python3-dev build-essential libssl-dev libffi-dev python3-setuptools python3-venv
```

## Pré-configurando o NGINX

Como utilizaremos o NGINX como um proxy reverso para expor o CTFd para a internet, então vamos realizar uma pré-configuração do mesmo, para posteriormente ajustar para a configuração final. Estamos fazendo isso neste ponto pois logo a frente iremos realizar um teste inicial de acesso ao CTFd, e para isso precisaremos que essa comunicação já seja realizada via NGINX.

Edite o arquivo **/etc/nginx/nginx.conf** para que o mesmo fique exatamente conforme abaixo:

```shell
user  nginx;
worker_processes  1;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    limit_conn_zone $binary_remote_addr zone=addr:10m;
    server_names_hash_bucket_size  256;

    client_max_body_size 10m;

    log_format log_standard '$remote_addr, $http_x_forwarded_for - $remote_user [$time_local] "$request_method $scheme://$host$request_uri $server_protocol" $status $body_bytes_sent "$http_referer" "$http_user_agent" to: $upstream_addr';

    access_log /var/log/nginx/access.log log_standard;
    error_log /var/log/nginx/error.log;

    sendfile        on;
    #tcp_nopush     on;

    keepalive_timeout  65;

    #gzip  on;

    include /etc/nginx/conf.d/*.conf;
}
```

Edite o arquivo **/etc/nginx/conf.d/default.conf** de forma que o mesmo fique com o conteúdo abaixo:

```shell
server {
    listen      80;
    server_name _;

    location / {

        proxy_pass http://127.0.0.1:8080;
        #include uwsgi_params;
        #uwsgi_pass unix:/home/ctfd/CTFd/ctfd.sock;

    }
}
```

Reinicie o nginx

```shell
root@M4v3r1ck:~# /etc/init.d/nginx restart
```

## Instalando e configurando o CTFd

Agora que temos o nginx já funcional, podemos instalar o CTFd e suas dependências.

Adicione o usuário e grupo conforme abaixo

```shell
root@M4v3r1ck:~# groupadd ctfd
root@M4v3r1ck:~# adduser --disabled-password --ingroup ctfd ctfd
```

Altere para o contexto do usuário

```shell
root@M4v3r1ck:~# su - ctfd
```

Realize o download do CTFd. Note que o comando está sendo executado com o usuário ctfd e dentro do seu diretório home (/home/ctfd)

```shell
ctfd@M4v3r1ck:~$ git clone https://github.com/CTFd/CTFd.git
```

Agora vamos criar um ambiente virtual para isolar o nosso ambiente de outras aplicações python.

```shell
ctfd@M4v3r1ck:~$ python3 -m venv CTFd
```

Isso instalará uma cópia local do Python e do pip para um diretório chamado CTFd.

Antes de instalar aplicativos no ambiente virtual, você precisa ativá-lo. Faça isso digitando:

```shell
ctfd@M4v3r1ck:~$ source CTFd/bin/activate
```

Seu prompt mudará para indicar que você agora está operando no ambiente virtual. Ele se parecerá com isso (CTFd) ctfd@M4v3r1ck:~$.

Agora vamos instalar todas as dependências python necessárias para o ctfd.

**NOTA: Independente da versão do Python neste ponto usar o pip ao invés do pip3 (pois já estamos dentro de um ambiente python3)**

Primeiramente, vamos instalar o wheel com a instância local do pip para garantir que nossos pacotes serão instalados mesmo se estiverem faltando arquivos wheel:

```shell
(CTFd) ctfd@M4v3r1ck:~$ pip install wheel
```

Posteriormente, iremos instalar o uwsgi, flask e as dependências

```shell
(CTFd) ctfd@M4v3r1ck:~$ pip install uwsgi flask testresources werkzeug==0.16.0
(CTFd) ctfd@M4v3r1ck:~$ pip install -r CTFd/requirements.txt
```

Agora podemos testar o sistema

```shell
(CTFd) ctfd@M4v3r1ck:~$ cd CTFd
(CTFd) ctfd@M4v3r1ck:~/CTFd$ uwsgi --socket 0.0.0.0:8080 --protocol=http -w wsgi:app
```

Abra o seu navegador e acesse o IP do seu servidor http://[IP], a imagem igual abaixo deve ser exibida

![Imagem ilustrativa]({{site.baseurl}}/assets/2020/06/Xnip2020-06-20_00-37-23.jpg)

Quando você tiver confirmado que ele está funcionando corretamente, pressione CTRL-C na janela do seu terminal.

Acabamos agora o nosso ambiente virtual, para que possamos desativá-lo:

```shell
(CTFd) ctfd@M4v3r1ck:~$ deactivate
```

Agora, qualquer comando Python voltará a usar o ambiente do sistema Python.

Criar arquivo `ctfd.ini`

Note que neste arquivo iremos definir o modo de conexão (entre o nginx e o wsgi) como sendo um socket unix que é mais rápido e seguro.

```shell
[uwsgi]
module = wsgi:app

master = true
processes = 5

pidfile = ctfd.pid
socket = ctfd.sock
chmod-socket = 660
vacuum = true

die-on-term = true

logto = /var/log/ctfd/%n.log
```

Volte ao acesso como root

```shell
ctfd@M4v3r1ck:~$ exit
```

Os comandos agora são executados como **root**.

Crie o diretório de logs e defina sua permissão

```shell
ctfd@M4v3r1ck:~# mkdir /var/log/ctfd
ctfd@M4v3r1ck:~# chown ctfd:adm /var/log/ctfd/
```

Crie o arquivo para logrotate com nome **/etc/logrotate.d/ctfd** com o seguinte conteúdo:

```shell
/var/log/ctfd/*.log {
    daily
    missingok
    rotate 365
    compress
    datetext
    delaycompress
    notifempty
    create 640 ctfd adm
    sharedscripts
    postrotate
            if [ -f /home/ctfd/CTFd/ctfd.pid ]; then
                    kill -HUP `cat /home/ctfd/CTFd/ctfd.pid`
            fi
    endscript
}
```

Crie o arquivo **/etc/systemd/system/ctfd.service**

```shell
[Unit]
Description=CTFd Service
After=network.target

[Service]
User = ctfd
Group = nginx
WorkingDirectory=/home/ctfd/CTFd
Environment="PATH=/home/ctfd/CTFd/bin"
ExecStart=/home/ctfd/CTFd/bin/uwsgi --ini ctfd.ini

[Install]
WantedBy=multi-user.target
```

Podemos agora iniciar o serviço uWSGI que criamos e habilitá-lo para que ele seja iniciado na inicialização:

```shell
root@M4v3r1ck:~# systemctl daemon-reload
root@M4v3r1ck:~# systemctl enable ctfd
root@M4v3r1ck:~# systemctl start ctfd
```

Verifique o status

```shell
root@M4v3r1ck:~# systemctl status ctfd
```

Você deve ver um resultado como este:

```shell
root@M4v3r1ck:~# systemctl status ctfd
● ctfd.service - CTFd Service
     Loaded: loaded (/etc/systemd/system/ctfd.service; enabled; vendor preset: enabled)
     Active: active (running) since Sat 2020-06-20 03:51:28 UTC; 8s ago
   Main PID: 27730 (uwsgi)
      Tasks: 6 (limit: 2249)
     Memory: 59.2M
     CGroup: /system.slice/ctfd.service
             ├─27730 /home/ctfd/CTFd/bin/uwsgi --ini ctfd.ini
             ├─27740 /home/ctfd/CTFd/bin/uwsgi --ini ctfd.ini
             ├─27741 /home/ctfd/CTFd/bin/uwsgi --ini ctfd.ini
             ├─27742 /home/ctfd/CTFd/bin/uwsgi --ini ctfd.ini
             ├─27743 /home/ctfd/CTFd/bin/uwsgi --ini ctfd.ini
             └─27744 /home/ctfd/CTFd/bin/uwsgi --ini ctfd.ini
```

Estando tudo correto agora vamos editar o nginx para se conectar ao wsgi através do socket unix que criamos.

Altere o arquivo **/etc/nginx/conf.d/default.conf** para:

```shell
server {
    listen      80;
    server_name _;

    location / {

        uwsgi_param   Host                 $host;
        uwsgi_param   X-Real-IP            $remote_addr;
        uwsgi_param   X-Forwarded-For      $proxy_add_x_forwarded_for;
        uwsgi_param   X-Forwarded-Proto    $http_x_forwarded_proto;

        proxy_read_timeout 600;
        proxy_connect_timeout 1d

;
        proxy_max_temp_file_size 5024m;
        proxy_send_timeout 600;
        uwsgi_read_timeout 600;
        uwsgi_send_timeout 600;
        include uwsgi_params;

        uwsgi_pass unix:/home/ctfd/CTFd/ctfd.sock;

    }
}
```

Recarregue a configuração do nginx

```shell
root@M4v3r1ck:~# nginx -s reload
```

Realize o teste de acesso ao CTFd através da URL http://[IP]

Agora você tem o CTFd rodando na porta 80 do seu servidor, basta o teste de acesso ao CTFd através da URL http://[IP].

Fontes:
- [How to Serve Flask Applications with uWSGI and Nginx on Ubuntu 18.04](https://www.digitalocean.com/community/tutorials/how-to-serve-flask-applications-with-uswgi-and-nginx-on-ubuntu-18-04-pt)
- [CTFd on Ubuntu 18.04](https://ev1z.be/2018/10/23/ctfd-on-ubuntu-18-04/)

