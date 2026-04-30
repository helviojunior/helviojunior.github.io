---
layout: post
title: Asterisk FastAGI com PHP e Nginx
date: 2016-12-21 09:21:28.000000000 -02:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Asterisk
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/voip/asterisk/asterisk-fastagi-com-php-e-nginx/"
---

Antes de mais nada é importante lembrarmos o que é o Asterisk AGI, segundo o site Voip-Info ([http://www.voip-info.org/wiki/view/Asterisk+AGI](http://www.voip-info.org/wiki/view/Asterisk+AGI)) AGI é o acrônimo de Asterisk Gateway Interface, em outras palavras, é uma interface de comunicação para adicionar novas funcionalidades ao Asterisk, basicamente o Asterisk chama um script externo que pode ser escrito em qualquer linguagem (Perl, PHP, C, Pascal, Shell e etc...).

Uma característica do AGI é que o script deve estar fisicamente na mesma maquina do Asterisk, o que pode acabar sobrecarregado essa maquina, sendo assim existe uma variante do AGI que é o FastAGI, que basicamente é a mesma coisa do AGI mas podendo ser utilizado via rede, pois o Asterisk conecta via socket TCP a um servidor externo para chamar o script. Para maiores informações consulte o link [http://www.voip-info.org/wiki/view/Asterisk+FastAGI](http://www.voip-info.org/wiki/view/Asterisk+FastAGI).

Dito isso, o que veremos neste post é como montar toda a estrutura de um servidor FastAGI. Neste utilizaremos como linguagem de programação o PHP e como servidor o Ubuntu 14.04 com os aplicativos Xinet + Nginx, a utilização do Nginx se da pelo fato de facilitar a criação de balanceamento de carga, segurança entre outros.

<!--more-->

Chega de lero lero e vamos colocar  a mão na massa!

Antes de mais nada vamos atualizar os pacotes do nosso servidor com os comandos abaixo

```bash
apt-get update;
apt-get upgrade;
```

## Instalando pacotes

Agora, vamos adicionar o source list do Nginx para garantir que estamos pegando a ultima versão. No momento da escrita deste post é a 1.11.7

```bash
echo deb http://nginx.org/packages/mainline/ubuntu/ `lsb_release --codename --short` nginx >> /etc/apt/sources.list
cd /tmp
wget http://nginx.org/keys/nginx_signing.key
sudo apt-key add nginx_signing.key
```

Atualize a lista de pacotes

```bash
apt-get -y update
```

E por fim vamos instalar os pacotes necessários (Nginx, Xinet e php5 cliente)

```bash
apt-get install nginx xinetd php5-cli
```

## Configurando diretórios do FastAGI

Agora que temos tudo instalado podemos iniciar o processo de configuração de nosso ambiente, o primeiro passo dessa configuração é criar o diretório e realizar o download dos scripts PHP da biblioteca que da suporte ao FastAGI, essa biblioteca é a PHPAGI disponível em [http://phpagi.sourceforge.net/](http://phpagi.sourceforge.net/).

```bash
mkdir -p /usr/local/fastagi
cd /tmp/
wget http://ufpr.dl.sourceforge.net/project/phpagi/phpagi/2.20/phpagi-2.20.tgz
tar -xzvf phpagi-2.20.tgz -C /usr/local/fastagi/
```

## Melhorias e correções

Para melhorar a organização e estruturação do nosso ambiente vamos fazer alguns ajustes de estrutura e correção de um bug na biblioteca do PHPAGI.

```bash
mv /usr/local/fastagi/phpagi-2.20/phpagi-fastagi.php /usr/local/fastagi/
```

Edite o arquivo **/usr/local/fastagi/phpagi-2.20/phpagi.php** e altere a linha **1693** para finar conforme abaixo

```bash
# Linha antiga (original)
$chpath = is_null($checkpath) ? $_ENV['PATH'] : $checkpath;

#Linha nova (como deve ficar)
$chpath = (is_null($checkpath) && isset($_ENV['PATH'])) ? $_ENV['PATH'] : $checkpath;
```

Verifique o local onde o PHP-CLI está instalado com o comando **which php**, em meu ambiente está instalado em **/usr/bin/php**, sendo assim edite o arquivo **/usr/local/fastagi/phpagi-fastagi.php** alterando a primeira linha para representar o local correto do interpretador de comando, que no nosso caso é o PHP, conforme exemplo abaixo

```bash
#!/usr/bin/php -q
```

Ainda neste arquivo edite a linha que contem o require_once conforme demonstrado abaixo

```bash
# Linha antiga (original)
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'phpagi.php');

#Linha nova (como deve ficar)
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'phpagi-2.20' . DIRECTORY_SEPARATOR . 'phpagi.php');
```

## Configurando Xinetd

Digite o comando abaixo

```bash
echo 'fastagi   4545/tcp' >> /etc/services
```

Crie o arquivo **/etc/xinetd.d/fastagi** com o seguinte conteúdo

```bash
service fastagi
{
 socket_type = stream
 protocol = tcp
 user = root
 group = nogroup
 server = /usr/local/fastagi/phpagi-fastagi.php
 wait = no
 protocol = tcp
 disable = no

 # Porta de escuta do serviço FastAGI, a mesma adicionada em '/etc/services'
 port = 4545

 # Restringe acesso somente na propria maquina (vindo do NGINX)
 only_from = 127.0.0.1 localhost
}
```

Reinicie o serviço XINETD

```bash
service xinetd restart
```

## Configurando NGINX

Edite o arquivo /etc/nginx/nginx.conf para que o mesmo fique com o seguinte conteúdo

```bash
user nginx;
worker_processes 1;

error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
 worker_connections 1024;
}

stream {

 upstream fastagi {
 server 127.0.0.1:4545;

 }

 server {
 listen 4573;
 proxy_pass fastagi;
 }
}
```

Reinicie o serviço NGINX

```bash
service nginx restart
```

## Criando primeiro script FastAGI

Agora que temos todo nosso ambiente pronto e funcionando vamos criar nosso primeiro script FastAGI. Para isso crie o arquivo **/usr/local/fastagi/sample.php** com o seguinte conteúdo

```bash
<?php
$fastagi->verbose('Parabéns, seu servidor FastAGI está funcionando!!!');
?>
```

## Utilizando FastAGI no plano de discagem do Asterisk

Por fim vamos criar nosso plano de discagem do Asterisk para chamar esse FastAGI. Edite o arquivo /etc/asterisk/extensions.conf e crie uma extensão para chamar o nosso primeiro FastAGI, em meu ambiente utilizei a extensão 2000.

```bash
exten = 2000,1,AGI(agi://127.0.0.1/sample.php)
```

Note que na chamada AGI usamos uma URI **agi://127.0.0.1/sample.php**, onde: **127.0.0.1** é o IP do servidor que responderá a requisição AGI via socket TCP, e o **/sample.php** é o script que queremos executar.

Agora basta você acessar a console do Asterisk e recarregar as configurações do seu plano de discagem com o comando **dialplan reload** e discar para a extensão 2000.

## Conclusão

Vimos como realizar toda a configuração do servidor para suportar o FastAGI, em nosso ambiente colocamos na mesma maquina do Asterisk, mas este pode certamente ser um servidor remoto, sendo assim com este procedimento você realizar diversas ações como integração com sistemas externos, comunicação com outras APIs, consultas a banco de dados, URA e etc... enfim o céu é o limite!!!

## Referencias

[http://enricosimonetti.com/asterisk-fastagi-with-php/](http://enricosimonetti.com/asterisk-fastagi-with-php/)

[https://www.nginx.com/resources/admin-guide/tcp-load-balancing/](https://www.nginx.com/resources/admin-guide/tcp-load-balancing/)
