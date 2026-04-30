---
layout: post
title: Resgatando IP válido do agente zabbix
date: 2013-07-20 10:47:17.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
- Monitoramento
- Zabbix
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/resgatando-ip-valido-do-agente-zabbix/"
---

Em uma das construtivas discuções do grupo Zabbix Brasil ([Blog](http://zabbixbrasil.org/)| [Yahoo](http://br.groups.yahoo.com/group/zabbix-brasil/)), foi levantado a necessidade de obter o IP válido dos agentes ou dos proxies em caso de ambiente com IP dinâmico.

Uma das soluções possíveis para resolver este problema foi proposta pelo membro do grupo Igor Araujo, esta solução consiste em criar uma página no proprio servidor apache do zabbix server que retorne o IP em que o agente está conectando e utilizar esta URL pelo agente que por sua vez irá obter o seu próprio IP e informa-lo ao Zabbix server.

<!--more-->

Chega de lero, lero e vamos ao passo a passo desta solução.

**Criando a página no apache**

Localize o diretório onde estão os arquivos do front-end (web) do zabbix, no meu ambiente está em **/usr/share/zabbix.**

Crie um subdiretório dentro deste com o nome **ip**

```bash
mkdir /usr/share/zabbix/ip
```

Crie um arquivo nomeado **/usr/share/zabbix/ip/index.php** com o seguinte conteúdo

```php
<?php
 $ip = $_SERVER['REMOTE_ADDR'];
 echo $ip;
 ?>
```

Caso as permissões dos seus arquivos web estejam para outro usuário que não o root, defina as permissões para o usuário especificado.

Realize o teste de acesso com a url do seu servidor web ex.: http://meuservidor.com.br/zabbix/ip/

[![IP_001]({{ site.baseurl }}/assets/2013/07/IP_001.png)]({{ site.baseurl }}/assets/2013/07/IP_001.png)

**Configurando o agente**

O Zabbix suporta diversos sistemas operacional como cliente (Linux, Windows MAC e etc...), porem para o objetivo deste tutorial a unica diferença entre eles será a forma de instalação do aplicativo cURL e o caminho de chamada deste na configuração do agente,  desta forma serão mostrados como realizar em windows e linux.

Linux

Instale o aplicativo cURL através do comando

```bash
apt-get install curl
```

Windows e outras plataformas

Realize o download do executável do aplicativo no site oficial do fabricante (http://curl.haxx.se/download.html)

Descompacte o executável no mesmo diretório de instalação do agente do zabbix. No meu ambiente é c:\zabbix.

Este aplicativo terá a função de acessar a url que criamos no servidor e extrair somente o ip, para isso a sintaze de execução é curl -s url, onde o -s extrai todo o cabeçalho http deixando somente o conteúdo.

Edite o arquivo de configuração do agente zabbix (zabbix_agentd.conf) e adicione as seguintes linhas

Para linux

```bash
#Endereço IP WAN
UserParameter=net.ipaddress,curl -s http://meuservidor.com.br/zabbix/ip/
```

Para windows

```bash
#Endereço IP WAN
UserParameter=net.ipaddress,c:\zabbix\commands\curl -s http://meuservidor.com.br/zabbix/ip/
```

Reinicie o agente

**Criando o item de nomitoramento no Host no zabbix**

Vá no host desejado, clique em Items e clique em Novo Item

Cadastre o novo item conforme informações abaixo:

- Key: net.ipaddress
- Type of information: Text
- Update interval: 180

Quanto ao item **Update interval** vale a pena considerar qual é o tempo ideal para o seu ambiente para não sobrecarregar o seu servidor do zabbix.

[![IP_002]({{ site.baseurl }}/assets/2013/07/IP_002.png)]({{ site.baseurl }}/assets/2013/07/IP_002.png)

Basta salvar o item que automaticamente o IP do host será capturado na próxima verificação.
