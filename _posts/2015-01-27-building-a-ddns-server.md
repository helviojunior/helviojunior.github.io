---
layout: post
title: Criando um servidor de DDNS
date: 2015-01-27 20:38:52.000000000 -02:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/building-a-ddns-server/"
---

Neste post veremos como realizar a criação de um servidor de DDNS (Dynamic DNS) para ambientes corporativos, ou seja, utilizando o seu próprio servidor de DNS e servidor Web e tendo como cliente qualquer plataforma (Windows, Linux, Unix, Android, iOS e etc...).

<!--more-->

Mas antes de começarmos a parte técnica é importante entendermos o que é o DDNS e para que serve. DDNS é o acrônimo para Dynamic Domain Name System, ou seja um DNS dinâmico, porém continua a pergunta o que isso faz? Um DNS dinâmico permite que o seu cliente possa atualizar a sua informação.

Como posso usar isso na prática? Atualmente temos diversos provedores de internet de baixo custo que em geral utiliza IP váli dinâmico, ou seja, de tempos em tempos o ip é trocado. Quando usamos isso em um ambiente residencial não temos problemas, porém em um ambiente corporativo fica bem complicado de saber o ip válido de uma filial (por exemplo).

Em geral para resolver este problema diversas empresas e administradores usam serviços gratuitos ou pagos para ter um DDNS como DyDNS, No-IP entre outros, para poder ter um nome legal e atualizado como filial1.no-ip.org onde toda vez que trocar o ip da filial este host estará atualizado, porém ao fazer isso você precisa instalar um cliente de terceiro em seu ambiente que nem sempre são multi-plataforma, e precisa usar um domínio (nome) atribuído pelo provedor de serviço.

Sendo assim este post objetiva ensinar como fazer este mesmo processo  usando um servidor web IIS, seu servidor de DNS (qualquer um) e no lado do cliente um app qualquer que acesse uma url como wget, curl ou até um navegador como Internet Explorer, Chrome, etc...

## Passo 1 - Criando servidor Web

Antes de iniciar se certifique que haja instalado o .NET 4.0 em seu servidor.

Realize o download do arquivo [DDNSWeb.zip]({{ site.baseurl }}/assets/2015/01/DDNSWeb.zip) e extraia em seu servidor web em nosso ambiente faremos isso em **c:\Inetpub\DDNSWeb\.**

Agora acesse a console do IIS, e crie o site conforme o exemplo abaixo

[![site]({{ site.baseurl }}/assets/2015/01/site.png)]({{ site.baseurl }}/assets/2015/01/site.png)

Após isso se certifique que o ResourcePool do seu site está definido para utilizar o .NET 4.0

[![site2]({{ site.baseurl }}/assets/2015/01/site2.png)]({{ site.baseurl }}/assets/2015/01/site2.png)

Agora veremos alguns trechos do arquivo **update.aspx.cs** e o que alterar para o correto funcionamento do seu servidor DDNS

```csharp
if (auth_key != "authtest123")
 {
 Response.Status = "403 Access denied";
 Response.StatusCode = 403;
 Response.End();
 return;
 }
```

No bloco de código acima é verificado uma chave de autenticação, essa chave é passada pelo cliente para incrementar a segurança e se certificar que o cliente pode realizar essa atualização. Com poucas alterações você pode realizar uma verificação mais rebuscada vinda de um banco de dados por exemplo.

Ainda neste arquivo, você pode ver o código abaixo

```csharp
Dictionary<String, String> hosts = new Dictionary<string, string>();
hosts.Add("aae5cd33-5b51-49af-8b10-6e88d5af92a8", "filial1");
hosts.Add("759eacaa-f2d9-4324-86c4-b599a709890a", "filial2");
```

este código é na verdade uma tabela de ID versus host, onde estamos definindo um ID para cada host que desejamos atualizar, sendo assim nosso cliente passará somente o ID, e o sistema identifica qual é o host que ele deve atualizar.

O próximo trecho de código que veremos é a definição da sua zona DNS e o IP do seu servidor DNS. Em nosso exemplo a zona é teste.com.br e o servidor 192.168.254.200. Existe algumas questões de segurança do servidor DNS, mas comentarei no momento que estivermos realizando a configuração do DNS.

```csharp
String dnsZone = "teste.com.br";
IPAddress server = IPAddress.Parse("192.168.254.200");
```

## Passo 2 - Servidor DNS

Para que este aplicativo funcione o servidor DNS precisa permitir atualização dinâmica sem DNSSec, o que é inseguro, desta forma é altamente recomendado que você só libere isso em uma zona específica para DDNS, e que o seu servidor não libere a porta 53 TCP para a internet.

Abra o gerenciador de DNS, e edite a sua zona alterando o parâmetro de atualização para permitir atualizações não seguras, conforme a imagem abaixo.

[![dns1]({{ site.baseurl }}/assets/2015/01/dns1.png)]({{ site.baseurl }}/assets/2015/01/dns1.png)

## Passo 3 - Configurando cliente

Na pratica não existe um cliente em que você precisa fazer o download, instalar e configurar, qualquer navegador web pode ser cliente neste projeto, como Google Chrome, Wget, cURL, firefox entre outros. Esse conceito permite que usemos softwares como o wget e cURL para automatizar a requisição de tempos em tempos para sempre manter nosso host atualizado.

Mas antes de chegar neste ponto irei mostrar como montar a URL para prover a atualização, testa-la no Google Chrome, assim fica facil para você entender e aplicar a mesma URL em outros navegadores como wget, cURL e etc...

A url de atualização é composta basicamente por 3 partes:

- **Host**: Host do seu servidor web, pode nome dns ou IP.
- **Host_id**: ID do host conforme configurado no passo 1;
- **Auth_key**: Chave de autenticação conforme configurado no passo 1.

Sendo assim a url compleca ficará assim: http://host_do_servidor/update/host_id/auth_key, usando os valores do nosso exemplo e supondo que nosso servidor web responda pelo ip 192.168.254.100 a url ficará conforme abaixo:

```csharp
http://192.168.254.100/update/aae5cd33-5b51-49af-8b10-6e88d5af92a8/authtest123/
```

Agora coloque essa URL em seu navegador preferido, em nosso teste utilizarei o Google Chrome.

[![teste1]({{ site.baseurl }}/assets/2015/01/teste1.png)]({{ site.baseurl }}/assets/2015/01/teste1.png)

Se você recebeu como retorno um texto **OK**, isso indica que tudo está configurado corretamente e seu host foi atualizado com seu IP.

Conforme a imagem abaixo o registro do tipo A com nome host1 foi criado automaticamente na minha zona de DNS e tendo como valor o meu IP.

[![dns2]({{ site.baseurl }}/assets/2015/01/dns2.png)]({{ site.baseurl }}/assets/2015/01/dns2.png)
