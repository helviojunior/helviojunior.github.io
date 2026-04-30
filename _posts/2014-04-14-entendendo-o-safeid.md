---
layout: post
title: Entendendo a estrutura básica do SafeID
date: 2014-04-14 18:35:48.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- SafeID
- SafeTrend
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/safetrend/safeid/entendendo-o-safeid/"
---

## O que é o SafeID

O SafeID é um software de gestão de identidades e acessos da empresa SafeTrend ([www.safetrend.com.br](www.safetrend.com.br)). Este post tem por objetivo explicar de forma rápida e simples sua estrutura básica.

<!--more-->

## Entendendo o SafeID

Antes da configuração propriamente dita vamos entender um pouco do ambiente e da estrutura de dados do SafeID.

[caption id="attachment_821" align="alignnone" width="431"][![Modelo de implantação do SafeID]({{ site.baseurl }}/assets/2014/04/Implantação.png)]({{ site.baseurl }}/assets/2014/04/Implantação.png) Modelo de implantação do SafeID[/caption]

Na imagem acima podemos observar o modelo básico de implantação do SafeID onde os dados são importados de um sistema de ERP/Gestão de pessoal, processados e posteriormente integrados com outros sistemas (Microsoft Active Directory, Google Apps, Banco de dados e outros)

Neste post iremos configurar o SafeID para realizar essa importação de dados, e o sistema de origem do qual realizaremos este processo é um arquivo TXT separado por vírgula (CSV), mas poderia ser qualquer outro sistema (Microsoft Active Directory, Google Apps, Banco de dados e outros).

Seguindo em nosso ambiente a imagem abaixo demonstra as integrações do módulo de proxy do SafeID.

[caption id="attachment_822" align="alignnone" width="574"][![Ambiente de proxy]({{ site.baseurl }}/assets/2014/04/Proxy.png)]({{ site.baseurl }}/assets/2014/04/Proxy.png) Ambiente de proxy[/caption]

Como o SafeID pode atuar com o servidor na nuvem ou em loco no ambiente do cliente a integração entre o servidor do SafeID e os sistemas integrados se dá através de um módulo que chamamos de proxy, toda a comunicação entre o SafeID e este proxy sempre é originada pelo proxy através de HTTP ou HTTPS, em ambos os casos os dados são criptografados para garantir a segurança.

Último item que precisamos antes de realizar as configurações é entender a estrutura de dados do SafeID.

[caption id="attachment_824" align="alignnone" width="471"][![Estrutura de dados do SafeID]({{ site.baseurl }}/assets/2014/04/Estutura-de-dados.png)]({{ site.baseurl }}/assets/2014/04/Estutura-de-dados.png) Estrutura de dados do SafeID[/caption]
