---
layout: post
title: Copiando arquivos entre servidores VMWare ESXi
date: 2016-04-25 19:17:12.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories: []
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/uncategorized/copiando-arquivos-entre-vmware-esxi/"
---

Neste post veremos passo a passo como configurar um servidor VMWare ESXi para liberar cópia via SCP entre eles.

<!--more-->

Para realizar a cópia de arquivos entre servidores VMWare ESXi, é necessário a realização dos seguintes passos:

1. Iniciar serviço SSH;
2. Liberação do firewall para permitir as conexões SSH;

## Inicie o servidor SSH

Na console do vSphere, Selecione o seu servidor, clique em **Configuration** -> **Security Profile**, e depois na sessão **Services** clique em **Properties...**

[![vmware-ssh-service]({{ site.baseurl }}/assets/2016/04/vmware-ssh-service-300x162.png)]({{ site.baseurl }}/assets/2016/04/vmware-ssh-service.png)

Selecione o serviço SSH e configure para iniciar automaticamente.

[![vmware-ssh-service-2]({{ site.baseurl }}/assets/2016/04/vmware-ssh-service-2-281x300.png)]({{ site.baseurl }}/assets/2016/04/vmware-ssh-service-2.png)

[![vmware-ssh-service-3]({{ site.baseurl }}/assets/2016/04/vmware-ssh-service-3-300x200.png)]({{ site.baseurl }}/assets/2016/04/vmware-ssh-service-3.png)

## Configure o Firewall para permitir as conexões

Na console do vSphere, Selecione o seu servidor, clique em **Configuration** -> **Security Profile**, e depois na sessão **Firewall** clique em **Properties...**

[![vmware-ssh-firewall]({{ site.baseurl }}/assets/2016/04/vmware-ssh-firewall-300x162.png)]({{ site.baseurl }}/assets/2016/04/vmware-ssh-firewall.png)

Selecione as 2 opções de liberação de SSH (Cliente e Servidor)

[![vmware-ssh-firewall-2]({{ site.baseurl }}/assets/2016/04/vmware-ssh-firewall-2-281x300.png)]({{ site.baseurl }}/assets/2016/04/vmware-ssh-firewall-2.png)
