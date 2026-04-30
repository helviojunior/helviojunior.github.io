---
layout: post
title: Como mudar a pasta de backup do iTunes no computador
date: 2018-05-16 11:03:55.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/como-mudar-pasta-de-backup-do-itunes-no-computador/"
---

Por: [HELITO BIJORA](https://www.techtudo.com.br/colaborador/helito-bijora.html) para o TechTudo

Fonte: [http://www.techtudo.com.br/dicas-e-tutoriais/noticia/2015/08/como-mudar-pasta-de-backup-do-itunes-no-computador.html](http://www.techtudo.com.br/dicas-e-tutoriais/noticia/2015/08/como-mudar-pasta-de-backup-do-itunes-no-computador.html)

*** Este arquivo é apenas uma cópia do original postado no TechTudo (acima referenciado)

O iTunes salva os backups de dispositivos iOS no disco C: do computador. Com isso, dependendo da quantidade e tamanho dos backups, a pasta pode ocupar vários gigabytes e faltar espaço na unidade do sistema. Veja como mover a pasta de backup do serviço para outra partição ou HD e criar um link simbólico na localização original.

<!--more-->

[caption id="attachment_1733" align="alignnone" width="695"][![Veja como mudar a pasta de backup do iTunes (Foto: Reprodução/Edivaldo Brito)]({{ site.baseurl }}/assets/2018/05/executando-itunes.png)]({{ site.baseurl }}/assets/2018/05/executando-itunes.png) Veja como mudar a pasta de backup do iTunes (Foto: Reprodução/Edivaldo Brito)[/caption]

**Passo 1.** Pressione a tecla “Windows + R” para abrir o “Executar” e entre com o comando “%APPDATA%\Apple Computer\MobileSync” (sem as aspas);

[caption id="attachment_1734" align="alignnone" width="695"][![Acessando pasta de backup do iTunes (Foto: Reprodução/Helito Bijora) ]({{ site.baseurl }}/assets/2018/05/captura-de-tela-2015-08-18-as-094612.png)]({{ site.baseurl }}/assets/2018/05/captura-de-tela-2015-08-18-as-094612.png) Acessando pasta de backup do iTunes (Foto: Reprodução/Helito Bijora)[/caption]

**Passo 2.** A pasta de backups do iTunes será aberta. Mova a pasta “Backup” para um local de sua preferência, como uma outra partição ou HD externo;

[caption id="attachment_1735" align="alignnone" width="695"][![Movendo pasta de backup para outra unidade (Foto: Reprodução/Helito Bijora) ]({{ site.baseurl }}/assets/2018/05/captura-de-tela-2015-08-18-as-094936.png)]({{ site.baseurl }}/assets/2018/05/captura-de-tela-2015-08-18-as-094936.png) Movendo pasta de backup para outra unidade (Foto: Reprodução/Helito Bijora)[/caption]

**Passo 3.** Caso tenha apenas copiado a pasta, lembre-se de excluí-la da sua localização original. Se não conseguir, verifique se o iTunes está fechado;

[caption id="attachment_1736" align="alignnone" width="695"][![Exclua a pasta da localização original (Foto: Reprodução/Helito Bijora) ]({{ site.baseurl }}/assets/2018/05/captura-de-tela-2015-08-18-as-094945.png)]({{ site.baseurl }}/assets/2018/05/captura-de-tela-2015-08-18-as-094945.png) Exclua a pasta da localização original (Foto: Reprodução/Helito Bijora)[/caption]

**Passo 4.** Clique com o botão direito no canto inferior esquerdo da tela e, no menu que se abre, clique em “Prompt de Comando (Admin)”;

[caption id="attachment_1738" align="alignnone" width="695"][![Acessando prompt de comandos (Foto: Reprodução/Helito Bijora) ]({{ site.baseurl }}/assets/2018/05/captura-de-tela-2015-08-18-as-095324.png)]({{ site.baseurl }}/assets/2018/05/captura-de-tela-2015-08-18-as-095324.png) Acessando prompt de comandos (Foto: Reprodução/Helito Bijora)[/caption]

**Passo 5.** Entre com o comando abaixo para criar um link simbólico para a pasta movida na localização original da pasta de backup do iTunes. Troque “E:\Backup” pelo localização atual da pasta:

mklink /J “%APPDATA%\Apple Computer\MobileSync\Backup” “E:\Backup”

[caption id="attachment_1739" align="alignnone" width="695"][![Criando link simbólico para a pasta de backup (Foto: Reprodução/Helito Bijora) ]({{ site.baseurl }}/assets/2018/05/captura-de-tela-2015-08-18-as-095426.png)]({{ site.baseurl }}/assets/2018/05/captura-de-tela-2015-08-18-as-095426.png) Criando link simbólico para a pasta de backup (Foto: Reprodução/Helito Bijora)[/caption]

**Pronto.** Você poderá mover a pasta de backup do iTunes para outra partição para “desafogar” o disco C: do seu PC. Caso tenha movido para um HD externo, lembre-se de conectá-lo ao computador antes de realizar os backups.
