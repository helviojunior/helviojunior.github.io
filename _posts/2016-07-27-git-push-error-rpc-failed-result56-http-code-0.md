---
layout: post
title: 'git push error: RPC failed; result=56, HTTP code = 0'
date: 2016-07-27 11:49:03.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Desenvolvimento
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/devel/git-push-error-rpc-failed-result56-http-code-0/"
---

Ao tentar migrar um repositório do GitHub para um servidor local usando Bonobo Git Server ([https://bonobogitserver.com/](https://bonobogitserver.com/)), tive o seguinte erro:

```bash
Counting objects: 5682, done.
Delta compression using up to 4 threads.
Compressing objects: 100% (3751/3751), done.
error: unable to rewind rpc post data - try increasing http.postBuffer
error: RPC failed; result=56, HTTP code = 0
Writing objects:  10% (619/5682), fatal: The remote end4.75 M huniB | 3g u6p unexpecte.00 Kdly
Writing objects: 100% (5682/5682), 34.68 MiB | 22.00 KiB/s, done.
Total 5682 (delta 1827), reused 5682 (delta 1827)
fatal: The remote end hung up unexpectedly
```

Pesquisando na internet verifiquei que este erro está associado ao tamanho do pacote que necessita ser enviado pelo cliente ao servidor, sendo assim a solução do mesmo é ajustar o cliente e o servidor para receber pacotes maiores.

No cliente fiz o ajuste com o seguinte comando

```bash
git config --global http.postBuffer 100M
```

Ja no servidor alterei o arquivo web.config do Bonobo para permitir o conteúdo com 100Mb (conforme abaixo)

```bash
<?xml version="1.0" encoding="utf-8"?>
<configuration>
...
  <system.web>
    <httpRuntime maxRequestLength="104857600" />
    ...
  <system.webServer>
    <security>
      <requestFiltering>
        <requestLimits executionTimeout="18000" maxAllowedContentLength="104857600" />
        ...
```

Após este procedimento e a aplicação do HotFix Microsoft ([KB2634328](http://support.microsoft.com/kb/2634328/en-us)) tudo funcionou normalmente em meu ambiente.

Referência:

[https://bonobogitserver.com/frequently-asked-questions/](https://bonobogitserver.com/frequently-asked-questions/)
