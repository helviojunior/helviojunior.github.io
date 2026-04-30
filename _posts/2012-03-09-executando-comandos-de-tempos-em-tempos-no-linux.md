---
layout: post
title: Executando comandos de tempos em tempos no linux
date: 2012-03-09 16:35:15.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
- Linux
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/executando-comandos-de-tempos-em-tempos-no-linux/"
---

O objetivo deste comando é executar (na console) um comando de tempos em tempos. Não pretende aqui substituir o cron do linux.

```bash
while :; do ps; sleep 10; done
```

Em nosso exemplo o comando executa o "ps" e depois um sleep de 10 segundos, ou seja, o comando ps é executado a cada 10 segundos.
