---
layout: post
title: Filtrando logs de uma chamada no Asterisk
date: 2017-09-26 16:18:03.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Asterisk
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/voip/asterisk/filtrando-logs-de-uma-chamada-no-asterisk/"
---

Uma das coisas mais interessantes do Asterisk é a capacidade de você tratar e identificar erros olhando somente o arquivo de log do mesmo.

Porém por ser bem detalhado e completo, dependendo da quantidade de chamadas simultâneas que há em seu ambiente é uma tarefa quase impossível ler este arquivo de log de uma forma que você possa isolar as informações de uma única ligação.

Buscando na internet encontrei um post bem interessante que mostra um comando linux para realizar essa atividade ([http://hackrr.com/2013/asterisk/get-all-logs-of-a-number-that-was-dialed/](http://hackrr.com/2013/asterisk/get-all-logs-of-a-number-that-was-dialed/)), desta forma o meu intuito aqui é apenas incrementar este script para pegar dinamicamente o local  e nome do arquivo de log do asterisk e depois filtrar os logs necessários.

Segue abaixo o script completo. Basta salva-lo no local de sua preferência Ex.: **/root/busca.sh**

```bash
#/bin/bash
#

LOGPATH=$(cat /etc/asterisk/asterisk.conf | grep -v "^\s*[#\;]\|^\s*$" | grep --only-matching -i --perl-regex "(\bastlogdir\b).*" | cut -d'=' -f 2 | sed 's/>//g')
FILE=$(cat /etc/asterisk/logger.conf | grep -v "^\s*[#\;]\|^\s*$" | grep --only-matching -i --perl-regex "(\bfull\b).*" | cut -d'=' -f 1)
LOGFILE="$LOGPATH/$FILE"

grep $1 $LOGFILE | grep -o "C-[0-9a-f]\+" | uniq | xargs -I{} grep "\[{}\]" $LOGFILE
```

Agora depois de salvo basta executa-lo passando como parâmetro qualquer informação que você ache que possa localizar a chamada, lógico que quanto mais específico melhor. Ex.: Canal, contexto, peer e etc..

```bash
/root/busca.sh 'SIP/6619-00001121'
```
