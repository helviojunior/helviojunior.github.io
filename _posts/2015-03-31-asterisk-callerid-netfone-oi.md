---
layout: post
title: Asterisk - CallerID
date: 2015-03-31 14:46:54.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Asterisk
- VoIP
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/voip/asterisk-callerid-netfone-oi/"
---

Este post tem por objetivo demonstrar como realizar a identificação de chamadas através do Asterisk usando uma placa analógica FXO.

A maioria das operadoras no Brasil utiliza sinalização Padrão do Asterisk, porem a Net, VIVO e a OI utilizam outro tipo de sinalização. A boa notícia é que podemos realizar essa identificação sem a necessidade de conversor DTMF para FXS como muitos fóruns sugerem.

<!--more-->

## Ambiente

- Asterisk 1.8.26;
- DAHDI 2.9.2;
- Placa FXO X100P;
- NetFone Arris TG862

## Troubleshooting

No Asterisk o módulo responsável pela identificação do CALLERID é o chan_dahdi e normalmente o seu arquivo de configuração está localizado em /etc/asterisk/chan_dahdi.conf e detém 3 variáveis que controlam o funcionamento dessa identificação:

- **usecallerid**: Define se o Asterisk deve ou não o caller ID, "yes" ou "no" são as unicas opções disponíveis
- **cidsignalling**: Determina o tipo de sinalização usada para o caller ID. As sinalizações suportadas pelo Asterisk são: bell: bell202 usada nos Estados Unidos (padrão do Asterisk) v23: v23 usada no Reino Unido v23_jp: v23 usado no Japão dtmf: DTMF usado por Dinamarca, Suécia, Holanda e por algumas operadoras aqui no Brasil (NET, VIVO e OI)
- **cidstart**: Determina o sinal de início do caller ID. As opções suportadas pelo Asterisk São: ring: O início é ao início sinal ring (padrão do Asterisk) polarity: A inversão de polaridade sinaliza o início polarity_IN: A inversão de polaridade sinaliza o início, a detecção de tom de discagem DTMF na Índia dtmf: O caller ID é recebido através de tons dtml que ocorrem antes do sinal ring.

Se o **cidstart** for configurado como dtmf, o nível do sinal da linha precisa ser ajustado para a correta identificação dos tons DTMF. Este ajuste ocorre através do parâmetro **dtmfcidlevel**. O padrão deste padâmetro é 256, porém pode ser ajustado conforme sua necessidade, quanto maior o valor menor será a detecção de falsos tons DTMF.

Segue abaixo um exemplo dessa configuração no arquivo **/etc/asterisk/chan_dahdi.conf**.

```bash
[channels]
...
usecallerid=yes
cidsignalling=bell
cidstart=ring
...
```

*Nota: "..." indica outras configurações não relacionadas a identificação do caller ID.*

## Identificando o caller ID em NetFone, VIVO e OI

Segue abaixo o trecho de parâmetros do arquivo o **/etc/asterisk/chan_dahdi.conf** para que ocorra a identificação correta do caller ID

```bash
[channels]
...
usecallerid=yes
cidsignalling=dtmf
cidstart=dtmf
dtmfcidlevel=7640
...
```

## Exemplo de configuração, e log na console do Asterisk

Segue abaixo um trecho do arquivo extensions.conf

```bash
exten = s,1,NoOP(Chamada entrando ${CALLERID(num)})
exten = s,n,Dial(SIP/2000,15,r)
```

Saída em tela ao entrar a ligação. Nível verbose do asterisk definido como 4.

```bash
 == Starting DTMF CID detection on channel 1
 -- Starting simple switch on 'DAHDI/1-1'
 -- Executing [s@default:1] NoOp("DAHDI/1-1", "Chamada entrando 04198xxxxxx") in new stack
 -- Executing [s@default:2] Dial("DAHDI/1-1", "SIP/2000,15,r") in new stack
```

## Fonte para Troubleshooting

[http://kb.digium.com/articles/Configuration/Troubleshooting-missing-caller-ID-on-Analog-calls](http://kb.digium.com/articles/Configuration/Troubleshooting-missing-caller-ID-on-Analog-calls)
