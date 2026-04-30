---
layout: post
title: Instalando placa X100P no Asterisk
date: 2015-03-30 20:48:01.000000000 -03:00
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
permalink: "/voip/installing-x100p-asterisk/"
---

## Introdução

Este post demonstra a minha primeira experiência na instalação de placas Intel X100P original (e X100P clone), esta é uma placa FXO (Foreign eXchange Office) para permitir realizar e receber ligações telefônicas através de linha telefônica analógica.

<!--more-->

## Hardware

Para conectar o seu PBX a uma linha telefônica analógica você necessita de uma placa FXO. O Asterisk é um aplicativo gratuito, porém as placas FXO geralmente são caras, porém existem alguns modelos de Fax Modem que são suportados pelo Asterisk, os modelos suportados necessitam ser dos seguintes chipsets:

- Intel 537PG and 537PU
- Ambient MD3200
- Motorola 62802

Caso, a sua placa seja uma de fax-mode, verifique se sua placa é compatível com o Asterisk usando o comando lspci, este comando deve retornar um valor similar ao abaixo

```bash
00:0a.0 Communication controller: Tiger Jet Network Inc. Tiger3XX Modem/ISDN interface
```

## Configurando X100P com DAHDI

Carregue o driver wcfxo que é responsável pelas placas X100P (e clones) e configure para que ao iniciar o linux o driver inicie automaticamente

```bash
modprobe wcfxo
sudo sh -c 'grep -q wcfxo /etc/modules || echo wcfxo >> /etc/modules'
```

Execute o comando abaixo para identificar as placas e gerar os arquivos de configuração **/etc/dahdi/system.conf** e **/etc/asterisk/dahdi-channels.conf**

```bash
dahdi_genconf -vvvv
```

Edite o arquivo **/etc/dahdi/system.conf** e altere o código de localidade conforme abaixo

```bash
loadzone = br
defaultzone = br
```

Execute o comando abaixo para verificar a configuração e canais disponíveis

```bash
dahdi_cfg -vvv
```

Este comando irá reproduzir um texto similar a **X channels to configure**, onde X indica o número de canais disponíveis. Se isso aconteceu, podemos continuar com o procesimento, caso contrário verifique se o hardware está OK e funcionando com os comandos **dahdi_scan**, **dahdi_hardware**, **dahdi_test**... enfim, algumas placas são sensíveis a mudanças de IRQ e podem não funcionar corretamente em alguns slots PCI

Edite o arquivo **/etc/asterisk/chan_dahdi.conf** com o conteúdo abaixo

```bash
[channels]
language=pt_BR
context=from-trunk
signalling=fxs_ks
faxdetect=incoming
usecallerid=yes
echocancel=yes
echocancelwhenbridged=no
echotraining=800
group=0
channel=1
```

Edite o arquivo **/etc/asterisk/modules.conf**

```bash
load => chan_dahdi.so
```

Reinicie o asterisk

### Exemplos no extension.conf

Segue abaixo alguns exemplos de utilização no extensions.conf

```bash
; Realizando ligação através do grupo 0
exten = _X.,1,Dial(DAHDI/g0/${EXTEN},20,r)

; Realisando ligação através do canal 1
exten = 0,1,Dial(DAHDI/1,20,r)

; Encaminhando qualquer chamada de entrada para o ramal SIP 2000
exten = s,1,Dial(SIP/2000,15,r)

; Exemplo de URA
exten = s,1,Answer(1) ; Atende a chamada de entrada
exten = s,n,Playback(boas-vindas) ; Toda o arquivo e audio boas-vindas.wav
exten = s,n,Hangup(1) ; Desliga a ligação
```

### Erros

Segue alguns erros encontrados no processo:

1 - Comando dahdi não é listado na console do Asterisk

Reinicie o módulo chan_dahdi.so com o comando module load chan_dahdi.so, reload chan_dahdi.so e dahdi restart

2 - Asterisk não realiza e nem recebe chamadas e no dmesg apresenta o erro wcfxo: Out of space to write register 05 with 0a

Este erro indica problema de irq, ou seja, a placa FXO não está recebendo interrupções de irq. O Hardware pode necessitar um irq próprio.
