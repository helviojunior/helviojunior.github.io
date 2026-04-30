---
layout: post
title: Text to speech para asterisk usando Google Translate
date: 2015-08-21 16:39:28.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Asterisk
- VoIP
tags:
- agi
- asterisk
- elastix
- googletts
- tts
author: Helvio Junior (m4v3r1ck)
permalink: "/voip/text-to-speech-for-asterisk-using-google-translate-2/"
---

Este script AGI foi desenvolvido para que você possa dar a capacidade do seu Asterisk falar com o seu usuário/cliente.

Este script utiliza a plataforma do Google Translate para reinderizar (converter) um texto para audio, e posteriormente tocar este audio no Asterisk. Como este script utiliza a plataforma do Google Translate, você pode realizar este processo em diversas linguagens, para maiores informações verifique a documentação do Google.

<!--more-->

## Dependências

- PHP5: PHP 5 para processamento dos scripts
- cURL: Biblioteca de acesso web
- Perc: Biblioteca para acesso web através do PHP
- sox : Sound eXchange, aplicativo para conversão/processamento de audio
- mpg123 : MPEG Audio Player and decoder, aplicativo para conversão de MP3
- Acesso a internet para conectar a plataforma do Google e efetuar o download do audio

## Instalando as dependências

```bash
apt-get install -y php-http php5-dev libcurl3 libpcre3-dev libcurl4-openssl-dev mpg123 sox
pecl install pecl_http-1.7.6
```

Edite o arquivo **/etc/php5/cli/php.ini** adicionando a linha abaixo

```bash
extension=http.so
```

## Instalando o script AGI

Antes de instalar o script AGI verifique o diretório agi-bin do seu Asterisk, geralmente o padrão é **/var/lib/asterisk/agi-bin/**, essa informação pode ser encontrada em **/etc/asterisk/asterisk.conf**. Considerando que este é o diretório padrão execute os comandos abaixo:

```bash
wget {{ site.baseurl }}/assets/2015/08/googletts.tgz
tar -xzvf googletts.tgz -C /var/lib/asterisk/agi-bin/
chmod 777 /var/lib/asterisk/agi-bin/googletts.php
```

## Utilização

**agi(googletts.php,texto,[linguagem]):** Este comando irá executar o script googletts.php que utilizar-a o Google Translate para converter texto para áudio e tocar esse áudio para o cliente. O Parâmetro linguagem é opcional, caso não definido o script utilizará a linguagem deste canal no Asterisk.

Exemplos de utilização no plano de discagem (dialplan) do Asterisk:

```bash
exten => 1234,1,Answer()
  ;;Toca a mensagem usando a linguagem padrão deste canal:
exten => 1234,n,agi(googletts.php,"Este é um exemplo simples.")
  ;;Toca a mensagem em Portugês:
exten => 1234,n,agi(googletts.php,"Este é um exemplo simples usando Google TTS em português.",pt-BR)
  ;;Toca a mensagem em inglês:
exten => 1234,n,agi(googletts.php,"This is a simple google text to speech test in english.",en)
```
