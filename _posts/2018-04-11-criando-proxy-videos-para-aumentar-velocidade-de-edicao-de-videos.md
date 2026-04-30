---
layout: post
title: Criando proxy vídeos para aumentar a velocidade de edição de vídeos
date: 2018-04-11 13:43:38.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Vídeo
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/video/criando-proxy-videos-para-aumentar-velocidade-de-edicao-de-videos/"
---

Como alguns sabem pratico Airsoft como esporte e tenho um canal no youtube ([HelvioSniper](https://www.youtube.com/channel/UCS8J70C-fNTuD2gMLc26drA)) com os meus vídeos, dicas, tutoriais e etc...

Na busca por aperfeiçoamento fui buscar uma técnica para edição mais rápida uma vez que a cada jogo de duração média de 2 a 3 horas eu demoro +- 12 horas entre edição e renderização dos meus vídeos.

Nessa busca encontrei este vídeo abaixo:

Onde ele explica como realizar uma técnica que basicamente consiste em gerar uma versão em baixa qualidade (e pequeno tamanho de arquivo) para realizar a edição de forma fluida, e depois no momento da renderização colocar o software de edição a utilizar os arquivos originais com alta qualidade.

No vídeo ele explica este processo usando o aplicativo HandBrake, muito bom por sinal.

Mas como eu tenho um PC com uma placa de vídeo legal rodando em Linux, fui procurar alguma solução para aproveitar este PC durante este meu processo, então encontrei uma solução utilizando o ffmpeg.

PS: Apenas como observação, apesar de eu comentar que vou usar meu PC linux, o ffmpeg também pode ser usado no windows, conforme demonstro neste artigo ([http://www.helviojunior.com.br/video/utilizando-ffmpeg-para-converter-videos-e-audio/](http://www.helviojunior.com.br/video/utilizando-ffmpeg-para-converter-videos-e-audio/)).

<!--more-->

Chega de bla, bla, bla e vamos ao comando.

```bash
ffmpeg -i input.mp4 -r 25 -c:v libx264 -pix_fmt yuv420p -profile:v main -level 2.1 -preset veryfast -tune fastdecode -crf 26 -x264opts keyint=75 -c:a aac -b:a 96k -y -threads 8 -strict -2 output.mp4
```

Com este comando o meu vídeo foi de 3,6 GB para 360 Mb, o que facilita bastante o software de edição de carregar o arquivo e deixar a edição bem mais fluida.

Segue abaixo um script .cmd para automatizar o processo de criação de um sub diretório e conversão

```text
@echo off
SET _file=%~nx1
SET _dir=%~dp$PATH:1
SET _newFile=%_file:avi=mp4%
SET _newFile=%_newFile:AVI=mp4%
SET _newFile=%_newFile:MKV=mp4%
SET _newFile=%_newFile:mkv=mp4%
SET _newFile=%_newFile:MOV=mp4%
SET _newFile=%_newFile:mov=mp4%
SET _newFile=%_newFile:3GP=mp4%
SET _newFile=%_newFile:3gp=mp4%
SET _newFile=%_newFile:WMV=mp4%
SET _newFile=%_newFile:wmv=mp4%
SET _newFile=%_newFile:swf=mp4%
SET _newFile=%_newFile:SWF=mp4%
SET _newFile=%_newFile:vob=mp4%
SET _newFile=%_newFile:VOB=mp4%
SET _newFile=%_newFile:rf=mp4%

SET _newDir=%_dir%\proxy
SET _proxyFile=%_newDir%\%_newFile%

echo "Creating directory %_newDir"
mkdir "%_newDir%" 2> nul

echo "Converting file to %_proxyFile%"

rem Convert using CPU
rem ffmpeg -i "%1" -r 25 -c:v libx264 -pix_fmt yuv420p -profile:v main -level 2.1 -preset veryfast -tune fastdecode -crf 26 -x264opts keyint=75 -c:a aac -b:a 96k -y -threads 8 -strict -2 "%_proxyFile%"

rem Convert using NVIDIA driver (GPU)
ffmpeg.exe -hwaccel_output_format cuda -i "%1" -c:v h264_nvenc  -b:v 500K -r 25 -pix_fmt yuv420p -preset fast -tune fastdecode -crf 26 -x264opts keyint=75 -c:a aac -b:a 96k  -y -threads 8 -strict -2 "%_proxyFile%"

if %ERRORLEVEL% NEQ 0 pause
```

Até o próximo tutorial, valew!
