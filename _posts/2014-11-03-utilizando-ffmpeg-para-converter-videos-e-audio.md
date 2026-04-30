---
layout: post
title: Utilizando FFmpeg para converter vídeos e audio
date: 2014-11-03 07:46:39.000000000 -02:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Vídeo
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/video/utilizando-ffmpeg-para-converter-videos-e-audio/"
---

O FFmpeg é uma ferramenta que pode ser utilizada para diversas ações com vídeo e audio (encode, decode, transcode, crop e etc...). O FFmpeg é uma poderosa ferramenta por ser multi plataformas (windows, linux, mac), pequena leve e portátil.

Segue o link oficial da ferramenta: [https://www.ffmpeg.org](https://www.ffmpeg.org)

<!--more-->

Agora chega de bla, bla, bla... e vamos ao que interessa, os comandos de conversão.

Segue o link para a página oficial do FFmpeg para download: [https://www.ffmpeg.org/download.html](https://www.ffmpeg.org/download.html)

### Convertendo para MP4

```bash
ffmpeg -i source_file.mov -b:v 16M -vcodec h264 -pix_fmt yuv420p -acodec aac -strict -2 destination_file.mp4
```

Segue a explicação de cada parâmetro:

- **-i source_file.mov:** Arquivo de entrada, ou seja, o vídeo original. Este exemplo demostra a conversão de um arquivo MOV para MP4, mas pode ser utilizado qualquer arquivo suportado pelo FFmpeg como entrada que o comando funcionará. Ex.: (avi, mov, 3gp e wmv).
- **-b:v 16M:** Definição de um bitrate máximo de 16 Mbps para o vídeo
- **-vcodec h264:** Utilização do coded h264 para saída de vídeo, ou seja, para o vídeo de destino ja convertido
- **-acodec aac -strict -2:** Utilização do codec aac como saída de audio
- **destination_file.mp4:** Arquivo do vídeo convertido

### Convertendo para MP4 mantendo a qualidade

```bash
ffmpeg -i source_file.mov -vcodec h264 -crf 0 -pix_fmt yuv420p -acodec copy destination_file.mp4
```

Segue a explicação de cada parâmetro:

- **-i source_file.mov:** Arquivo de entrada, ou seja, o vídeo original. Este exemplo demostra a conversão de um arquivo MOV para MP4, mas pode ser utilizado qualquer arquivo suportado pelo FFmpeg como entrada que o comando funcionará. Ex.: (avi, mov, 3gp e wmv).
- **-vcodec h264:** Utilização do coded h264 para saída de vídeo, ou seja, para o vídeo de destino ja convertido
- **-crf 0:** Utilizado para manter a qualidade sem se importar com o tamanho do arquivo. Valor padrão é 23
- **-acodec copy:** Copia o áudio
- **destination_file.mp4:** Arquivo do vídeo convertido

### Convertendo para WMV

```bash
ffmpeg -i source_file.3gp -b:v 16M -vcodec msmpeg4 -acodec wmav2 destination_file.wmv
```

Segue a explicação de cada parâmetro:

- **-i source_file.3gp:** Arquivo de entrada, ou seja, o vídeo original. Este exemplo demostra a conversão de um arquivo 3GP para WMV, mas pode ser utilizado qualquer arquivo suportado pelo FFmpeg como entrada que o comando funcionará. Ex.: (avi, mov, mp4 e wmv).
- **-b:v 16M:** Definição de um bitrate máximo de 16 Mbps para o vídeo
- **-vcodec msmpeg4:** Utilização do codec msmpeg4 para saída de vídeo, ou seja, para o vídeo de destino ja convertido
- **-acodec wmav2:** Utilização do coded wmav2 como saída de audio
- **destination_file.wmv:** Arquivo do vídeo convertido

### Convertendo para MP3

```bash
ffmpeg -i source_file.avi -b:a 16M -acodec libmp3lame destination_file.mp3
```

Segue a explicação de cada parâmetro:

- **-i source_file.avi:** Arquivo de entrada, ou seja, o vídeo original. Este exemplo demostra a conversão de um arquivo AVI para MP3, mas pode ser utilizado qualquer arquivo suportado pelo FFmpeg como entrada que o comando funcionará. Ex.: (avi, mov, mp4 e wmv).
- **-b:a 16M:** Definição de um bitrate máximo de 16 Mbps para o audio
- **-acodec libmp3lame:** Utilização do codec libmp3lame como saída de audio
- **destination_file.mp3:** Arquivo de audio convertido

### Extração/corte de parte de audio/vídeo

```bash
ffmpeg -ss 210 -t 30 -i source_file.mov -b:v 16M -vcodec h264 -acodec aac -strict -2 destination_file.mp4
```

Neste exemplo utilizamos o mesmo comando do primeiro exemplo (convertendo para MP4) porém extraindo somente uma parte do vídeo, porém os 2 parâmetros utilizado para este corte (-ss e -t) podem ser utilizado para todos os outros exemplos.

Segue a explicação de cada parâmetro:

- **-ss 210:** Início da área de corte, ou seja, o ponto do vídeo original que será convertido. Neste caso no segundo 210.
- **-t 30:** O tamanho, em segundos, do novo vídeo a partir do ponto inicial definido no parâmetro anterior
- **-i source_file.mov:** Arquivo de entrada, ou seja, o vídeo original. Este exemplo demostra a conversão de um arquivo MOV para MP4, mas pode ser utilizado qualquer arquivo suportado pelo FFmpeg como entrada que o comando funcionará. Ex.: (avi, mov, 3gp e wmv).
- **-b:v 16M:** Definição de um bitrate máximo de 16 Mbps para o vídeo
- **-vcodec h264:** Utilização do coded h264 para saída de vídeo, ou seja, para o vídeo de destino ja convertido
- **-acodec aac -strict -2:** Utilização do codec aac como saída de audio
- **destination_file.mp4:** Arquivo do vídeo convertido

### Facilitando a vida em windows

Para usuários windows (como eu) fica maio chato ter que entrar no command, digitar tudo sempre que precisar converter, desta forma criei um bach **.cmd** que recebe como primeiro parâmetro o nome do arquivo a ser convertido, altera o nome do arquivo de saída conforme o script e realiza a conversão. Desta forma basta que eu arraste o arquivo a ser convertido para cima do arquivo CMD que ele faz o resto.

Como fazer isso? Vamos la...

Primeiro realize o download do FFmpeg no local de sua preferência. No meu ambiente coloquei em **C:\FFmpeg**.

Agora crie neste diretório um arquivo nomeado **converte_para_mp4.cmd** e adicione o seguinte conteúdo

```bash
@echo off
SET _file=%1
SET _newFile=%_file:avi=mp4%
SET _newFile=%_newFile:AVI=mp4%
SET _newFile=%_newFile:MOV=mp4%
SET _newFile=%_newFile:mov=mp4%
SET _newFile=%_newFile:3GP=mp4%
SET _newFile=%_newFile:3gp=mp4%
SET _newFile=%_newFile:WMV=mp4%
SET _newFile=%_newFile:wmv=mp4%

rem MOV to MP4
c:\FFmpeg\ffmpeg.exe -i %1 -b:v 16M -vcodec h264 -acodec aac -strict -2 %_newFile%
```

Agora para converter o seu vídeo basta arrastar o arquivo de vídeo para cima deste arquivo cmd conforme ilustrado na imagem abaixo

[![Convert]({{ site.baseurl }}/assets/2014/11/Convert.png)]({{ site.baseurl }}/assets/2014/11/Convert.png)
