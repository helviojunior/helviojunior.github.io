---
layout: post
title: Gerando varios hashes (MD5, SHA1 e SHA256) ao mesmo tempo
date: 2018-05-28 11:56:17.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Linux
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/linux/gerando-varios-hashes-md5-sha1-e-sha256-ao-mesmo-tempo/"
---

O objetivo deste post é mostrar um script, simples, em bash para gerar os hashes MD5, SHA1 e SHA256 de um arquivo qualquer.

Mas ai você pode se perguntar, porque eu quero isso se posso simplesmente rodar os comandos manualmente e obter os hashes, simples, pois com este comando vc tem tudo em um unico comando e com a identificação de qual foi o algorítmo e o seu hash.

Crie o script abaixo com o nome **/sbin/gethash**

```bash
#!/bin/bash
#

if [ "$(id -u)" != "0" ]; then
   echo "Sorry, you must run this script as root." 1>&2
   exit 1
fi

if [ $# -lt 1 ]
  then
    echo "Usage: $0 file_name"
    exit 1
fi

echo "Generating hash, please wait..."

md5=$(md5sum "$1" | awk '{ print $1 }')
echo "MD5($1)= $md5"

sha1=$(sha1sum "$1" | awk '{ print $1 }')
echo "SHA1($1)= $sha1"

sha256=$(sha256sum "$1" | awk '{ print $1 }')
echo "SHA256($1)= $sha256"
```

Defina a permissão de execução para este script

```bash
chmod +x /sbin/gethash
```

E seja feliz!!!

```bash
# gethash teste.txt
Generating hash, please wait...
MD5(teste.txt)= 7ded919cba92b59c28671227b1364297
SHA1(teste.txt)= 023749462808478515826213cb9eccf77c2823eb
SHA256(teste.txt)= c1b2ad9e5d95367f43ad67e5120cbdf868a3085d0a183b06af8101a2dc1bd258
```
