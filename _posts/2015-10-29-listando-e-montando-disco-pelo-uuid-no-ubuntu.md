---
layout: post
title: Listando e montando disco pelo UUID no ubuntu
date: 2015-10-29 13:06:20.000000000 -02:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Linux
tags:
- disco
- disk
- fstab
- montar disco
- uuid
author: Helvio Junior (m4v3r1ck)
permalink: "/it/linux/listando-e-montando-disco-pelo-uuid-no-ubuntu/"
---

O UUID (Universally Unique Identifier) pode ser utilizado para identificar um disco como ponto de montagem. A estratégia de utilizar o UUID ao invés do nome do dispositivo é mais interessante pois caso você troque o disco de porta física, haveria muitos problemas de ponto de montagem incorreto.

Para listar todos os seus discos e seus respectivos UUIDs basta executar o comando abaixo

```bash
ls -l /dev/disk/by-uuid
lrwxrwxrwx 1 root root 10 Oct 29 11:21 1cadf475-fa59-4809-a3a0-667bc581f44c -> ../../sdb1
```

Para montar o seu disco usando o UUID basta alterar o seu fstab para utilizar o UUID ao invés do device conforme o exemplo abaixo:

```bash
#Modo antigo de montar
/dev/sdb1 /media/dados ext4 defaults 1 2

#Modo Novo
UUID=1cadf475-fa59-4809-a3a0-667bc581f44c /media/dados ext4 defaults 1 2
```
