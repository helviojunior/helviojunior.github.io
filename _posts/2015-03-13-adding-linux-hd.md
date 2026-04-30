---
layout: post
title: Adicionando HD em um linux sem reboot
date: 2015-03-13 14:44:08.000000000 -03:00
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
permalink: "/it/adding-linux-hd/"
---

Quando é utilizado um ambiente virtual (VMWare) é possível adicionar novos discos sem a necessidade de reiniciar o servidor. Porém o linux não identifica automaticamente este novos disco em /dev/sdX, desta forma este procedimento visa mostrar como realizar a releitura deste disco.

Digite o comando abaixo para listar os discos:

```bash
ls -ltr /sys/class/scsi_host
```

Execute o comando (trocando hostX por um dos hosts listados co comando anterior) abaixo para scanear o disco e mapear as unidades /dev/sdX:

```bash
echo "- - -" > /sys/class/scsi_host/hostX/scan
```

Opcionalmente você pode executar o comando abaixo que realiza esse passo-a-passo acima de forma automática

```bash
for h in `ls /sys/class/scsi_host/` ; do echo "- - -" > /sys/class/scsi_host/$h/scan; done
```
