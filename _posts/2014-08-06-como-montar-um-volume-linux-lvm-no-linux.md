---
layout: post
title: Como montar um volume Linux LVM no Linux
date: 2014-08-06 09:04:57.000000000 -03:00
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
permalink: "/it/como-montar-um-volume-linux-lvm-no-linux/"
---

Em muitos casos é necessário montar um volume LVM em um linux, como um HD externo, por exemplo. Segue o procedimento de identificação e montagem do volume LVM.

<!--more-->

Listando os discos e partições

```bash
fdisk -l
```

Este comando irá listar a tabela de partições do sistema.

```bash
Device Boot Start End Blocks Id System
/dev/sda1 * 1 4864 39070048+ 7 HPFS/NTFS
/dev/sda2 4865 6691 14675377+ 83 LVM2_member
```

Para trabalhar com volumes será necessário instalar os aplicativos com o comando abaixo:

```bash
sudo apt-get install lvm2
```

Após a instalação do aplicativo será necessário forçar o linux para listar e entender os volumes LVM utilizando os comandos abaixo:

```bash
vgscan
vgchange -a y
```

Agora podemos rodar o comando pvs.

```bash
pvs
```

Este irá listar os grupos de volume dos discos físicos.

```bash
PV VG Fmt Attr PSize PFree
/dev/hda2 VolGroup01 lvm2 a- 148.94G 32.00M
```

A segunda coluna (VG) exibe o nome do grupo de volume, utilizando este nome podemos obter maiores informações deste volume

```bash
lvdisplay /dev/VolGroup01
```

A saída deste comando será o nome do volume, pelo qual poderemos monta-lo no Linux

```bash
LV Name /dev/VolGroup01/LogVol00
```

Verifique qual volume deseja montar e execute o comando de montagem com este volume, conforme exemplo abaixo

```bash
mount /dev/VolGroup01/LogVol00   /mnt
```

Pronto! Agora basta acessar os arquivos montado em /mnt
