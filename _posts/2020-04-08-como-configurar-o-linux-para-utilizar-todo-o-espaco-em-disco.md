---
layout: post
title: Como configurar o linux para utilizar todo o espaço em disco?
date: 2020-04-08 17:26:53.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/como-configurar-o-linux-para-utilizar-todo-o-espaco-em-disco/"
---


Algumas distribuições baseadas no Debian como Ubuntu, Kali e etc... no processo de instalação quando utilizado LVM no processo de formatação o mesmo cria um LV (Logical Volume) com somente 4GB e deixando o restante do disco inutilizado. Neste post abordaremos os comandos necessários para expandir o volume bem como a partição ext4.

<!--more-->

Antes de iniciar o processo de correção vamos entender o comportamento e situação da maquina atual.

Em meu ambiente realizei a instalação de um Ubuntu 18.04.4 LTS, conforme visualizado abaixo.

```shell
root@M4v3r1ck:~# cat /etc/lsb-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.4 LTS"
```

A instalação foi no modo Next, Next, Finish, de forma que não realizei nenhuma personalização ou alteração durante o wizard de instalação.

Assim que finalizado a instalação posso verificar através do DF que o volume lógico não utiliza o tamanho total do meu disco.

```shell
root@M4v3r1ck:~# df -h
Filesystem                         Size  Used Avail Use% Mounted on
udev                               463M     0  463M   0% /dev
tmpfs                               99M  1.1M   98M   2% /run
/dev/mapper/ubuntu--vg-ubuntu--lv  3.9G  3.2G  478M  88% /
tmpfs                              493M     0  493M   0% /dev/shm
tmpfs                              5.0M     0  5.0M   0% /run/lock
tmpfs                              493M     0  493M   0% /sys/fs/cgroup
/dev/loop0                          90M   90M     0 100% /snap/core/8268
/dev/sda2                          976M   77M  832M   9% /boot
tmpfs                               99M     0   99M   0% /run/user/0
```

Bem como podemos visualizar/confirmar a mesma condição com o pvdisplay, gvdisplay e lvdisplay

```shell
root@M4v3r1ck:~# pvdisplay
  --- Physical volume ---
  PV Name               /dev/sda3
  VG Name               ubuntu-vg
  PV Size               <19.00 GiB / not usable 0
  Allocatable           yes
  PE Size               4.00 MiB
  Total PE              4863
  Free PE               3839
  Allocated PE          1024
  PV UUID               mXnKPZ-kYUU-6nVL-bys8-1OhC-Sd2Q-CshTCg

root@M4v3r1ck:~# vgdisplay ubuntu-vg
  --- Volume group ---
  VG Name               ubuntu-vg
  System ID
  Format                lvm2
  Metadata Areas        1
  Metadata Sequence No  2
  VG Access             read/write
  VG Status             resizable
  MAX LV                0
  Cur LV                1
  Open LV               1
  Max PV                0
  Cur PV                1
  Act PV                1
  VG Size               <19.00 GiB
  PE Size               4.00 MiB
  Total PE              4863
  Alloc PE / Size       1024 / 4.00 GiB
  Free  PE / Size       3839 / <15.00 GiB
  VG UUID               VQvN5o-ErRP-BrzE-htzN-cD5o-ig2Y-vLJG79

root@M4v3r1ck:~# lvdisplay
  --- Logical volume ---
  LV Path                /dev/ubuntu-vg/ubuntu-lv
  LV Name                ubuntu-lv
  VG Name                ubuntu-vg
  LV UUID                qGLYII-fSE1-dMb4-Y8MF-5D0L-j3p2-WXXywh
  LV Write Access        read/write
  LV Creation host, time ubuntu-server, 2020-04-08 19:49:53 +0000
  LV Status              available
  # open                 1
  LV Size                4.

00 GiB
  Current LE             1024
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  - currently set to     256
  Block device           253:0
```

Agora podemos realizar a extensão, ou seja, aumentar o tamanho do volume lógico para que o mesmo utilize 100% do disco com o comando abaixo:

```shell
root@M4v3r1ck:~# lvextend -l+100%FREE /dev/ubuntu-vg/ubuntu-lv
  Size of logical volume ubuntu-vg/ubuntu-lv changed from 4.00 GiB (1024 extents) to <19.00 GiB (4863 extents).
  Logical volume ubuntu-vg/ubuntu-lv successfully resized.
```

E posteriormente redimensionar a nossa partição ext4 para utilizar 100% do novo espaço disponível no volume

```shell
root@M4v3r1ck:~# resize2fs /dev/ubuntu-vg/ubuntu-lv
resize2fs 1.44.1 (24-Mar-2018)
Filesystem at /dev/ubuntu-vg/ubuntu-lv is mounted on /; on-line resizing required
old_desc_blocks = 1, new_desc_blocks = 3
The filesystem on /dev/ubuntu-vg/ubuntu-lv is now 4979712 (4k) blocks long.
```

E confirmar que todas as alterações surtiram com sucesso.

```shell
root@M4v3r1ck:~# df -h
Filesystem                         Size  Used Avail Use% Mounted on
udev                               463M     0  463M   0% /dev
tmpfs                               99M  1.1M   98M   2% /run
/dev/mapper/ubuntu--vg-ubuntu--lv   19G  3.2G   15G  18% /
tmpfs                              493M     0  493M   0% /dev/shm
tmpfs                              5.0M     0  5.0M   0% /run/lock
tmpfs                              493M     0  493M   0% /sys/fs/cgroup
/dev/loop0                          90M   90M     0 100% /snap/core/8268
/dev/sda2                          976M   77M  832M   9% /boot
tmpfs                               99M     0   99M   0% /run/user/0
```
