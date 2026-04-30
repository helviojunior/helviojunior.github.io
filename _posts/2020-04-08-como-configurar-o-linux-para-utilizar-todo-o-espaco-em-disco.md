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

Verificando com o `dmesg` podemos ver que nosso disco físico tem 60 Gb mas o `df -h` mostra que não estamos usando todo este espaço.

```shell
root@M4v3r1ck:~# dmesg | grep sda
[    2.571080] sd 32:0:0:0: [sda] 125829120 512-byte logical blocks: (64.4 GB/60.0 GiB)
[    2.571538] sd 32:0:0:0: [sda] Write Protect is off
[    2.571684] sd 32:0:0:0: [sda] Mode Sense: 61 00 00 00
[    2.571827] sd 32:0:0:0: [sda] Cache data unavailable
[    2.571940] sd 32:0:0:0: [sda] Assuming drive cache: write through
[    2.576091]  sda: sda1 sda2 sda3
[    2.576790] sd 32:0:0:0: [sda] Attached SCSI disk
[    4.770027] EXT4-fs (sda2): mounted filesystem 83aefc1a-e764-4f64-bc5f-dbd72ba8b23f r/w with ordered data mode. Quota mode: none.
```

```shell
root@M4v3r1ck:~# df -h
Filesystem                         Size  Used Avail Use% Mounted on
tmpfs                              1.2G  1.6M  1.2G   1% /run
efivarfs                           256K   40K  212K  16% /sys/firmware/efi/efivars
/dev/mapper/ubuntu--vg-ubuntu--lv  9.8G  2.9G  6.5G  31% /
tmpfs                              5.8G     0  5.8G   0% /dev/shm
tmpfs                              5.0M     0  5.0M   0% /run/lock
/dev/sda2                          1.7G  103M  1.5G   7% /boot
/dev/sda1                          952M  6.2M  945M   1% /boot/efi
tmpfs                              1.2G   12K  1.2G   1% /run/user/0
```

Bem como podemos visualizar/confirmar a mesma condição com o pvdisplay, gvdisplay e lvdisplay

```shell
root@M4v3r1ck:~# pvdisplay
  --- Physical volume ---
  PV Name               /dev/sda3
  VG Name               ubuntu-vg
  PV Size               <17.32 GiB / not usable 0
  Allocatable           yes
  PE Size               4.00 MiB
  Total PE              4433
  Free PE               1873
  Allocated PE          2560
  PV UUID               p5p22Q-WDiT-05Fv-0aD5-z2Dj-2WPw-YvImZa

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
  VG Size               <17.32 GiB
  PE Size               4.00 MiB
  Total PE              4433
  Alloc PE / Size       2560 / 10.00 GiB
  Free  PE / Size       1873 / <7.32 GiB
  VG UUID               GJdcHm-RO68-Hpbd-0anv-UF4L-8Cdq-LGAJZQ


root@M4v3r1ck:~# lvdisplay
  --- Logical volume ---
  LV Path                /dev/ubuntu-vg/ubuntu-lv
  LV Name                ubuntu-lv
  VG Name                ubuntu-vg
  LV UUID                NCcXFf-F92s-5rM3-i6vS-8ll4-VTkf-raXKSH
  LV Write Access        read/write
  LV Creation host, time ubuntu-server, 2025-11-06 19:50:01 -0300
  LV Status              available
  # open                 1
  LV Size                10.00 GiB
  Current LE             2560
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  - currently set to     256
  Block device           252:0

```


Em nosso cenário a partição `/dev/sda3` não está utilizando todo o espaço livre do disco

```shell
root@image-base:~# lsblk | grep "NAME\|sda\|ubuntu"
NAME                      MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS
sda                         8:0    0   60G  0 disk
├─sda1                      8:1    0  953M  0 part /boot/efi
├─sda2                      8:2    0  1.8G  0 part /boot
└─sda3                      8:3    0 17.3G  0 part
  └─ubuntu--vg-ubuntu--lv 252:0    0   10G  0 lvm  /
```

Desta forma teremos que primeiramente expandir essa partição.

> Este procedimento pode destruir todos os dados do servidor, então tenha um backup antes de executar esta operação.
{: .prompt-warning }

```shell
root@image-base:~# growpart /dev/sda 3
CHANGED: partition=3 start=5623808 old: size=36317184 end=41940991 new: size=120205279 end=125829086
```

Se olharmos novamente o o pvdisplay, gvdisplay e lvdisplay, podemos observar que a partição `/dev/sda3` e Volume Group `ubuntu-vg` estão com o novo tamanho, mas o Logical volume não.

```shell
root@M4v3r1ck:~# pvdisplay
  --- Physical volume ---
  PV Name               /dev/sda3
  VG Name               ubuntu-vg
  PV Size               <57.32 GiB / not usable 16.50 KiB
  Allocatable           yes
  PE Size               4.00 MiB
  Total PE              14673
  Free PE               12113
  Allocated PE          2560
  PV UUID               p5p22Q-WDiT-05Fv-0aD5-z2Dj-2WPw-YvImZa

root@M4v3r1ck:~# vgdisplay ubuntu-vg
  --- Volume group ---
  VG Name               ubuntu-vg
  System ID
  Format                lvm2
  Metadata Areas        1
  Metadata Sequence No  3
  VG Access             read/write
  VG Status             resizable
  MAX LV                0
  Cur LV                1
  Open LV               1
  Max PV                0
  Cur PV                1
  Act PV                1
  VG Size               <57.32 GiB
  PE Size               4.00 MiB
  Total PE              14673
  Alloc PE / Size       2560 / 10.00 GiB
  Free  PE / Size       12113 / <47.32 GiB
  VG UUID               GJdcHm-RO68-Hpbd-0anv-UF4L-8Cdq-LGAJZQ

root@M4v3r1ck:~# lvdisplay
  --- Logical volume ---
  LV Path                /dev/ubuntu-vg/ubuntu-lv
  LV Name                ubuntu-lv
  VG Name                ubuntu-vg
  LV UUID                NCcXFf-F92s-5rM3-i6vS-8ll4-VTkf-raXKSH
  LV Write Access        read/write
  LV Creation host, time ubuntu-server, 2025-11-06 19:50:01 -0300
  LV Status              available
  # open                 1
  LV Size                10.00 GiB
  Current LE             2560
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  - currently set to     256
  Block device           252:0

```


Agora podemos realizar a extensão do `Logical volume`, ou seja, aumentar o tamanho do volume lógico para que o mesmo utilize 100% do disco com o comando abaixo:

```shell
root@M4v3r1ck:~# lvextend -l+100%FREE /dev/ubuntu-vg/ubuntu-lv
  Size of logical volume ubuntu-vg/ubuntu-lv changed from 10.00 GiB (2560 extents) to <57.32 GiB (14673 extents).
  Logical volume ubuntu-vg/ubuntu-lv successfully resized.
```

E posteriormente redimensionar a nossa partição ext4 para utilizar 100% do novo espaço disponível no volume

```shell
root@M4v3r1ck:~# resize2fs /dev/ubuntu-vg/ubuntu-lv
resize2fs 1.47.0 (5-Feb-2023)
Filesystem at /dev/ubuntu-vg/ubuntu-lv is mounted on /; on-line resizing required
old_desc_blocks = 2, new_desc_blocks = 8
The filesystem on /dev/ubuntu-vg/ubuntu-lv is now 15025152 (4k) blocks long.
```

E confirmar que todas as alterações surtiram com sucesso.

```shell
root@M4v3r1ck:~# lsblk | grep "NAME\|sda\|ubuntu"
NAME                      MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS
sda                         8:0    0   60G  0 disk
├─sda1                      8:1    0  953M  0 part /boot/efi
├─sda2                      8:2    0  1.8G  0 part /boot
└─sda3                      8:3    0 57.3G  0 part
  └─ubuntu--vg-ubuntu--lv 252:0    0 57.3G  0 lvm  /

root@M4v3r1ck:~# df -h
Filesystem                         Size  Used Avail Use% Mounted on
tmpfs                              1.2G  1.6M  1.2G   1% /run
efivarfs                           256K   40K  212K  16% /sys/firmware/efi/efivars
/dev/mapper/ubuntu--vg-ubuntu--lv   57G  2.9G   52G   6% /
tmpfs                              5.8G     0  5.8G   0% /dev/shm
tmpfs                              5.0M     0  5.0M   0% /run/lock
/dev/sda2                          1.7G  103M  1.5G   7% /boot
/dev/sda1                          952M  6.2M  945M   1% /boot/efi
tmpfs                              1.2G   12K  1.2G   1% /run/user/0
```
