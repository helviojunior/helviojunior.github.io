---
layout: post
title: OpenWRT rootfs em um pendrive (extroot)
date: 2013-05-14 15:28:28.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Zabbix
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/monitoramento/zabbix/openwrt-rootfs-em-um-pendrive-extroot/"
---

O objetivo deste post é demonstrar como utilizar um armazenamento externo, como pendrive, para complementar o espaço em disco no OpenWRT. A motivação para este procedimento foi a necessidade de superar a pouca memória flash contida na maioria dos dispositivos, o meu por exemplo contém somente 4Mb, desta forma depois da instalação super enxuta do OpenWRT sobram mais ou menos 1.2 Mb para os aplicativos.

<!--more-->

A versão utilizada neste artigo é a OpenWrt Backfire 10.03+.

**Pré-requisitos**

Instale os pacotes abaixo:

```bash
opkg update
opkg install block-extroot block-hotplug block-mount
opkg install kmod-usb-core kmod-usb2 kmod-usb-storage kmod-usb-ohci
opkg install kmod-fs-ext3
opkg install e2fsprogs
```

**Instalando o pendrive**

Insira o pendrive no seu dispositivo e realize o reboot, após o reboot formate o seu pendrive com o comando

```bash
mkfs.ext3 /dev/sda1
```

Edite o arquivo **/etc/config/fstab** conforme o exemplo abaixo

```bash
config mount
option device /dev/sda1
option fstype ext3
option options rw,sync
option enabled 1
option enabled_fsck 0
option is_rootfs 1
```

Pronto, basta reiniciar seu dispositivo e o /overlay ja estará montado no pendrive.

Para se certificar disso basta executar o comando df -h

Referência original: [http://wiki.openwrt.org/doc/howto/ex troot](http://wiki.openwrt.org/doc/howto/extroot)
