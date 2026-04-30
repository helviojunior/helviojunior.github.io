---
layout: post
title: Configurando 802.1q VLAN Tagging no linux
date: 2013-03-13 21:14:35.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/configurando-802-1q-vlan-tagging/"
---

1 - Verifique se o módulo está carregado no kernel

```csharp
lsmod | grep 8021q
```

2 - Se o módulo não tiver carregado, carregue com o seguinte comando:

```csharp
modprobe 8021q
```

3 - Configure a interface física em /etc/sysconfig/network-scripts/ifcfg-ethX, onde X é o número correspondente a interface específica, como abaixo:

```csharp
DEVICE=ethX
TYPE=Ethernet
BOOTPROTO=none
ONBOOT=yes
```

4 - Configure a interface VLAN em /etc/sysconfig/network-scripts. O arquivo de configuração precisa conter o nome da interface física mais o caracter . (ponto) mais o ID da VLAN. Por exemplo, se o ID da VLAN é 192, e a interface física é eth0, então o arquivo de configuração terá como nome ifcfg-eth0.192:

```csharp
DEVICE=ethX.192
BOOTPROTO=static
ONBOOT=yes
IPADDR=192.168.1.1
NETMASK=255.255.255.0
USERCTL=no
NETWORK=192.168.1.0
VLAN=yes
```

5 - Se houver a necessidade de configurar uma segunda VLAN, como por exemplo, VLAN ID 193, na mesma interface, adicione um novo arquivo com o nome ifcfg-eth0.193 seguindo o mesmo modelo apresentado.

6 - Reinicie as interfaces de rede para que i linux carregue as informações, com o seguinte comando:

```csharp
service network restart
```
