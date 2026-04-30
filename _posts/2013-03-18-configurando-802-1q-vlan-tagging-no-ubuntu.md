---
layout: post
title: Configurando 802.1q VLAN Tagging no ubuntu até 14.04
date: 2013-03-18 13:20:40.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/configurando-802-1q-vlan-tagging-no-ubuntu/"
---

1 - Realize a instalação do módulo

```bash
sudo apt-get install vlan
```

2 - Verifique se o módulo está carregado no kernel

```bash
lsmod | grep 8021q
```

3 - Se o módulo não tiver carregado, carregue com o seguinte comando:

```bash
modprobe 8021q
```

4 - Configure o módulo para iniciar automaticamente após o reboot

```bash
sudo sh -c 'grep -q 8021q /etc/modules || echo 8021q >> /etc/modules'
```

5 - Configure as interfaces editando o arquivo /etc/network/interfaces, onde X é o número correspondente a interface específica. O nome do device precisa conter o nome da interface física mais o caracter . (ponto) mais o ID da VLAN. Por exemplo, se o ID da VLAN é 192, e a interface física é eth0, então o nome do device será eth0.192:

```bash
auto eth0.192
iface eth0.192 inet static
address 192.168.1.1
netmask 255.255.255.0
```

6 - Se houver a necessidade de configurar uma segunda VLAN, como por exemplo, VLAN ID 193, na mesma interface, adicione um novo trecho no arquivo /etc/network/interfaces com o device eth0.193 seguindo o mesmo modelo apresentado.

7 - Reinicie as interfaces de rede para que o linux carregue as informações, com o seguinte comando:

```bash
/etc/init.d/networking restart
```
