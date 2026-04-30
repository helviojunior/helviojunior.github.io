---
layout: post
title: Configurando 802.1q VLAN Tagging no ubuntu 16.04
date: 2017-11-17 09:27:50.000000000 -02:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories: []
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/uncategorized/configurando-802-1q-vlan-tagging-no-ubuntu-16-04/"
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
sudo sh -c 'grep -q 8021q /etc/modules-load.d/modules.conf || echo 8021q >> /etc/modules-load.d/modules.conf'
```

5 - Configure as interfaces editando o arquivo /etc/network/interfaces, onde o nome da interface será o nome da VLAN, e haverá um parâmetro vlan-raw-device onde será definido qual interface física deve ser usada. No exemplo abaixo vamos supor que nossa VLAN é 192 e a interface física a ser usada é a enp0s3:

```bash
auto vlan192
iface vlan192 inet static
address 192.168.1.1
netmask 255.255.255.0
vlan-raw-device enp0s3
```

6 - Se houver a necessidade de configurar uma segunda VLAN, como por exemplo, VLAN ID 193, na mesma interface, adicione um novo trecho no arquivo /etc/network/interfaces com o device vlan193 seguindo o mesmo modelo apresentado.

7 - Reinicie as interfaces de rede para que o linux carregue as informações, com o seguinte comando:

```bash
/etc/init.d/networking restart
```
