---
layout: post
title: Instalando placa de rede no ubuntu no Hyper-V
date: 2013-07-04 08:54:40.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
tags:
- hyperv
- network interface
- ubuntu
author: Helvio Junior (m4v3r1ck)
permalink: "/it/instalando-placa-de-rede-no-ubuntu-no-hyper-v/"
---

Se na instalação do ubuntu em Hyper-V a placa de rede não foi identificada, será necessário carregar os módulos do Hyper-V.

Para isso, edite o arquivo **/etc/initramfs-tools/modules** e adicione as seguintes linhas:

```bash
hv_vmbus
hv_storvsc
hv_blkvsc
hv_netvsc
```

Agora, atualize a imagem initramfs:

```bash
sudo update-initramfs –u
```

Basta reiniciar o linux.
