---
layout: post
title: Instalando OpenVPN 2.4.x em Ubuntu/Debian
date: 2020-05-27 16:17:48.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
tags: 
- OpenVPN
- VPN
author: Helvio Junior (m4v3r1ck)
permalink: "/it/instalando-openvpn-2-4-x-em-ubuntu-debian/"
---


```shell
curl -s https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
echo "deb http://build.openvpn.net/debian/openvpn/stable `lsb_release --codename --short` main" > /etc/apt/sources.list.d/openvpn-aptrepo.list
apt update
apt install -y openvpn
```
