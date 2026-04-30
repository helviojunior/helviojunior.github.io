---
layout: post
title: Raspberry Pi, AutoLogin, Auto start uma aplicação e dessabilitar Screen blanking
date: 2013-05-29 16:54:17.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
- Monitoramento
- Zabbix
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/raspberry-pi-autologin-auto-start-uma-aplicacao-e-dessabilitar-screen-blanking/"
---

Este post demonstra como configurar o Raspberry (quando em modo de tela gráfica - x-session) para iniciar automaticamente uma aplicação e prevenir que entre em modo de espera, proteção de tela ou desabilite o monitor.

<!--more-->

**Login automático**

Maiores informações em: [http://elinux.org/RPi_Debian_Auto_Login](http://elinux.org/RPi_Debian_Auto_Login)

Edite o arquivo **/etc/rc.local** e adicione a seguinte linha

```bash
su meu_usuario -c startx
```

**Desabilitando proteção de tela**

Maiores informações em: [http://raspberrypi.stackexchange.com/questions/752/how-do-i-prevent-the-screen-from-going-blank](http://raspberrypi.stackexchange.com/questions/752/how-do-i-prevent-the-screen-from-going-blank)

Instale o pacote xset

```bash
apt-get install x11-xserver-utils
```

Abra ou crie o arquivo **~/.xinitrc** e adicione o seguinte conteúdo

```bash
xset s off # don't activate screensaver
xset -dpms # disable DPMS (Energy Star) features.
xset s noblank # don't blank the video device
exec /etc/alternatives/x-session-manager # start lxde
```

**Auto run**

Maiores informações em: [http://blog.flowbuzz.com/2012/07/raspberry-pi-and-autostart.html](http://blog.flowbuzz.com/2012/07/raspberry-pi-and-autostart.html)

Supondo que o usuário utilizado para iniciar o startx foi o **pi**, iremos realizar as configurações abaixo. Caso contrário altere para o /home do usuário desejado.

```bash
cd /home/pi/.config/
mkdir autostart
```

Crie um arquivo nomeado **/home/pi/.config/autostart/.desktop** e adicione o seguinte conteúdo

```bash
[Desktop Entry]
Type=Application
Name=AppName
Comment=
Exec=/filetorun
StartupNotify=false
Terminal=false
Hidden=false
```
