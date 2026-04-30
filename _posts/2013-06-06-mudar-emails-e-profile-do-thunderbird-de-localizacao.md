---
layout: post
title: Mudar emails e profile do thunderbird de localização
date: 2013-06-06 11:36:16.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/mudar-emails-e-profile-do-thunderbird-de-localizacao/"
---

Para facilitar formatação do PC é interessante ter todos os arquivos em uma pasta/partição diferente, assim não corremos o rtisco de esquecer nada. Com o Thunderbird tudo ficou mais fácil pois todas as configurações e e-mails estão na mesma pasta **C:\Documents and Settings\<utilizador>\Application Data\Thunderbird\**

Para alterar o local basta alterar o ficheiro ***profiles.ini*** da seguinte maneira:

```text
IsRelative=0
Path=<novapasta>\Profiles\<perfilantigo>.default
```
