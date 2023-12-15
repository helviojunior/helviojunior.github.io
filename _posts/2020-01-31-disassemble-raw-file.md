---
layout: post
title: Disassemble raw file
date: 2020-01-31 09:36:10.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Criação de Exploits
- Offensive Security
tags:
- Offensive Security
- Buffer Overflow
- Shellcoding
- OSED
- OSEE
- OSCE3
- Pentest
- Criação de Exploits
- Windows Internals
author: Helvio Junior (m4v3r1ck)
permalink: "/it/disassemble-raw-file/"
---

Em um processo de exploitation ou engenharia reversa é bem comum a necessidade de realizar um disassemble de um objeto.

Muitas vezes se faz necessário realizar isso em um arquivo não reconhecido automaticamente pelo disassembler, sendo assim segue abaixo os comandos para forçar a identificação

```shell
# objdump -D -Mintel,i386 -b binary -m i386 foo.bin # for 32-bit code
# objdump -D -Mintel,x86-64 -b binary -m i386 foo.bin # for 64-bit code
```

Fonte: [https://stackoverflow.com/questions/14290879/disassembling-a-flat-binary-file-using-objdump](https://stackoverflow.com/questions/14290879/disassembling-a-flat-binary-file-using-objdump)
