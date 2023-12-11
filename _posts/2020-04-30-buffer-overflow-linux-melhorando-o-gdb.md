---
layout: post
title: Buffer Overflow Linux - Melhorando o GDB
date: 2020-04-30 14:18:14.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Criação de Exploits
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/security/criacao-de-exploits/buffer-overflow-linux-melhorando-o-gdb/"
---

O GDB ([The GNU Project Debugger](https://www.gnu.org/software/gdb/)) é hoje sem dúvida o melhor debugger para ambientes Linux e Unix. Porém sua interface padrão causa um pouco de rejeição para quem está começando a se aventurar no processo de criação de exploits ou engenharia reversa.

Por este motivo trago para vocês algumas dicas que vão lhe ajudar bastante neste processo.

<!--more-->

#### Parte 1: Configurando o locale

Se certifique que o locale da máquina está configurado como UTF-8

```shell
sudo locale-gen "en_US.UTF-8"
echo 'LANG="en_US.UTF-8"' > /etc/default/locale
echo 'LANGUAGE="en_US:en"' >> /etc/default/locale
echo 'LC_ALL="en_US.UTF-8"' >> /etc/default/locale
```

#### Parte 2: Instalando o GDB + Python3

```shell
sudo apt-get install python python3 python-dev gdb python3-gdbm python3-gdbm-dbg
```

#### Parte 3: Instalando GEF

O GEF (acrônimo para GDB Enhanced Features) é um plugin que deixa o visual do GDB bem mais amigável, bem como implementa novos comandos que auxiliam bastante no processo de criação de exploits e engenharia reversa. O seu manual está disponível em [https://hugsy.github.io/gef/](https://hugsy.github.io/gef/)

```shell
wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/main/gef.py
echo source ~/.gdbinit-gef.py >> ~/.gdbinit
echo "set follow-fork-mode parent" >> ~/.gdbinit
```

#### Parte 4: Instalando scripts adicionais do GEF

Dentro destes scripts adicionais há 2 comandos que implementei que é muito útil no processo de criação de exploits, mais especificamente no momento da checagem de Badchars.

- **bytearray**: gera o bytearray para copiar e colocar dentro do script python de exploit, bem como o arquivo binário para comparação
- **bincompare**: compara o arquivo binário com os dados em memória objetivando encontrar por badchars.

```shell
wget -q -O- https://github.com/hugsy/gef/raw/main/scripts/gef-extras.sh | sh
```

