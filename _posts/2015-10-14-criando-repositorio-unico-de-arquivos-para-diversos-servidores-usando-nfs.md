---
layout: post
title: Criando repositório único de arquivos para diversos servidores usando NFS
date: 2015-10-14 12:18:47.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
- Linux
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/criando-repositorio-unico-de-arquivos-para-diversos-servidores-usando-nfs/"
---

O objetivo deste post é demonstrar como criar um único repositório de arquivos para acesso através de diversos servidores. Você pode estar se perguntando onde e como devo utilizar isso? Bom, há muitas utilizações mas uma delas, e a motivadora deste estudo e post, e a possibilidade de você armazenar em um único lugar todo o conteúdo do seu site web (/var/www) e poder utilizar por diversos servidores balanceados, ou seja, você poderá ter 10 servidores Web acessando um único /var/www sem ter que se preocupar toda vez que atualizar um arquivo em um servidor ter que replicar para os outros.

<!--more-->

## O que é NFS?

Antes de iniciar o processo técnico é importante entender o que é e como funciona o NFS. NFS é um acronimo de Network File System, ou seja, Sistema de arquivos em rede. Basicamente o NFS permite que você monte partições ou diretórios fisicamente armazenados em outra maquina como se fosse local, ou seja, via rede, podendo definir permissões específicas de acesso com base no cliente que está acessando.

## Instalando e configurando o servidor NFS

Para este post utilizei o Linux Ubuntu Server 14.04 LTS, mas este procedimento poderá ser replicado para diversas outras distribuições Linux sem nenhum problema. Chega de conversa e vamos ao que interessa, a instalação do servidor NFS.

Primeiro vamos configurar o servidor, ou seja, o local onde os arquivos estarão fisicamente.

Utilize o comando abaixo para instalar os pacotes necessários

```bash
apt-get install nfs-common nfs-kernel-server
```

Crie o diretório que utilizaremos para o compartilhamento com o comando abaixo

```bash
mkdir /media/share
```

Edite o arquivo **/etc/exports** deixando o mesmo com o conteúdo abaixo

```bash
# Caminho do diretório  IP do cliente  Permissões de acesso
/media/share/      192.168.0.0/24(rw,async,no_subtree_check)
```

O padrão deste arquivo é: *Diretório host1(opção11, opção12) host2(opção21, opção22)*

Onde:

- Diretório: Local (diretório) onde os arquivos estão armazenados;
- HostN: IP do cliente que irá acessar os arquivos
- Opções: Permissões de acesso ao compartilhamento

Segue as principais permissões:

- ro: somente leitura.
- rw: leitura e escrita.
- no_root_squash: por default, o nível de acesso dos clientes ao servidor é mesmo que o root. Porém, se quiser que os níveis de acesso sejam os mesmos que os locais, basta definir esta opção no compartilhamento.

Agora vamos fazer uma otimização para alto desempenho no NFS. Edite o arquivo /etc/default/nfs-kernel-server e altere as linhas correspondentes conforme exemplo abaixo:

```bash
RPCNFSDCOUNT=20
RPCMOUNTDOPTS="--manage-gids --no-nfs-version 4"
```

Como último passo do servidor iniciar o serviço NFS com o comando abaixo

```bash
service nfs-kernel-server start
```

Caso você adicione um novo ponto de montagem (compartilhamento) no arquivo **/etc/exports**, para ativa-lo sem reiniciar o serviço do NFS basta executar o comando **exportfs.**

## Configurando o cliente NFS

Utilize o comando abaixo para instalar os pacotes necessários

```bash
apt-get install nfs-common
```

Crie o ponto de montagem, ou seja, o diretório virtual onde posteriormente montaremos o diretório remoto com o comando abaixo

```bash
mkdir /mnt/remoto
```

Caso deseje realizar um teste de montagem do NFS basta utilizar o comando abaixo

```bash
mount -t nfs 192.168.0.1:/media/share  /mnt/remoto
```

Posteriormente basta adicionar no arquivo **/etc/fstab** as configurações do NFS e ponto de montagem conforme o exemplo abaixo

```bash
# Caminho do servidor        Ponto de montagem  Tipo-FS Opções
192.168.0.1:/media/share  /mnt/remoto   nfs  rw   0 0
```

Adicionalmente vamos realizar algumas otimizações para melhor desempenho no NFS, para isso basta alterar as opções de montagem conforme exemplo abaixo

```bash
# Caminho do servidor        Ponto de montagem  Tipo-FS Opções
192.168.0.1:/media/share  /mnt/remoto   nfs  auto,rw,noatime,bg,soft,intr,rsize=32768,wsize=32768,nfsvers=3,nolock,nocto,tcp   0 0
```

Agora basta montar o diretório remoto com o seguinte comando

```bash
mount /mnt/remoto
```
