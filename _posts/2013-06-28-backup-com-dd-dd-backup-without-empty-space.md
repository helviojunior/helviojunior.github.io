---
layout: post
title: Backup com dd (dd backup without empty space)
date: 2013-06-28 14:43:10.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
- Linux
- Zabbix
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/backup-com-dd-dd-backup-without-empty-space/"
---

Com a utilização do Raspberry tive a necessidade de preparar uma imagem base para clonar em outros dispositivos ou até mesmo para fins de backup. A melhor ferramenta para realizar essa operação é o **dd**, porém se não for definido a área que se deseja realizar o backup ele faz de todo o disco mesmo das áreas vazias (sem partição).

Este post mostra como verificar a área utilizada do disco (ou cartão de memória no caso do Raspberry) e realizar o backup somente dessas áreas. Adicionalmente mostra como realizar o backup e compactar com gzip.

<!--more-->

**Verificando área utilizada**

Execute o comando abaixo substituindo o X pelo seu dispositivo

```bash
fdisk -l /dev/sdX
```

O retorno do comando será similar ao mostrado abaixo

[![fdisk]({{ site.baseurl }}/assets/2013/06/fdisk.png)]({{ site.baseurl }}/assets/2013/06/fdisk.png)

[{{ site.baseurl }}/assets/2013/06/fdisk.png]({{ site.baseurl }}/assets/2013/06/fdisk.png)O retorno do comando mostra os blocos utilizados por cada partição bem como o bloco inicial, final e o tamanho do bloco.

Neste retorno a ultima partição **/dev/sdb2** tem o seu final no bloco 6266879, desta forma o comando dd necessita realizar o backup até este bloco, porém por preciosismo faremos o backup de um bloco a mais.

**Backup sem gzip**

```bash
dd if=/dev/sdb bs=512 count=6266880 of=/path/to/imagefile.img
```

**Backup com gzip**

```bash
dd if=/dev/sdb bs=512 count=6266880 | gzip | dd of=/path/to/imagefile.img.gz
```

Nos 2 comandos acima utilizamos o tamanho do bloco (bs=) como 512 e a contagem como o último bloco a ser copiado.

**Restauração sem gzip**

```bash
dd if=/path/to/imagefile.img of=/dev/sdX
```

**Restauração com gzip**

```bash
dd if=/path/to/imagefile.img.gz | gunzip | dd of=/dev/sdX
```

**Cópia dos dados de disco para disco**

```bash
dd if=/dev/sdb bs=512 count=6266880 of=/dev/sdX
```
