---
layout: post
title: Configurando o raspberry para iniciar através do HD externo
date: 2015-10-02 15:43:52.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/configurando-o-raspberry-para-iniciar-atraves-do-hd-externo/"
---

O Objetivo deste post é demonstrar passo a passo como configurar um Raspberry Pi para utilizar um HD externo como base do seu sistema operacional. Isso é interessante pois dependendo da aplicação que você for realizar no Raspberry terá problema com o SDCard que tem uma limitação de gravação e escrita e consequentemente crash do sistema.

<!--more-->

**O que é o Raspberry Pi?**

O Raspberry Pi é um computador do tamanho de um cartão de crédito que se conecta à sua TV e um teclado. É um PC que pode ser usado para muitas das coisas que o seu PC faz, como planilhas cálculo, processamento de texto, jogos e servidores diversos. Ele também reproduz vídeo de alta definição.

O Raspberry suporta por padrão algumas distribuições linux como Debian, Arch Linus e Risc OS. Para este post a distribuição de linux escolhida foi o Debian disponível na página oficial do fornecedor do hardware ([clique aqui](http://www.raspberrypi.org/)).

Este tutorial começa após a instalação normal dele, então se precisas de informações sobre como instalar o sistema operacional do raspberry consulte a na página de download existem informações a respeito de como criar a imagem, pois não iremos repetir tais informações para não fugir ao tema.

O primeiro passo, no raspberry ou em qualquer instalação de servidor ao meu ver, é garantir que todos os pacotes básicos estejam devidamente atualizados.

```bash
apt-get update;
apt-get upgrade;
reboot
```

Como o raspberry utiliza como base do seu sistema uma cartão de memória SD há um problema conhecido que é a limitação de quantidade escritas em um mesmo bloco, o que ocasiona uma falha do cartão SD após este número de gravações. Há diversas formas de contornar este problema, a primeira dela é desativar swap do SO, colocar o /var em memória entre outros, porém como para este post teremos um HD externo anexado utilizaremos este HD como base para o sistema operacional.

## Configurando o raspberry para iniciar através do HD

No raspberry não há como realizar o boot diretamente no HD, desta forma sempre precisaremos do SDcard para realizar o boot, e direcionamos o restante do processo para o HD, vamos ao procedimento.

Primeiramente vamos copiar todo o conteúdo do SDCard para o hs externo. Este processo irá excluir todo o conteúdo do hd, desta forma caso tenha algo importante nele realize o backup antes.

Supondo que o sdcard está montado em /dev/sdb e o hd externo em /dev/sdc utilizaremos o seguinte comando

```bash
dd if=/dev/sdb of=/dev/sdc bs=512
```

Sabendo que o raspberry sempre precisará da do SDcard com a partição de boot, será  nessário alterar as as configurações objetivando mudar a localização da raiz para a partição do HD externo ao invés da partição do SDcard. Para isso basta localizar a partição de boot do SDCard e alterar o arquivo /boot/cmdline.txt. substituindo o texto **root=/dev/mmcblk0p2** por **root=/dev/sda2.** Outra alteração necessária é a adição dos comandos **bootdelay rootdelay** ao final da linha para que o boot aguarde a carregamento do HD externo antes de iniciar.

Agora podemos colocar o sdcard e o hd no raspberry e inicia-lo.

Depois de inicia-lo iremos criar uma partição para utilizar como swap através dos comandos abaixo

```bash
fdisk /dev/sda
Command (m for help): p
```

Com este comando será exibido a listagem de partições

[![001]({{ site.baseurl }}/assets/2015/10/001.png)]({{ site.baseurl }}/assets/2014/07/001.png)

Vamos anotar a último bloco utilizado pela última partição, no nosso caso 6266879. Agora vamos criar uma nova partição com 1 Gb para swap.

```bash
Command (m for help): n
Partition type:
 p primary (2 primary, 0 extended, 2 free)
 e extended
 Select (default p): p
 Partition number (1-4, default 3): 3
 First sector (2048-976773167, default 2048): 6266880
 Last sector, +sectors or +size{K,M,G} (6266880-976773167, default 976773167): +1024M
 
```

Logo após podemos exibir novamente a listagem das partições

```bash
Command (m for help): p
```

[![002]({{ site.baseurl }}/assets/2015/10/002.png)]({{ site.baseurl }}/assets/2014/07/002.png)

Por fim grave as alterações realizadas com o comando abaixo

```bash
Command (m for help): w
```

Agora reinicie o sistema para que o mesmo identifique as partições e logo após crie a estrutura de swap na partição /dev/sda3

```bash
mkswap /dev/sda3
```

Ao executar este comando uma mensagem similar a esta será exibida:

```bash
Setting up swapspace version 1, size = 10485756 KiB
no label, UUID=1d82ec7d-cd70-4e1b-b02c-fca25a41faf0
```

Altere o arquivo **/etc/fstab** e adicione a seguinte linha:

```bash
/dev/sda3    none      swap    sw           0       0
```

E por fim removeremos o arquivo de swap utilizado pelo sistema originalmente para que o mesmo não tenha a brilhante idéia de usa-lo.

```bash
rm -rf /etc/rc2.d/S02dphys-swapfile
```

Assim ficamos com 3 partições:

- /dev/sda1: Cópia da partição de boot
- /dev/sda2: Partição de sistema (contém o SO)
- /dev/sda3: Partição usada para swap

Pronto, agora poderemos iniciar o processo de configuração do nosso NAS.

Grave as informações no disco e reinicie o equipamento

```bash
Command (m for help): w
reboot
```
