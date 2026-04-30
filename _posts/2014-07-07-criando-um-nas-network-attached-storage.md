---
layout: post
title: Criando um NAS (Network-Attached Storage) e DLNA
date: 2014-07-07 21:06:04.000000000 -03:00
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
permalink: "/it/criando-um-nas-network-attached-storage/"
---

O Objetivo deste post é demonstrar passo a passo como configurar um Raspberry Pi para servir como servidor de arquivos/NAS. Com poucas alterações este mesmo procedimento poderá ser utilizado para criar um NAS com aquele computador velho que não se utiliza mais.

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

[![001]({{ site.baseurl }}/assets/2014/07/001.png)]({{ site.baseurl }}/assets/2014/07/001.png)

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

[![002]({{ site.baseurl }}/assets/2014/07/002.png)]({{ site.baseurl }}/assets/2014/07/002.png)

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

## Instalando e configurando outros pacotes

```bash
apt-get -y install ntfs-3g
apt-get -y install wget samba
```

## Instalando webmin

O Webmin será utilizado para gerenciar o samba e suas permissões

Edite o arquivo **/etc/apt/sources.list** e adicione as seguintes linhas para adicionar os repositórios oficiais

```bash
deb http://download.webmin.com/download/repository sarge contrib
deb http://webmin.mirror.somersettechsolutions.co.uk/repository sarge contrib
```

Agora iremos adicionar o arquivo de chaves para garantir o acesso ao repositorio

```bash
cd ~
wget http://www.webmin.com/jcameron-key.asc
apt-key add jcameron-key.asc
```

Agora realize a instalação do webmin

```bash
apt-get update
apt-get -y install webmin
```

Após a instalação pode ser realizado o acesso ao webmin através da URL https://ip_do_servidor:10000

[![003]({{ site.baseurl }}/assets/2014/07/003.png)]({{ site.baseurl }}/assets/2014/07/003.png)

## Criando partição de dados

Agora vamos criar uma nova partição com todo o espaço restante do disco para ser utilizado como dados do NAS. Dentro do webmin vá em **Hardware** > **Partition on local disk** > **selecione o disco externo**

[![004]({{ site.baseurl }}/assets/2014/07/004.png)]({{ site.baseurl }}/assets/2014/07/004.png)

Clique no link **add primary partition**

[![005]({{ site.baseurl }}/assets/2014/07/005.png)]({{ site.baseurl }}/assets/2014/07/005.png)

Configure a partição para utilizar o sistema de arquivos **Windows NTFS** e clique em **Create**

[![006]({{ site.baseurl }}/assets/2014/07/006.png)]({{ site.baseurl }}/assets/2014/07/006.png)

Através da console ou SSH realize a formatação desta partição

```bash
mkfs.ntfs /dev/sda4 --quick
mkdir /media/dados
```

Configure o ponto de montagem editando o arquivo **/etc/fstab** e adicionando a seguinte linha

```bash
/dev/sda4 /media/dados/ ntfs-3g defaults
```

Neste momento toda a base está configurada, basta agora configurar os acessos a rede.

## Configurando acesso a rede

No Webmin vá em **Server** > **Samba windwow file sharing,** posteriormente em **Create a new file share**

[![007]({{ site.baseurl }}/assets/2014/07/0071.png)]({{ site.baseurl }}/assets/2014/07/0071.png)

Preencha os dados do compartilhamento conforma a imagem abaixo e clique em **Create**

[![008]({{ site.baseurl }}/assets/2014/07/008.png)]({{ site.baseurl }}/assets/2014/07/008.png)

Após este processo pode-se observar que o compartilhamento foi criado como somente leitura, desta forma iremos alterar as permissões para permitir a escrita.

[![009]({{ site.baseurl }}/assets/2014/07/009.png)]({{ site.baseurl }}/assets/2014/07/009.png)

Clique no nome do compartilhamento desejado (**NAS**) e posteriormente clique em **Security and Access control**

[![010]({{ site.baseurl }}/assets/2014/07/010.png)]({{ site.baseurl }}/assets/2014/07/010.png)

Altere a permissão **Writable** como **Yes, Guest** como **Yes** clique em **save**

[![011]({{ site.baseurl }}/assets/2014/07/011.png)]({{ site.baseurl }}/assets/2014/07/011.png)

Na tela de edição do NAS clique em **Save** novamente

Como o objetivo deste NAS é um servidor para meus vídeos irei configurar um serviço DLNA.

## Configurando DLNA

Instale o servidor DLNA com o seguinte comando

```bash
apt-get -y install minidlna
```

Para fins de organização criaremos 3 diretórios em nosso NAS (Music, Pictures e Videos)

```bash
mkdir /media/dados/Music
mkdir /media/dados/Pictures
mkdir /media/dados/Videos
```

Agora vamos editar o arquivo de configuração do DLNA **/etc/minidlna.conf** conforme abaixo

```bash
media_dir=A,/media/dados/Music
media_dir=P,/media/dados/Pictures
media_dir=V,/media/dados/Videos
friendly_name=Home DLNA
inotify=yes
```

Inicie o serviço

```bash
service minidlna start
```

Por fim configure para que o dlna inicie no boot

```bash
update-rc.d minidlna defaults
```
