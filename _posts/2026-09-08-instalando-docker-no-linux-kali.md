---
layout: post
title: Instalando o Docker no Linux (Debian/Ubuntu/Kali)
date: 2026-09-08 10:00:00.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Linux
tags:
- Linux
- Docker
author: Helvio Junior (m4v3r1ck)
permalink: "/it/linux/instalando-docker-no-linux-kali/"
excerpt: "Passo a passo de instalação do Docker em distribuições baseadas em Debian, incluindo o Kali Linux"
---

O procedimento oficial de instalação do Docker funciona muito bem em Debian e Ubuntu, porém quebra no Kali Linux. O motivo é simples: o repositório oficial do Docker não publica pacotes para o codename `kali-rolling`, e o `lsb_release --codename --short` do Kali retorna justamente este valor.

A solução é detectar o codename da distribuição e, quando ele não existir no repositório do Docker, utilizar o codename de uma versão suportada do Ubuntu (neste caso o `jammy`, referente ao Ubuntu 22.04).

<!--more-->

> Todos os comandos abaixo devem ser executados como **root**. Caso esteja utilizando um usuário comum, adicione `sudo` no início de cada linha.
{: .prompt-warning }

## Instalando as dependências

```bash
apt install apt-transport-https ca-certificates curl software-properties-common
```

## Adicionando a chave GPG do repositório

```bash
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
```

## Detectando o codename da distribuição

Este é o trecho que resolve o problema no Kali. O script abaixo verifica se o codename atual existe no repositório do Docker e, caso não exista, utiliza o `jammy`:

```bash
# Detecta o codename; se for Kali (ou outro não suportado pelo repo), usa Ubuntu 22.04 (jammy)
CODENAME=$(lsb_release --codename --short)
if [ "$CODENAME" = "kali-rolling" ] || [ "$(. /etc/os-release && echo "$ID")" = "kali" ] || \
   ! curl -fsSL -o /dev/null "https://download.docker.com/linux/ubuntu/dists/${CODENAME}/Release"; then
    echo "[*] Codename '${CODENAME}' não suportado pelo repositório Docker — usando 'jammy' (Ubuntu 22.04)"
    CODENAME=jammy
fi
```

## Adicionando o repositório do Docker

```bash
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${CODENAME} stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
```

> A variável `${CODENAME}` só existe na mesma sessão do shell em que o bloco anterior foi executado. Caso tenha fechado o terminal, execute novamente o bloco de detecção antes deste comando.
{: .prompt-tip }

## Instalando o Docker

```bash
apt update
apt install docker-ce
```

## Validando a instalação

Verifique se o serviço está ativo e execute o container de teste:

```bash
systemctl enable --now docker
systemctl status docker
docker run --rm hello-world
```

## Alterando o local de armazenamento das imagens e caches

Por padrão o Docker grava tudo dentro de `/var/lib`, ou seja, na partição raiz (`/`). Em servidores que fazem build de imagens com frequência ou que mantêm muitos containers, esse diretório cresce rapidamente (facilmente centenas de GB) e acaba lotando o `/`, o que derruba não só o Docker, mas o sistema operacional inteiro (logs, apt, sessões SSH etc.). A boa prática é manter o sistema operacional em um disco pequeno e colocar os dados do Docker em um disco/partição dedicado, que pode ser dimensionado e expandido de forma independente.

Nas versões atuais do Docker (a partir da 29) o armazenamento de imagens passou a ser feito pelo **containerd** (*containerd image store*, com o storage driver `overlayfs` do tipo `io.containerd.snapshotter.v1`). Na prática isso significa que os dados ficam divididos em **dois** diretórios diferentes, e ambos precisam ser movidos:

| Diretório padrão     | Quem utiliza | O que armazena |
|----------------------|--------------|----------------|
| `/var/lib/containerd` | containerd  | Imagens, camadas (snapshots) e o conteúdo baixado dos registries — normalmente a maior parte do espaço |
| `/var/lib/docker`     | dockerd     | Volumes, metadados dos containers, redes, logs dos containers e cache do BuildKit |

Alterar apenas o `data-root` do Docker (dica que ainda aparece na maioria dos tutoriais) não é mais suficiente: as imagens continuariam sendo gravadas em `/var/lib/containerd`, na partição raiz.

Nos exemplos abaixo o disco dedicado está montado em `/u01`, portanto os diretórios de destino serão `/u01/docker` e `/u01/containerd`.

> O disco de destino deve estar montado de forma persistente (via `/etc/fstab`) **antes** de iniciar os serviços. Caso contrário, se o disco não montar durante o boot, o Docker e o containerd irão criar os diretórios vazios na partição raiz.
{: .prompt-warning }

### Parando os serviços

```bash
systemctl stop docker.socket docker containerd
```

### Customização 1: diretório do containerd

A configuração do containerd fica em `/etc/containerd/config.toml` (o pacote `containerd.io` já cria este arquivo). Altere/adicione o parâmetro `root`, que define onde o containerd armazena seus dados persistentes:

```bash
mkdir -p /u01/containerd
vi /etc/containerd/config.toml
```

```toml
disabled_plugins = ["cri"]
root = "/u01/containerd"
```

> O parâmetro `root` deve ficar no início do arquivo (nível raiz do TOML), e não dentro de alguma seção `[...]`. Não altere o parâmetro `state` (padrão `/run/containerd`), pois ele contém apenas dados temporários em memória e o socket utilizado pelo Docker.
{: .prompt-tip }

### Customização 2: diretório do Docker

A configuração do daemon do Docker fica em `/etc/docker/daemon.json`. O parâmetro `data-root` define onde o dockerd armazena volumes, metadados e caches:

```bash
mkdir -p /u01/docker
vi /etc/docker/daemon.json
```

```json
{
  "data-root": "/u01/docker"
}
```

> Caso também deseje definir o parâmetro `hosts` no `daemon.json`, será necessário remover o `-H fd://` da linha de execução do serviço, pois o Docker não inicia quando a mesma opção é definida nos dois locais. Isso é feito criando o arquivo `/etc/systemd/system/docker.service.d/override.conf` com o conteúdo abaixo e executando `systemctl daemon-reload`:
>
> ```ini
> [Service]
> ExecStart=
> ExecStart=/usr/bin/dockerd
> ```
{: .prompt-info }

### Migrando os dados existentes (opcional)

Caso o Docker já esteja em uso e você deseje manter as imagens, containers e volumes existentes, copie os dados preservando permissões, hard links, ACLs e atributos estendidos:

```bash
rsync -aHAX --numeric-ids /var/lib/containerd/ /u01/containerd/
rsync -aHAX --numeric-ids /var/lib/docker/ /u01/docker/
```

Se for uma instalação nova, basta pular este passo.

### Iniciando os serviços e validando

```bash
systemctl start containerd docker
docker info | grep -Ei "root dir|storage driver"
containerd config dump | grep -E "^root"
```

A saída deve apontar para os novos diretórios:

```
 Storage Driver: overlayfs
 Docker Root Dir: /u01/docker
root = '/u01/containerd'
```

Por fim, faça o `pull` de uma imagem e confirme que o espaço foi consumido no novo disco (e não no `/`):

```bash
docker pull ubuntu:24.04
du -sh /u01/containerd /u01/docker
df -h / /u01
```

Após validar que tudo funciona corretamente, os diretórios antigos podem ser removidos para liberar espaço na partição raiz:

```bash
rm -rf /var/lib/containerd /var/lib/docker
```

## Utilizando o Docker sem root

Por padrão o socket do Docker pertence ao grupo `docker`, portanto apenas o root consegue executar os comandos. Para permitir o uso com o seu usuário comum:

```bash
usermod -aG docker $USER
```

Após executar o comando acima é necessário encerrar e iniciar novamente a sessão (logout/login) para que o novo grupo seja aplicado.

> Adicionar um usuário ao grupo `docker` concede a ele privilégios equivalentes ao root na máquina, pois é possível montar qualquer diretório do host dentro de um container.
{: .prompt-danger }
