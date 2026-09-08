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

## Utilizando o Docker sem root

Por padrão o socket do Docker pertence ao grupo `docker`, portanto apenas o root consegue executar os comandos. Para permitir o uso com o seu usuário comum:

```bash
usermod -aG docker $USER
```

Após executar o comando acima é necessário encerrar e iniciar novamente a sessão (logout/login) para que o novo grupo seja aplicado.

> Adicionar um usuário ao grupo `docker` concede a ele privilégios equivalentes ao root na máquina, pois é possível montar qualquer diretório do host dentro de um container.
{: .prompt-danger }
