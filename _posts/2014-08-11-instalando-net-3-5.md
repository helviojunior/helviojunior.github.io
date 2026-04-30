---
layout: post
title: Instalando .NET 3.5
date: 2014-08-11 11:56:19.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/instalando-net-3-5/"
---

Por uma falha no windows 8, 8.1 e 2012 não é possível realizar a instalação do .net 3.5 através da interface de gerenciamento gráfica.

Sendo assim você poderá habilitar o .NET Framework 3.5 usando a ferramenta de linha de comando DISM (Gerenciamento e Manutenção de Imagens de Implantação) e especificando a mídia de instalação (imagem ISO ou DVD) com a qual o Windows 8 foi instalado.

1. No Windows 8 ou no Windows Server 2012, abra uma janela do Prompt de Comando com credenciais administrativas (ou seja, escolha **Executar como Administrador**).
2. Para instalar o .NET Framework 3.5 da mídia de instalação localizada no diretório D:\sources\sxs, use o seguinte comando: *DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /LimitAccess /Source:d:\sources\sxs* onde,
