---
layout: post
title: Identificando Versão do Windows através de arquivos
date: 2018-08-01 20:44:19.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Segurança da Informação
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/security/identificando-versao-do-windows-atraves-de-arquivos/"
---

Um dos desafios em um pentest é identificar a versão exata de um windows, então segue aqui algumas dicas de como faze-lo usando arquivos nativos do Sistema operacional.

Este procedimento é dividido em 2 passos:

1. Buscar o build number, ou seja, o número de compilação
2. Traduzir este número em algo que possamos entender

## Buscando o Build Number

Arquivo **c:\windows\system32\prodspec.ini**, pode-se observar que a versão é a 5.1.2600.0

```text
;
;Attention : VOUS NE DEVEZ PAS MODIFIER NI SUPPRIMER CE FICHIER.
;
[SMS Inventory Identification]
Version=1.0

[Product Specification]
Product=Windows XP Professionnel

Version=5.0
Localization=Français
ServicePackNumber=0
BitVersion=40
[Version]
DriverVer=07/01/2001,5.1.2600.0
```

Arquivo **c:\boot.ini**, este arquivo detém um não tão exato com a versão do windows

```text
;[boot loader]
timeout=1
default=multi(0)disk(0)rdisk(0)partition(1)\WINDOWS
[operating systems]
multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Windows Server 2003, Standard" /fastdetect /NoExecute=OptIn
```

Arquivo c:\windows\explorer.exe, é um executável então temos que usar uma ferramenta do linux chamada exiftool para buscar as informações do mesmo

```bash
exiftool /tmp/explorer.exe | grep -i "produ"
```

Esse comando retornará algo parecido com o texto abaixo

```text
Product Version Number          : 6.0.3790.1830
Product Name                    : Microsoft® Windows® Operating System
Product Version                 : 6.00.3790.1830
```

## Traduzindo o Build Number em informação do qual é o Sistema Operacional

Agora de posse da informação tão desejada basta traduzir para a versão do windows com a tabela abaixo (retirada de [https://www.gaijin.at/en/lstwinver.php](https://www.gaijin.at/en/lstwinver.php))

| Sistema Operacional | Versão / Build / Data |
| --- | --- |
| Windows 95 OEM Service Release 1 (95A) | 4.00.950 A *) |
| Windows 95 OEM Service Release 2 (95B) | 4.00.1111 B *) |
| Windows 95 OEM Service Release 2.1 | 4.03.1212-1214 B *) |
| Windows 95 OEM Service Release 2.5 C | 4.03.1214 C *) |
| Windows 98 | 4.10.1998 |
| Windows 98 Second Edition (SE) | 4.10.2222 A |
| Windows Millenium Beta | 4.90.2476 |
| Windows Millenium | 4.90.3000 |
| Windows NT 3.1 | 3.10.528 (27.07.1993) |
| Windows NT 3.5 | 3.50.807 (21.09.1994) |
| Windows NT 3.51 | 3.51.1057 (30.05.1995) |
| Windows NT 4.00 | 4.00.1381 (24.08.1996) |
| Windows NT 5.00 (Beta 2) | 5.00.1515 |
| Windows 2000 (Beta 3) | 5.00.2031 |
| Windows 2000 (Beta 3 RC2) | 5.00.2128 |
| Windows 2000 (Beta 3) | 5.00.2183 |
| Windows 2000 | 5.00.2195 (17.02.2000) |
| Whistler Server Preview | 2250 |
| Whistler Server alpha | 2257 |
| Whistler Server interim release | 2267 |
| Whistler Server interim release | 2410 |
| Windows XP (RC 1) | 5.1.2505 |
| Windows XP | 5.1.2600 (25.10.2001) |
| Windows XP, Service Pack 1 | 5.1.2600.1105-1106 |
| Windows XP, Service Pack 2 | 5.1.2600.2180 |
| Windows XP, Service Pack 3 | 5.1.2600 (21.04.2008) |
| Windows .NET Server interim | 5.2.3541 |
| Windows .NET Server Beta 3 | 5.2.3590 |
| Windows .NET Server Release Candidate 1 (RC1) | 5.2.3660 |
| Windows .NET Server 2003 RC2 | 5.2.3718 |
| Windows Server 2003 (Beta?) | 5.2.3763 |
| Windows Server 2003 | 5.2.3790 (24.04.2003) |
| Windows Server 2003, Service Pack 1 | 5.2.3790.1180 |
| Windows Server 2003 | 5.2.3790.1218 |
| Windows Home Server | 5.2.3790 (16.06.2007) |
| Windows Longhorn | 6.0.5048 |
| Windows Vista, Beta 1 | 6.0.5112 (20.07.2005) |
| Windows Vista, Community Technology Preview (CTP) | 6.0.5219 (30.08.2005) |
| Windows Vista, TAP Preview | 6.0.5259 (17.11.2005) |
| Windows Vista, CTP (Dezember) | 6.0.5270 (14.12.2005) |
| Windows Vista, CTP (Februar) | 6.0.5308 (17.02.2006) |
| Windows Vista, CTP (Refresh) | 6.0.5342 (21.03.2006) |
| Windows Vista, April EWD | 6.0.5365 (19.04.2006) |
| Windows Vista, Beta 2 Previw | 6.0.5381 (01.05.2006) |
| Windows Vista, Beta 2 | 6.0.5384 (18.05.2006) |
| Windows Vista, Pre-RC1 | 6.0.5456 (20.06.2006) |
| Windows Vista, Pre-RC1, Build 5472 | 6.0.5472 (13.07.2006) |
| Windows Vista, Pre-RC1, Build 5536 | 6.0.5536 (21.08.2006) |
| Windows Vista, RC1 | 6.0.5600.16384 (29.08.2006) |
| Windows Vista, Pre-RC2 | 6.0.5700 (10.08.2006) |
| Windows Vista, Pre-RC2, Build 5728 | 6.0.5728 (17.09.2006) |
| Windows Vista, RC2 | 6.0.5744.16384 (03.10.2006) |
| Windows Vista, Pre-RTM, Build 5808 | 6.0.5808 (12.10.2006) |
| Windows Vista, Pre-RTM, Build 5824 | 6.0.5824 (17.10.2006) |
| Windows Vista, Pre-RTM, Build 5840 | 6.0.5840 (18.10.2006) |
| Windows Vista, RTM (Release to Manufacturing) | 6.0.6000.16386 (01.11.2006) |
| Windows Vista | 6.0.6000 (08.11.2006) |
| Windows Vista, Service Pack 2 | 6.0.6002 (04.02.2008) |
| Windows Server 2008 | 6.0.6001 (27.02.2008) |
| Windows 7, RTM (Release to Manufacturing) | 6.1.7600.16385 (22.10.2009) |
| Windows 7 | 6.1.7600 (22.10.2009) |
| Windows 7, Service Pack 1 | 6.1.7601 |
| Windows Server 2008 R2, RTM (Release to Manufacturing) | 6.1.7600.16385 (22.10.2009) |
| Windows Server 2008 R2, SP1 | 6.1.7601 |
| Windows Home Server 2011 | 6.1.8400 (05.04.2011) |
| Windows Server 2012 | 6.2.9200 (04.09.2012) |
| Windows 8 | 6.2.9200 (26.10.2012) |
| Windows Phone 8 | 6.2.10211 (29.10.2012) |
| Windows Server 2012 R2 | 6.3.9200 (18.10.2013) |
| Windows 8.1 | 6.3.9200 (17.10.2013) |
| Windows 8.1, Update 1 | 6.3.9600 (08.04.2014) |
| Windows 10 | 10.0.10240 (29.07.2015) |
| Windows 10 (1511) | 10.0.10586 |
| Windows 10 (1607) | 10.0.14393 |
| Windows Server 2016, RTM (Release to Manufacturing) | 10.0.14393 (26.09.2016) |

*) O Build Number nem sempre é exibido exatamente como está na tabela
