---
layout: post
title: Convertendo relatório Zenmap (nmap) para Excel com C#
date: 2012-03-09 18:09:32.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Desenvolvimento
- IT
- Segurança da Informação
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/devel/convertendo-relatorio-zennmap-para-excel-com-c/"
---

O objetivo deste aplicativo é converter o arquivo gerado pelo Zenmap (Nmap) para uma planilha do excel.

O Aplicativo tem como entrada o arquivo XML do zenmap e gera um arquivo XML com um padrão reconhecido pelo Excel.

Método de utilização:

ZenNmapToExcel.exe [arquivo_zennmap.xml]

Segue o aplicativo compilado bem como o código fonte em C# [ZenmapToExcel]({{ site.baseurl }}/assets/2012/03/ZenNmapToExcel.zip).
