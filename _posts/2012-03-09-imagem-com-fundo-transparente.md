---
layout: post
title: Imagem com fundo transparente
date: 2012-03-09 16:57:43.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Desenvolvimento
- Fotografia
tags:
- alfa
- background transparent
- definir cor transparente
- fundo transparente
- image opacity
- replace color
- transparency
author: Helvio Junior (m4v3r1ck)
permalink: "/fotografia/imagem-com-fundo-transparente/"
---

Este artigo mostra de forma simples como converter uma cor sólida em transparência com C#.

O código do exemplo converte todos os pixels da cor branca para transparência e salva a imagem em PNG com fundo transparente.

<!--more-->

```csharp
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;

namespace WhiteToTransparent
{
 class Program
 {
 public static void Main(string[] args)
 {

 Color replaceColor = Color.White;

 foreach(String f in args)
 {
 FileInfo file = new FileInfo(f);
 if (file.Exists)
 Convert(file, replaceColor);
 }

 Console.Write("Press any key to continue . . . ");
 Console.ReadKey(true);
 }

 public static void Convert(FileInfo file, Color replaceColor){
 Bitmap originalBmp = (Bitmap)Bitmap.FromFile(file.FullName);

 Int32 colunas = originalBmp.Width;
 Int32 linhas = originalBmp.Height;

 Bitmap bmp = new Bitmap(colunas, linhas);

 for(Int32 y = 0; y < linhas; y++){
 for(Int32 x = 0; x < colunas; x++){
 Color pixel = originalBmp.GetPixel(x, y);
 if ((pixel.R != replaceColor.R) && (pixel.G != replaceColor.G) && (pixel.B != replaceColor.B))
 bmp.SetPixel(x, y, pixel);
 }
 }

 bmp.Save(file.FullName.Replace(file.Extension, "_t" + file.Extension), System.Drawing.Imaging.ImageFormat.Png);

 }
 }
}
```

Forma de execução:

```csharp
WhiteToTransparent.exe [nome_do_arquivo]
```

Fica como promessa realizar um algoritmo mais elaborado que substitui a cor principal e seus tons para graduações de transparência e publicá-lo aqui.

Para quem deseja apenas trocar a cor branca para fundo transparente segue o programa para download já compilado juntamente com  o código fonte [WriteToTransparent]({{ site.baseurl }}/assets/2012/03/WriteToTransparent.zip).
