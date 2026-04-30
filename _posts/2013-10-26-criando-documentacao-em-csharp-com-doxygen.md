---
layout: post
title: Criando documentação em C# com doxygen (html e pdf)
date: 2013-10-26 12:46:06.000000000 -02:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Desenvolvimento
- IT
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/devel/criando-documentacao-em-csharp-com-doxygen/"
---

[Doxygen](http://www.doxygen.org/)é um sistema  open-source para a geração de documentação e referência de código, o doxygen realiza a documentação de diversas linguagens como C#, C++, Java e etc. A documentação é gerada a partir de marcadores inseridos no próprio código-fonte.

Escolhi este sistema pelos motivos acima e por ser amplamente utilizado e documentado pela comunidade.

<!--more-->

Vamos ao passo a passo, primeiro realize o download do doxygen a partir do site oficial e realiza a instalação em seu windows. A instalação não requer comentários pois é extremamente simples e não necessita personalização.

Existe diversas sintaxes para a utilização do doxygen , para este tutorial foi escolhida a de XML, todas as sintaxes podem serem encontradas no [manual](http://www.stack.nl/~dimitri/doxygen/manual/index.html).

Segue abaixo um exemplo tipico da sintaxe de XML:

```csharp
/// <summary>
/// Exemplo de descrição da classe.
/// </summary>
class DoxygenSample
{
	/// <summary>
	/// Este método realiza a soma de 2 números
	/// </summary>
	/// <param name="a">Primeiro número a ser somado</param>
	/// <param name="b">Segundo número a ser somado</param>
	/// <returns>Retorna a soma dos 2 números passados via parâmetro (a + b)</returns>
	static Int32 Sum(Int32 a, Int32 b)
	{
		return a + b;
	}
}
```

Vamos ao exemplo prático, crie um novo projeto em C# conforme exemplo abaixo:

```csharp
///
/// @file program.cs
/// <summary>
/// Decrição sucinta deste arquivo
/// </summary>
/// Descrição detalhada deste arquivo
/// Esta descrição pode ter mais de uma linha
/// Conforme este exemplo
/// @author Helvio Junior <helvio_junior@hotmail.com>
/// @date 26/10/2013
/// $Id: program.cs, v1.0 2013/10/26 17:44:13 Helvio Junior $

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DoxygenSample
{
    /// <summary>
    /// Uma descrição sobre a classe Program
    /// Você pode colocar o que deseja.
    /// </summary>
    class Program
    {
        /// <summary>
        /// Método de inicialização do programa
        /// </summary>
        /// <param name="args">Como parâmetro é recebido os argumentos passados via linha de comando pelo usuário</param>
        static void Main(string[] args)
        {
            Console.WriteLine(Sum(10, 30));
        }

        /// <summary>
        /// Este método realiza a soma de 2 números
        /// </summary>
        /// <param name="a">Primeiro número a ser somado</param>
        /// <param name="b">Segundo número a ser somado</param>
        /// <returns>Retorna a soma dos 2 números passados via parâmetro (a + b)</returns>
        static Int32 Sum(Int32 a, Int32 b)
        {
            return a + b;
        }
    }
}
```

Para os comandos especiais do cabeçalho do arquivo pode ser consultado a [documentação](http://www.stack.nl/~dimitri/doxygen/manual/commands.html)do doxygen

Agora que o código está pronto vamos a execução do doxygen. Abra o doxywizard, ele facilita bastante toda a configuração.

Na janela inicial configure as seguintes opções:

- Diretório de execução (working directory)
- Na aba Wizard
  - Nome do projeto (project name)
  - Sumário do projeto (project synopsis)
  - Versão do projeto (project version)
  - Diretório do código fonte (source code directory)
  - Selecione a opção scan recursivo (scan recursively)
  - Diretório de destino da documentação (destination directory)

[![Doxygen 001]({{ site.baseurl }}/assets/2013/10/001.png)]({{ site.baseurl }}/assets/2013/10/001.png)

Clique em next ou no item mode e configure as seguintes opções:

- Todas as entidades (all entities)
- Otimizado para C# (optimize for C# and java output)

[![Doxygen 002]({{ site.baseurl }}/assets/2013/10/002.png)]({{ site.baseurl }}/assets/2013/10/002.png)

Clique em Next ou em Output e configure conforme abaixo:

[![Doxygen 003]({{ site.baseurl }}/assets/2013/10/003.png)]({{ site.baseurl }}/assets/2013/10/003.png)

Clique em next ou em Diagrams e configure conforme abaixo:

[![Doxygen 004]({{ site.baseurl }}/assets/2013/10/004.png)]({{ site.baseurl }}/assets/2013/10/004.png)

Por último clique na aba Expert depois em build e selecione todas as opções conforme imagem abaixo:

[![Doxygen 005]({{ site.baseurl }}/assets/2013/10/005.png)]({{ site.baseurl }}/assets/2013/10/005.png)

Toda a configuração está pronta, basta agora ir na aba run e clique no botão run doxygen:

[![Doxygen 006]({{ site.baseurl }}/assets/2013/10/006.png)]({{ site.baseurl }}/assets/2013/10/006.png)

Para visualizar a documentação clique em Show HTML output. A documentação gerada é semelhante as imagens abaixo:

[![Doxygen 007]({{ site.baseurl }}/assets/2013/10/007.png)]({{ site.baseurl }}/assets/2013/10/007.png)

[![Doxygen 010]({{ site.baseurl }}/assets/2013/10/010.png)]({{ site.baseurl }}/assets/2013/10/010.png)

[![Doxygen 008]({{ site.baseurl }}/assets/2013/10/008.png)]({{ site.baseurl }}/assets/2013/10/008.png)

Para gerar a documentação em PDF é necessário a instalação do Miktex disponível no site oficial [http://www.miktex.org/](http://www.miktex.org/).

Após a geração da documentação através do doxygen 2 sub-diretórios são criados dentro diretório escolhido para saída da documentação (html e latex) onde HTML tem a documentação mostrada acima e o latex é a preparação para a geração do PDF.

Após a instalação do miktex, entre no diretório latex e execute o arquivo bat nomeado make.bat o arquivo refman.pdf será gerado.
