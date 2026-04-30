---
layout: post
title: Geração randômica de senha com C#
date: 2012-06-13 10:47:07.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Desenvolvimento
- IT
tags:
- c#
- csharp
- geração randômica
- password
- random
- senha
author: Helvio Junior (m4v3r1ck)
permalink: "/it/devel/geracao-randomica-de-senha-com-c/"
---

Neste post será criado um código em C# para geração de senha randômica e cumprindo os níveis de complexidade estabelecidos.

<!--more-->

No Windows geralmente o nível de complexidade exigido é:

- Não conter partes significativas do nome da conta do usuário ou o nome todo
- Ter pelo menos seis caracteres de comprimento
- Conter caracteres de três das quatro categorias a seguir:
  - Caracteres maiúsculos do inglês (A-Z)
  - Caracteres minúsculos do inglês (a-z)
  - 10 dígitos básicos (0-9)
  - Caracteres não-alfabéticos (por exemplo, !, $, #, %)

Desta forma criei um código para cumprir todos estes requisitos.

A base de geração de alguns dados foi a tabela ASCII (conforma imagem abaixo). Da tabela foram utilizados os caracteres A-Z, a-z, 0-9 e alguns caracteres especiais. Porém no código eles aparecem como os seus decimais.

[![Tabela ASCII]({{ site.baseurl }}/assets/2012/06/ASCII1.gif)]({{ site.baseurl }}/assets/2012/06/ASCII1.gif)

Como referência temos os itens:

```csharp
using System;
using System.Collections.Generic;
using System.Text;
```

A Classe é:

```csharp
public class PasswordGenerator
{
    //Caracteres especiais utilizados
    private String[] Special = new String[] { "@", "#", "$", "!", "%", "-", "_" };

    //Requisitos mínimos de senha
    private Boolean useLowerCase;
    private Boolean useUpperCase;
    private Boolean useDigits;
    private Boolean useSpecial;

    public Boolean UseLowerCase { get { return useLowerCase; } set { useLowerCase = value; } }
    public Boolean UseUpperCase { get { return useUpperCase; } set { useUpperCase = value; } }
    public Boolean UseDigits { get { return useDigits; } set { useDigits = value; } }
    public Boolean UseSpecial { get { return useSpecial; } set { useSpecial = value; } }

    public PasswordGenerator() : this(true, true, true, true) { }

    public PasswordGenerator(Boolean UseLowerCase, Boolean UseUpperCase, Boolean UseDigits, Boolean UseSpecial)
    {
        this.useLowerCase = UseLowerCase;
        this.useUpperCase = UseUpperCase;
        this.useDigits = UseDigits;
        this.useSpecial = UseSpecial;

        if ((!this.useLowerCase) && (!this.useUpperCase) && (!this.useDigits) && (!this.useSpecial))
            this.useLowerCase = true;

    }

    public String Generate(Int32 Length)
    {
        String passwd = "";

        Int32 uppper = 0;
        Int32 lower = 0;
        Int32 digits = 0;
        Int32 special = 0;

        Random rnd = new Random();

        while(passwd.Length < Length)
        {
            Int32 i = rnd.Next(1, 4);
            Int32 i2 = 0;

            //Regras de checagem de requisitos
            while (i != i2)
            {
                switch (i)
                {
                    case 1:
                        if (!useDigits){
                            i++;
                            break;
                        }
                        else if (digits > 0)
                        {
                            if ((useUpperCase) && (uppper == 0))
                                i = i2 = 2;
                            else if ((useLowerCase) && (lower == 0))
                                i = i2 = 3;
                            else if ((useSpecial) && (special == 0))
                                i = i2 = 4;
                            else
                                i2 = i;
                        }
                        else
                        {
                            i2 = i;
                        }
                        break;

                    case 2:
                        if (!useUpperCase)
                        {
                            i++;
                            break;
                        }
                        else if (uppper > 0)
                        {
                            if ((useDigits) && (digits == 0))
                                i = i2 = 1;
                            else if ((useLowerCase) && (lower == 0))
                                i = i2 = 3;
                            else if ((useSpecial) && (special == 0))
                                i = i2 = 4;
                            else
                                i2 = i;
                        }
                        else
                        {
                            i2 = i;
                        }
                        break;

                    case 3:
                        if (!useLowerCase)
                        {
                            i++;
                            break;
                        }
                        else if (lower > 0)
                        {
                            if ((useDigits) && (digits == 0))
                                i = i2 = 1;
                            else if ((useUpperCase) && (uppper == 0))
                                i = i2 = 2;
                            else if ((useSpecial) && (special == 0))
                                i = i2 = 4;
                            else
                                i2 = i;
                        }
                        else
                        {
                            i2 = i;
                        }
                        break;

                    case 4:
                        if (!useSpecial)
                        {
                            i++;
                            break;
                        }
                        else if (special > 0)
                        {
                            if ((useDigits) && (digits == 0))
                                i = i2 = 1;
                            else if ((useUpperCase) && (uppper == 0))
                                i = i2 = 2;
                            else if ((useLowerCase) && (lower == 0))
                                i = i2 = 3;
                            else
                                i2 = i;
                        }
                        else
                        {
                            i2 = i;
                        }
                        break;
                }
            }

            String newItem = "";
            switch (i2)
            {
                case 1:
                    newItem = ((char)(rnd.Next(48, 57))).ToString();
                    digits++;
                    break;

                case 2:
                    newItem = ((char)(rnd.Next(65, 90))).ToString();
                    uppper++;
                    break;

                case 3:
                    newItem = ((char)(rnd.Next(97, 122))).ToString();
                    lower++;
                    break;

                case 4:
                    newItem = Special[rnd.Next(0, Special.Length - 1)];
                    special++;
                    break;
            }

            //Randomiza a posição dos caracteres
            if (passwd.Length > 0)
            {
                System.Threading.Thread.Sleep(1);
                Int32 pos = rnd.Next(0, passwd.Length - 1);
                passwd = passwd.Insert(pos, newItem);
            }
            else
            {
                passwd = newItem;
            }

            //Slep necessário para que o 'rnd.Next' traga valores diferentes
            System.Threading.Thread.Sleep(5);
        }

        return passwd;
    }
}
```

Para a utilização da classe temos este exemplo com um loop gerando 10 senhas diferentes com 16 caracteres cada.

```csharp
PasswordGenerator gen = new PasswordGenerator();

for (Int32 i = 0; i < 10; i++)
{
    Console.WriteLine(gen.Generate(16));
}
```

Segue abaixo o aplicativo completo para download

[Geração de Senha]({{ site.baseurl }}/assets/2012/06/Password.zip)
