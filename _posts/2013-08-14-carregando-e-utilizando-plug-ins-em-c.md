---
layout: post
title: Carregando e utilizando plug-ins em C#
date: 2013-08-14 13:04:25.000000000 -03:00
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
permalink: "/it/devel/carregando-e-utilizando-plug-ins-em-c/"
---

Este post demonstra como criar uma aplicação em C# que possibilite a interação com plug-ins. O método demonstrado é bastante simples e poderoso.

Este método realiza os seguintes passos:

- Lista todas as Dlls em um diretório (plugins)
- Carrega todos os assemblies deste diretório
- Verifica se o tipo do assembly é o desejado
- Cria a instancia do tipo que implementa e armazena em uma lista

<!--more-->

Para realizar todos os itens acima o seguinte método genérico lista qualquer interface existente no diretório plugins, veritica o tipo desejado e cria uma lista de casos de todos os tipos que implementam a interface plugin.

```csharp
using System;
using System.Reflection;
using System.Collections.Generic;
using System.IO;

public static List<T> GetPlugins<T>(string folder)
{
	string[] files = Directory.GetFiles(folder, "*.dll");
	List<T> tList = new List<T>();

	foreach (string file in files)
	{
		try
		{
			Assembly assembly = Assembly.LoadFile(file);
			foreach (Type type in assembly.GetTypes())
			{
				if (!type.IsClass || type.IsNotPublic) continue;
				Type[] interfaces = type.GetInterfaces();
				if (((IList<Type>)interfaces).Contains(typeof(T)))
				{
					object obj = Activator.CreateInstance(type);
					T t = (T)obj;
					tList.Add(t);
				}
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine("Erro: " + ex.Message);
		}
	}

	return tList;
}
```

Com este método, podemos escrever um código para mostrar a lista de plugins com sua descrição da seguinte forma

```csharp
string folder = Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), "Plugins");
List list = GetPlugins(folder);

foreach (ITestInterface ti in list)
{
	string name = ti.GetPluginName();
	string desc = ti.GetPluginDescription();
	string str = string.Format("{0}, {1}, {2}",
	ti.GetType().FullName, name, desc);
	Console.WriteLine(str);
}
```

A interface utilizada foi

```csharp
using System;

namespace PluginTest
{
    public delegate void TestEvent(object sender, EventArgs args);
    public interface ITestInterface
    {
        // Informacoes do plugin
        string GetPluginName();
        string GetPluginDescription();

        void PrintText(String text);
        void Reset();

        event TestEvent Motion;
    }
}
```

Fonte: http://blogs.msdn.com/b/abhinaba/archive/2005/11/14/492458.aspx
