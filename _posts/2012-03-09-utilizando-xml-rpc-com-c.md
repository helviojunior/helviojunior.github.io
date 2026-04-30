---
layout: post
title: Utilizando XML-RPC com C#
date: 2012-03-09 12:54:08.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Desenvolvimento
- IT
tags:
- antispam
- barracuda
- c#
- xml-rpc
- xmlrpc
author: Helvio Junior (m4v3r1ck)
permalink: "/it/devel/utilizando-xml-rpc-com-c/"
---

## Introdução

O XML-RPC é um protocolo de chamada de procedimento remoto (RPC) que utiliza XML para codificar suas chamadas e HTTP como um mecanismo de transporte.

É um protocolo simples, definido com poucas linhas de códigos em oposição com a maioria dos sistemas de RPC, onde os documentos padrões são freqüentemente com milhares de páginas e exige apoio de softwares para serem usados. Fonte: http://pt.wikipedia.org/wiki/XML-RPC

O XML-RPC é um protocolo criado em 1989 por Dave Winer na UserLand Software. Ele é o protocolo de WebService utilizado por diversos sistemas. Atualmente ele não é o padrão recomendado para implementações de  soluções WebService, sendo o SOAP 1.2 o padrão.

Para maiores informações sobre o SOAP 1.2 recomendo a leitura da sua especificação no W3C disponível em [http://www.w3.org/TR/soap/](http://www.w3.org/TR/soap/) e do livro *Programming Web Services with SOAP* de Doug Tidwell, James Snell e Pavel Kulchenko (O'Reilly).

Buscando um pouco na internet encontrei uma biblioteca de XML-RPC para C#, porém achei pouca informação sobre como utilizá-la e explorar todas suas possibilidades. Desta forma resolvi criar este post para quem está iniciando neste mundo de WebService.

Para quem deseja se aprofundar  no protocolo XML-RPC recomento a leitura do livro *Programming Web Services with XMLRPC* de Simon St. Laurent, Joe Johnston e Edd Dumbill (O'Reilly).

<!--more-->

## Biblioteca

Como base deste aplicativo foi utilizada a biblioteca XML-RPC.NET criada por Charles Cook.

## Recursos

- Listagem dos métodos disponíveis no WebService;
- Listagem das estruturas do WebService;
- Chamada de um método do WebService.

## Métodos básicos do XML-RPC

O método **system.listMethods** geralmente está presente nas implementações de servidor WebService. Este método é utilizado pata listar todos os métodos presentes no WebService.

### system.listMethods

Na execução deste método há como retorno uma lista contendo o nome de todos os métodos disponíveis no servidor.

**Nome:**

system.listMethods.

**Parametros:**

Não há parâmetros

**Resultado:**

Retorna uma XML-RPC array de Strings que representa o nome dos métodos implementados pelo servidor.

Cada elemento da lista é único, ou seja, não poderá haver duplicidade de nomes.

Não é obrigatório que o servidor retorne todos os métodos implementados pelo servidor. Um exemplo disso é quando deseja-se que um determinado método seja privado.

**Exemplo:**

Chamada:

```xml
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>
```

Resposta:

```xml
<methodResponse>
<params>
<param>
<value><array><data>
<value>
<string>system.listMethods</string>
</value>
<value>
<string>system.methodSignature</string>
</value>
</data></array></value>
</param>
</params>
</methodResponse>
```

## Implementação

Vamos a implementação da API de consulta.

A Primeira coisa a ser criada é a interface se conexão com o Server.

```csharp
using System;
using CookComputing.XmlRpc;
namespace WebServiceAPI
{
   public interface IStateName : IXmlRpcProxy
   {
      [XmlRpcMethod("system.listMethods")]
      String[] ListMethods();
   }
}
```

Com a interface criada agora podemos realizar a consulta, em meu projeto criarei uma classe chamada **APIBase** com o seguinte código:

```csharp
using System;
using System.Collections.Generic;
using CookComputing.XmlRpc;
using System.Text;
namespace WebServiceAPI
{
   public class APIBase
   {
      internal IStateName proxy;
      public APIBase(Uri uri) : this(uri, false){}
      public APIBase(Uri uri, Boolean ignoreCertificateErrors)
      {
          if (ignoreCertificateErrors)
               System.Net.ServicePointManager.ServerCertificateValidationCallback = ((sender, certificate, chain, sslPolicyErrors) => true);

           proxy = (IStateName)XmlRpcProxyGen.Create(typeof(IStateName));
           proxy.Url = uri.AbsoluteUri;
       }

       public String[] ListMethods()
       {
           return proxy.ListMethods();
       }

   }
}
```

Como métodos de instanciamento da classe temos 2 formas, a primeira somente com a URL do WebService (aceitando HTTP e HTTPS), e a segunda com a URL e se serão ignorados os erros de certificado HTTPS inválido.

Nesta classe também há o método **ListMethods** que por sua vez chama o ListMethods da interface com o WebService.

Vamos ao teste. Instancie a classe de API e execute o método ListMethods conforme demonstrado no código abaixo:

```csharp
APIBase xmlRpcApi = new APIBase(new Uri("http://servidor_wordpress/xmlrpc.php"), true);
String[] WSMethods = xmlRpcApi.ListMethods();
foreach(String methodName in WSMethods)
    Console.WriteLine(methodName);
```

Ao executar este código deve retornar o nome de todos os métodos.

Agora vamos implementar na classe **APIBase** umas funções para facilitar o trabalho no conhecimento das propriedades e métodos do WebService.  Ficando o código dessa classe conforme abaixo:

```csharp
using System;
using System.Collections.Generic;
using CookComputing.XmlRpc;
using System.Text;

namespace WebServiceAPI
{
   public class APIBase
   {
      internal IStateName proxy;
      public APIBase(Uri uri) : this(uri, false){}
      public APIBase(Uri uri, Boolean ignoreCertificateErrors)
      {
         if (ignoreCertificateErrors)
            System.Net.ServicePointManager.ServerCertificateValidationCallback = ((sender, certificate, chain, sslPolicyErrors) => true);
         proxy = (IStateName)XmlRpcProxyGen.Create(typeof(IStateName));
         proxy.Url = uri.AbsoluteUri;
      }

      public String[] ListMethods()
      {
         return proxy.ListMethods();
      }

      public static String DumpVariable(Object obj){
         return DumpVariable(obj, "");
      }

      public static String DumpVariable(Object obj, String printPrefix)
      {
         StringBuilder dumpText = new StringBuilder();
         try {
            dumpText.AppendLine(printPrefix + "type ==> " + obj.GetType());
         } catch (Exception) { }
         if (obj is XmlRpcStruct)
         {
             foreach(String key in ((XmlRpcStruct)obj).Keys){
                 dumpText.AppendLine(printPrefix + key);
                 dumpText.AppendLine(DumpVariable(((XmlRpcStruct)obj)[key], printPrefix + "\t"));
             }
         }
         else if (obj is XmlRpcStruct[])
         {
             foreach(XmlRpcStruct r1 in ((XmlRpcStruct[])obj)){
                 dumpText.AppendLine(DumpVariable(r1, printPrefix + "\t"));
             }
         }
         else if (obj is Object[])
         {
             foreach(Object t in ((Object[])obj)){
                 dumpText.AppendLine(DumpVariable(t, printPrefix + "\t   "));
             }
         }
         else if (obj is String)
         {
             if (obj != null)
                dumpText.AppendLine(printPrefix + "\t   " +obj.ToString());
         }
         else if (obj is String[])
         {
             foreach(Object t in ((String[])obj)){
                 if (t != null)
                    dumpText.AppendLine(printPrefix + "\t   " +t.ToString());
             }
         }
         else
         {
             if (obj != null)
                dumpText.AppendLine(printPrefix + "\t   " + obj.ToString());
         }
         return dumpText.ToString();
      }
   }
}
```

Basicamente foram criados 2 métodos nomeados **DumpVariable** que realizam o parse dos dados retornados pelo WebService.

Para dar os próximos passos é necessário a documentação do WebService, no tocante a parâmetros de entrada e saída dos métodos. Alguns aplicativos servidores de WebService implementam métodos de consulta da estrutura como é o caso do Webservice da Barracuda (colocarei um código de exemplo para download).

Para o webservice escolhido (Wordpress) há uma página de referência dos métodos em :

[http://codex.wordpress.org/XML-RPC_wp](http://codex.wordpress.org/XML-RPC_wp)

Para que se possa utilizar o WebService do wordpress é preciso habilitar em Configurações > Escrita > *Ativar os protocolos de publicação XML-RPC do WordPress, Movable Type, MetaWeblog e Blogger.*

Para exemplificação escolheremos dois métodos o **wp.getUsersBlogs** e **wp.getPageList.** Segue a descrição destes:

### wp.getUsersBlogs

Retorna os blogs dos usuários.

**Parâmetros:**

```text
String username
String password
```

**Retorno:**

```text
Array
   Struct
     Boolean isAdmin
     String url
     String blogid
     String blogName
     String xmlrpc
```

### wp.getPageList

Retorna uma array com todas as páginas de um blog. Somente informações mínimas são retornadas, para maiores informações pode ser usado o método **wp.getPages.**

**Parâmetros:**

```text
Int32 blog_id
String username
String password
```

**Retorno:**

```text
Array
   Struct
      Int32 page_id
      String page_title
      Int32 page_parent_id
      DateTime dateCreated
```

Agora que conhecemos a estrutura dos nossos métodos necessitamos cria-las em nosso projeto. Até o momento criaremos somente a estrutura de retorno do método **wp. getUsersBlogs**, pois nos próximos passos mostrarei como utilizar as funções **DumpVariables** para descobrir a estrutura de retorno dos dados.

```csharp
public struct getUsersBlogsResponse
{
   public Boolean isAdmin;
   public String url;
   public String blogid;
   public String blogName;
   public String xmlrpc;
}
```

Caso deseje não receber algum parâmetro basta incluir a instrução para ignorar conforme código abaixo. Apenas para exemplificação foi removido o parâmetro xmlrcp. Em nosso exemplo não utilizaremos essa instrução.

```csharp
[XmlRpcMissingMapping(MappingAction.Ignore)]
public struct getUsersBlogsResponse
{
   public Boolean isAdmin;
   public String url;
   public String blogid;
   public String blogName;
}
```

Após a criação das inclua os métodos na interface XML-RPC.

```csharp
[XmlRpcMethod("wp.getUsersBlogs")]
getUsersBlogsResponse[] getUsersBlogs(String username, String password);

[XmlRpcMethod("wp.getPageList")]
Object getPageList(Int32 blog_id, String username, String password);
```

Depois inclua as chamadas na classe APIBase

```csharp
public getUsersBlogsResponse[] UsersBlogs(String username, String password)
{
   return proxy.getUsersBlogs(username, password);
}

public Object PageList(Int32 blog_id, String username, String password)
{
   return proxy.getPageList(blog_id, username, password);
}
```

Note que o retorno do método **PageList** foi definido como **Object**, pois como desejamos conhecer a estrutura o Object é uma forma genérica de retorno para que possamos utilizar a função **DumpVariables**.

Agora no código principal basta realizar as consultas.

```csharp
using System;
using WebServiceAPI;

namespace Test
{
   class Program
   {
      public static void Main(string[] args)
      {
          APIBase xmlRpcApi = new APIBase(new Uri("http:// servidor_wordpress /xmlrpc.php"), true);
          String[] WSMethods = xmlRpcApi.ListMethods();
          //foreach(String methodName in WSMethods)
          //            Console.WriteLine(methodName);

          String username = "WordPressAdminUser";
          String password = "Senha";
          getUsersBlogsResponse[] Blogs = xmlRpcApi.UsersBlogs(username,password);
          foreach(getUsersBlogsResponse b in Blogs)
          {
              Object PList = xmlRpcApi.PageList(Int32.Parse(b.blogid), username,password);
              Console.WriteLine(b.blogid + " = " + b.blogName);
              Console.WriteLine(APIBase.DumpVariable(PList));
              Console.WriteLine("");
         }
         Console.Write("Press any key to continue . . . ");
         Console.ReadKey(true);
      }
   }
}
```

Executando este código tem-se a seguinte saída:

[![image1]({{ site.baseurl }}/assets/2012/03/image11.png)]({{ site.baseurl }}/assets/2012/03/image11.png)

Pode-se observar pela imagem que o retorno da chamada PageList é um array do tipo XmlRpcStruct e que contem as seguintes variáveis:

```text
String page_id
String page_title
DateTime dateCreated
Datetime date_created_gmt
```

De posse dessa informação podemos criar a struct e retornar os dados no formato desejado.

```csharp
public struct getPageListResponse
{
public String page_id;
public String page_title;
public DateTime dateCreated;
public DateTime date_created_gmt;
}
```

Altere a interface e a API para utilizar essa struct

```csharp
//Struct
[XmlRpcMethod("wp.getPageList")]
getPageListResponse[] getPageList(Int32 blog_id, String username, String password);

//API
public getPageListResponse[] PageList(Int32 blog_id, String username, String password)
{
   return proxy.getPageList(blog_id, username, password);
}
```

E por ultimo a aplicação principal:

```csharp
using System;
using WebServiceAPI;
namespace Test
{
     class Program
     {
        public static void Main(string[] args)
        {
             APIBase xmlRpcApi = new APIBase(new Uri("http:// servidor_wordpress /xmlrpc.php"), true);
             String[] WSMethods = xmlRpcApi.ListMethods();
             //foreach(String methodName in WSMethods)
             //            Console.WriteLine(methodName);
             String username = "WordPressAdminUser";
             String password = "Senha";
             getUsersBlogsResponse[] Blogs = xmlRpcApi.UsersBlogs(username,password);
             foreach(getUsersBlogsResponse b in Blogs)
             {
                  Console.WriteLine(b.blogid + " = " + b.blogName);
                  getPageListResponse[] PList = xmlRpcApi.PageList(Int32.Parse(b.blogid), username,password);
                  foreach(getPageListResponse pl in PList)
                  {
                      Console.WriteLine("\t" + pl.page_id + ", " + pl.page_title);
                  }
                  Console.WriteLine("");
             }
             Console.Write("Press any key to continue . . . ");
             Console.ReadKey(true);
         }
     }
}
```

Executando este código temos essa saída na tela:

## [![image2]({{ site.baseurl }}/assets/2012/03/image21.png)]({{ site.baseurl }}/assets/2012/03/image21.png)

## Licença

Este aplicativo pode ser livremente utilizado.

## Download

[Aplicativo XML-RPC padrão]({{ site.baseurl }}/assets/2012/03/XMLRPC_v1.zip)

[Aplicativo XMLRPC-barracuda]({{ site.baseurl }}/assets/2012/03/XMLRPC-barracuda_v1.zip)
