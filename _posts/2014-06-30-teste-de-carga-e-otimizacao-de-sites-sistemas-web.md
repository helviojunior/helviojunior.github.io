---
layout: post
title: Teste de carga e otimização de sites/sistemas web
date: 2014-06-30 18:53:19.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
tags:
- content type
- load test
- site optimization
- stress teste
author: Helvio Junior (m4v3r1ck)
permalink: "/it/teste-de-carga-e-otimizacao-de-sites-sistemas-web/"
---

A algum tempo necessitei realizar um teste de carga do site de um cliente, em busca pela web encontrei diversas ferramentas e sites que realizam este trabalho, porém nenhuma das ferramentas nos atendia completamente e algumas muito complexas para realizar testes simples.

Desta forma decidi criar uma ferramenta que pudesse me ajudar e ajudar a comunidade. Seu licenciamento é para livre utilização.

<!--more-->

Vamos ao que interessa, a ferramenta e suas funcionalidades.

**Funcionalidades:**

- Teste de carga (stress test);
- 2 modos de operação (VU - Virtual Users, este simula um número x de conexões simultâneas e SBU - Simulate Browser Users, este modo simula um numero x de navegadores web no qual pode abrir diversas conexões simultâneas por navegador);
- Suporte a 2 tipos de base de dados (SQLite e SQLServer)
- Permite utilização através de proxy ativo
- Plataforma windows;
- Realiza análise e sugere otimização de arquivos (CSS, JS e Imagens)
- Realiza análise de utilização de GZIP por parte do servidor web para otimização de banda;
- Configuração de Cookie e User-Agent personalizado;
- Ao final do teste gera um relatório HTML com as seguintes informações:
  - VU/SBU ativos
  - Número máximo de clientes (VU or SBU) ativos.
  - Bandwidth (Throughput máximo)
  - Quantidade de dados recebidos
  - Total de requisições web
  - Quantidade de requisições por segundo
  - Tempo de resposta das requisições
  - Quantidade de erros
  - Distribuição (volume de dados) por conteúdo (html, js, css, imagens e outros)
  - Tempo de carga por conteúdo (html, js, css, imagens e outros)
  - Volume de dados tráfegados de dados por conteúdo (html, js, css, imagens e outros)
  - Top 25 URLs em quantidade de chamadas
  - Top 25 URLs com maior tempo de resposta
  - Top 25 URLs com maior tráfego de dados
  - Tabela com sugestões de otimização e % estimada de ganho
  - Tabela com calculo de ganho de banda com Gzip/Deflate;
  - E muito mais...

**Segue abaixo alguns gráficos do relatório:**

[![web-stress-test-001]({{ site.baseurl }}/assets/2014/06/web-stress-test-001.png)]({{ site.baseurl }}/assets/2014/06/web-stress-test-001.png) [![web-stress-test-002]({{ site.baseurl }}/assets/2014/06/web-stress-test-002.png)]({{ site.baseurl }}/assets/2014/06/web-stress-test-002.png) [![web-stress-test-003]({{ site.baseurl }}/assets/2014/06/web-stress-test-003.png)]({{ site.baseurl }}/assets/2014/06/web-stress-test-003.png) [![web-stress-test-004]({{ site.baseurl }}/assets/2014/06/web-stress-test-004.png)]({{ site.baseurl }}/assets/2014/06/web-stress-test-004.png)

[![web-stress-test-005]({{ site.baseurl }}/assets/2014/06/web-stress-test-005.png)]({{ site.baseurl }}/assets/2014/06/web-stress-test-005.png)

**Pré requisitos:**

- Microsoft .NET Framework 4.0;
- Microsoft Visual C++ 2010 (x86 ou x64);

**Download e forma de utilização:**

Para utilização do aplicativo basta realizar o download neste link ([LoadTest]({{ site.baseurl }}/assets/2014/06/LoadTest.zip)) e seguir as instruções abaixo.

1 - Descompacte o arquivo rar, localize o arquivo LoadTest.exe.config e abra no seu editor de texto preferido, neste arquivo conterá todas as configurações necessárias para o correto funcionamento do aplicativo.

```xml
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
 <appSettings>
 <add key="type" value="vu"/>
 <add key="count" value="10"/>
 <add key="duration" value="420"/>
 <add key="levels" value="1"/>
 <add key="uri" value="http://www.seusite.com.br/path/completo/"/>
 <!--add key="proxy" value="http://teste:8080/"/-->
 <add key="User-Agent" value="Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36 LoadTest/1.2" />
 <add key="Cookie" value="Teste=Teste123" />
 </appSettings>
 <connectionStrings>
 <add name="LoadTest" connectionString="Data Source=|DataDirectory|SafeTrend.loadtest.db" providerName="System.Data.SQLite" />
 <!--add name="LoadTest" connectionString="Data Source=192.168.0.30;Initial Catalog=database_name;User Id=db_user;Password=db_password;" providerName="System.Data.SqlClient" /-->
 </connectionStrings>
</configuration>
```

Edite os parâmetros conforme desejado. Segue abaixo a explicação de cada um.

- **type**: tipo de teste (vu ou sbu);
- **count:** quantidade de usuários ou browsers a ser simulada;
- **duration**: tempo (em segundos) de duração do teste;
- **levels**: Quantidade de níveis dentro do site que o sistema verificará os links;
- **uri**: Url inicial do site;
- **proxy**: Caso desejado, qual proxy será utilizado para conexão com o site;
- **User-Agent**: Define o texto do User-Agent que será enviado em todas as requisições;
- **Cookie**: Texto do cookie passado em todas as requisições;

Execute o aplicativo **LoadTest.exe** e bons testes!

Caso tenha alguma sugestão de gráficos, relatório ou funcionalidade basta me enviar.
