---
layout: post
title: Integrando SafeID para importar usuários através de arquivo CSV
date: 2014-04-15 13:00:16.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- SafeID
- SafeTrend
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/safetrend/safeid/integrando-safeid-para-importar-usuarios-atraves-de-csv/"
---

O Objetivo deste post é demonstrar passo a passo como realizar toda a configuração do SafeID (gestão de identidades e acessos - identity and access manager) para a importação e cadastro de usuário no sistema com arquivo CSV.

<!--more-->

## Entendendo o SafeID

Antes da configuração propriamente dita é necessário entender um pouco da estrutura de dados do SafeID, através do post [Entendendo o SafeID](http://www.helviojunior.com.br/uncategorized/entendendo-o-safeid/)

Depois da leitura deste post com as informações básicas do SafeID podemos iniciar com as configurações.

Para que este post seja o mais completo possível será utilizado um ambiente totalmente linpo, ou seja recém instalado.

## 1 - Configurando o proxy

Acesse o painel de administração do SafeID, clique em **Menu** > **Proxy** > **Gerenciador de proxies**

[![001-admin]({{ site.baseurl }}/assets/2014/04/001-admin.png)]({{ site.baseurl }}/assets/2014/04/001-admin.png)

Depois clique no botão **Novo Proxy**

[![002-proxy]({{ site.baseurl }}/assets/2014/04/002-proxy.png)]({{ site.baseurl }}/assets/2014/04/002-proxy.png)

Digite o nome do proxy e clique em Adicionar.

Para instalar este proxy em seu servidor clique no link **Download (instalador e configuração)** para realizar o download dos executáveis e configuração do proxy.

[![004-proxy2]({{ site.baseurl }}/assets/2014/04/004-proxy2.png)]({{ site.baseurl }}/assets/2014/04/004-proxy2.png)

Dentro do seu servidor descompacte o arquivo ZIP gerado em um diretório de preferência.

[![004-proxy3]({{ site.baseurl }}/assets/2014/04/004-proxy3.png)]({{ site.baseurl }}/assets/2014/04/004-proxy3.png)

Execute o arquivo **_Install.cmd** para realizar a instalação do proxy como serviço.

Reinicie o serviço do proxy

[![004-proxy4]({{ site.baseurl }}/assets/2014/04/004-proxy4.png)]({{ site.baseurl }}/assets/2014/04/004-proxy4.png)

Após reiniciado se tudo tiver correto na console de administração você verá a informação que o proxy está on-line, ou seja conectado ao servidor.

[![004-proxy]({{ site.baseurl }}/assets/2014/04/004-proxy1.png)]({{ site.baseurl }}/assets/2014/04/004-proxy1.png)

## 2 - Configurando os campos

Os campos serão utilizados para que possamos mapear os dados de entrada (neste exemplo as colunas do arquivo CSV) com o padrão do SafeID.

No painel de administração do SafeID, clique em **Menu** > **Campos** > **Gerenciador de campos**

[![005-fields]({{ site.baseurl }}/assets/2014/04/005-fields.png)]({{ site.baseurl }}/assets/2014/04/005-fields.png)

Na tela acima podemos observar a listagem dos campos cadastrados por padrão no sistema, caso deseje adicionar outro campo clique no botão **Novo campo.** Na configuração de cada campo há 2 opções: Público e permite edição, a primeira indica de outros usuários poderão visualizar essa informação, e o segundo se o usuário em questão poderá alterar essa informação.

## 3 - Configurando o recurso

Recurso é o nome dado para o sistema de origem/destino de onde os dados serão importados ou para onde serão publicados.

No painel de administração do SafeID, clique em **Menu** > **Recurso**> **Novo recurso**

[![006-recurso]({{ site.baseurl }}/assets/2014/04/006-recurso.png)]({{ site.baseurl }}/assets/2014/04/006-recurso.png)

Na tela de criação de recurso será necessário informar 3 campos, o primeiro é o nome do recurso, segundo é o contexto do qual ele faz parte e por último qual será o proxy que fará a comunicação entre o SafeID e este recurso.

## 4 - Integrando o recurso *versus* plugin

A tela final de configuração, também a mais complexa, contém diversos passos para que seja realizada a integração do recurso com o SafeID.

Neste passo informaremos através de qual plugin desejamos realizar a integração entre o SafeID com o recurso cadastrado no passo anterior.

Esta tela tem diversas configurações que serão explicadas uma a uma a seguir.

### 4.1 - Configurações gerais

Para criar este vínculo, clique em **Menu** > **Recurso x plugin**> **Novo recurso x plugin**

[![007-resourceplugin]({{ site.baseurl }}/assets/2014/04/007-resourceplugin.png)]({{ site.baseurl }}/assets/2014/04/007-resourceplugin.png)

Nesta tela há o início da configuração, onde existe 3 campos a serem cadastrados: O primeiro é o recurso, seguido do plugin (no nosso caso o plugin de integração com CSV) e por último o domínio de e-mail.

Após informar estes campos clique em **Salvar e continuar**.

Logo após serão exibidas diversas informações e opções de configuração, porém neste momento iremos nos ater a finalizar as configurações gerais.

[![008-resourceplugin]({{ site.baseurl }}/assets/2014/04/008-resourceplugin.png)]({{ site.baseurl }}/assets/2014/04/008-resourceplugin.png)

Segue abaixo a explicação de cada uma destas opções:

- **Permite adição de entidade:** Como sta integração que estamos realizando tem por objetivo capturar os usuários do CSV e importa-los no SafeID, será necessário habilitar que os dados vindos deste recurso versus plugin possa inserir entidade. Caso esta opção esteja desabilitada o SafeID não será capaz de adicionar novos usuários (Entidades), porém caso exista uma entidade que se enquadre nas regras (mapeamento de campos) que serão configuradas posteriormente, o SafeID irá criar uma nova identidade na entidade existente;
- **Criação de login:** Permite que o SafeID crie um login de usuário caso não exista;
- **Criação de e-mail:** Permite que o SafeID crie um e-mail de usuário caso não exista;
- **Habilita importação:** Habilita que o SafeID resgate dados através deste plugin.

Após selecionas as opções desejadas clique em **Salvar**.

Agora clique na opção **Saída** e depois em **Editar**

[![009-resourceplugin]({{ site.baseurl }}/assets/2014/04/009-resourceplugin.png)]({{ site.baseurl }}/assets/2014/04/009-resourceplugin.png)

Realize as configurações conforme desejado e clique em **Salvar**

[![010-resourceplugin]({{ site.baseurl }}/assets/2014/04/010-resourceplugin.png)]({{ site.baseurl }}/assets/2014/04/010-resourceplugin.png)

Para finalizar as configurações gerais clique em **Campos** e posteriormente **Editar** e configure os campos conforme abaixo e clique em **Salvar**

[![011-resourceplugin]({{ site.baseurl }}/assets/2014/04/011-resourceplugin.png)]({{ site.baseurl }}/assets/2014/04/011-resourceplugin.png)

### 4.2 - Entendendo a tela de recurso *versus* plugin

Nesta tela tem-se basicamente 2 quadros, o primeiro com informações das configurações e status importantes, e na segunda as configurações/ações possíveis

[![012-resourceplugin]({{ site.baseurl }}/assets/2014/04/012-resourceplugin.png)]({{ site.baseurl }}/assets/2014/04/012-resourceplugin.png)

[![013-resourceplugin]({{ site.baseurl }}/assets/2014/04/013-resourceplugin.png)]({{ site.baseurl }}/assets/2014/04/013-resourceplugin.png)

Segue a explicação de cada um dos itens do quadrante de informações, posteriormente realizaremos as configurações dos que ainda não realizamos:

1. Status: Mostra o status atual deste recurso x plugin;
2. Status do recurso: Mostra o status do recurso cadastrado;
3. Status do proxy: Mostra se o proxy está online, ou seja, conectado neste momento;
4. Configurações gerais: Mostra se as configurações estão completas ou se falta algo. Obrigatório estar completa para que o plugin possa ser habilitado e funcione corretamente.
5. Parâmetros do plugin: Cada plugin necessita e exige uma configuração diferente, desta forma essa tela será diferente para cada um dos plugins que o sistema integra. Obrigatório estar completa para que o plugin possa ser habilitado e funcione corretamente.
6. Mapeamento de campos: Nesta tela que iremos efetivamente mapear os campos do sistema remoto com os campos internos do SafeID. Estes campos servem para que haja uma padronização e entendimento das informações obtidas no sistema remoto. Obrigatório estar completa para que o plugin possa ser habilitado e funcione corretamente.

O quadrante de configurações/ações estão os links para cada uma das ações e configurações possíveis para este recurso x plugin.

### 4.3 - Parâmetros do plugin

[![014-resourceplugin]({{ site.baseurl }}/assets/2014/04/014-resourceplugin.png)]({{ site.baseurl }}/assets/2014/04/014-resourceplugin.png)

Conforme descrito anteriormente cada plugin exige uma configuração diferenciada nesta tela. Para o plugin de CSV há somente 2 configurações:

- Diretório de importação: Local físico, no servidor que está instalado o proxy, de onde os arquivos CSV serão lidos e importados;
- Delimitador: Texto delimitador de colunas do CSV.

Clique em editar e configure essa tela conforme a imagem abaixo e posteriormente clique em **Salvar**

[![015-resourceplugin]({{ site.baseurl }}/assets/2014/04/015-resourceplugin.png)]({{ site.baseurl }}/assets/2014/04/015-resourceplugin.png)

Dentro do servidor do proxy crie o diretório **c:\demonstracao\** e insira um arquivo nomeado **teste.csv** com o seguinte conteúdo

```text
nome,login,email,rg
Helvio Junior,hjunior,hjunior@safeid.com.br,001002003
Maria da silva,msilva,msilva@safeid.com.br,004005006
João de lima,jlima,jlima@safeid.com.br,007008009
```

[![016-resourceplugin]({{ site.baseurl }}/assets/2014/04/016-resourceplugin.png)]({{ site.baseurl }}/assets/2014/04/016-resourceplugin.png)

### 4.4 - Mapeamento de campos

Para mapeamento de campos há 2 opções:

- O mapeamento manual onde é necessário conhecer exatamente os parâmetros (campos) do sistema que estamos integrando;
- A opção automatizada onde o SafeID, através do seu proxy, se conecta no sistema que estamos integrando e coleta essas informações.

#### **Mapeamento manual**

Dentro do recurso x plugin clique no link **Mapeamento de campos,** depois no botão **Editar**

[![017-resourceplugin]({{ site.baseurl }}/assets/2014/04/017-resourceplugin.png)]({{ site.baseurl }}/assets/2014/04/017-resourceplugin.png)

Digite o nome do campo cadastrado no SafeID e selecione o campo desejado. (Caso deseje cadastrar um novo campo basta ir em Menu > Campos > Novo Campo)

[![018-resourceplugin]({{ site.baseurl }}/assets/2014/04/018-resourceplugin.png)]({{ site.baseurl }}/assets/2014/04/018-resourceplugin.png)

Ao selecionar o campo desejado as opções do campo serão exibidas. Segue a explicação de cada uma das opções do mapeamento do campo:

- Campo do recurso: nome do campo exatamente como o sistema integrado informa (este campo diferencia maiúsculo de minúsculo)
- É um identificador: Indica que o campo é um identificador no sistema integrado;
- É senha: Indica que o campo detém uma senha, ao importar a senha do usuário será sempre substituída por essa deste campo;
- É um campo único: Indica que o campo é único, ou seja, não pode haver duplicidade dentre da base do SafeID no mesmo contexto.

Obs.: Para que o SafeID identifique se os dados importados são de uma entidade (usuário) existente ou de uma nova entidade, ele utiliza estes campos marcados como Identificador e campo único.

Para completar a operação basta clicar em **Salvar**

#### **Mapeamento automatizado**

Para que este mapeamento funcione corretamente as configurações gerais e os parâmetros de configuração devem estar configurados e corretos, bem como o proxy precisa estar on-line.

Dentro do recurso x plugin clique no link **Mapeamento de campos,** depois no botão **Busca automática** e depois no botão **Iniciar nova busca**

Neste momento o procedimento de busca será iniciado e a informação de aguardando as informações do proxy será informado

[![020-resourceplugin]({{ site.baseurl }}/assets/2014/04/020-resourceplugin.png)]({{ site.baseurl }}/assets/2014/04/020-resourceplugin.png)

Aguarde alguns instantes e atualize a tela. Caso o procedimento apresente erro uma informação de erro será exibida e os detalhes do erro poderão ser vistos no botão de Log, caso o procedimento seja realizado com sucesso a tela abaixo será exibida

[![021-resourceplugin]({{ site.baseurl }}/assets/2014/04/021-resourceplugin.png)]({{ site.baseurl }}/assets/2014/04/021-resourceplugin.png)

Para abrir as informações mapeadas clique no botão **Abrir,** uma tabela com as informações mapeadas será exibida. Pode observar que além das colunas (campos do sistema) são exibidos alguns exemplos de valor do campo.

[![022-resourceplugin]({{ site.baseurl }}/assets/2014/04/022-resourceplugin.png)]({{ site.baseurl }}/assets/2014/04/022-resourceplugin.png)

Mapeie os campos conforme desejado e clique em Salvar. Caso haja algum campo que não deseje mapear basta clicar no botão excluir que o mesmo será desconsiderado no mapeamento.

Obs.: É obrigatório a seleção de pelo menos um campo como identificador ou único.

Para o nosso exemplo o seguinte mapeamento foi realizado

[![023-resourceplugin]({{ site.baseurl }}/assets/2014/04/023-resourceplugin.png)]({{ site.baseurl }}/assets/2014/04/023-resourceplugin.png)

### 4.5 - Agendamento

Dentro do recurso x plugin clique no link **Agendamento** e clique no botão **Editar.**

Cadastre o agendamento conforme a tela abaixo e clique em salvar.

[![024-schedule]({{ site.baseurl }}/assets/2014/04/024-schedule.png)]({{ site.baseurl }}/assets/2014/04/024-schedule.png)

### 4.6 - Outras configurações

De configurações obrigatórios são essas demonstradas acima, outras configurações podem ser realizadas como vínculo com função, e regras de bloqueio. Porém estas não serão abordadas neste post.

### 4.7 - Habilitando recurso versus plugin

Estando toda a configuração completa o plugin pode ser habilitado. Para isso ainda dentro do recurso x plugin clique no link **Habilitar**.

## 5 - Teste de importação

Após todas as configurações realizadas ainda dentro do recurso x plugin clique no link **Publicar agora**, para forçar que toda a configuração seja replicada com o proxy.

### 5.1 - Verificando logs

Para verificar se tudo está ocorrendo conforme desejado é possível visualizar os logs do sistema em **Menu** > **Sistema** > **Visualizador de logs do sistema**

Em nosso teste os seguintes logs foram gerados

[![025-logs]({{ site.baseurl }}/assets/2014/04/025-logs.png)]({{ site.baseurl }}/assets/2014/04/025-logs.png)

Pode-se observar:

- O recurso x plugin foi habilitado;
- Depois marcado para realizar a publicação da configuração;
- O Proxy realizou a importação do arquivo com sucesso
- E por último o engine informando que realizou a importação.

### 5.1 - Visualizando usuários

Como em nosso teste todas as importações ocorreram com sucesso podemos visualizar os dados dos usuários (Entidades e Identidades) em **Menu** > **Gerenciador de usuários**

Clicando em um usuário recém importado podemos observar todas suas informações.

[![026-user]({{ site.baseurl }}/assets/2014/04/026-user.png)]({{ site.baseurl }}/assets/2014/04/026-user.png)

## 5 - Dúvidas?

Caso tenha alguma dúvida favor entrar em contato conosco através do link [www.safetrend.com.br/contato/](www.safetrend.com.br/contato/)
