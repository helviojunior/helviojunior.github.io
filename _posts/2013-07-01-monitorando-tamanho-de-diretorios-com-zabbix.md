---
layout: post
title: Monitorando tamanho de diretórios com Zabbix
date: 2013-07-01 18:26:43.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Monitoramento
- Zabbix
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/monitoramento/monitorando-tamanho-de-diretorios-com-zabbix/"
---

Este post mostra como listar todos os subdiretórios dentro de um diretório e monitorar o tamanho destes.

Para isso será necessário a utilização de um aplicativo (escrito por mim) que tem 2 funções: 1 - Listar todos os subdiretórios dentro de um diretório; 2 - Calcular o espaço em disco utilizado por estes diretórios. Este aplicativo chama-se ZabbixDirSize.exe e está disponível aqui ([ZabbixDirSize]({{ site.baseurl }}/assets/2013/07/ZabbixDirSize.zip)), inclusive com código fonte.

<!--more-->

**Configurando o agente**

Edite o arquivo de configuração do agente e adicione as linhas abaixo:

```text
UnsafeUserParameters=1
UserParameter=ds.subdirs[*],C:\Zabbix\ZabbixDirSize.exe --sub-dirs "$1" "$2" "$3" "$4" "$5"
UserParameter=ds.subdirs.size[*],C:\Zabbix\ZabbixDirSize.exe --size "$1"
```

Nas linhas acima criamos 2 chaves **ds.subdirs** e **ds.subdirs.size**, a primeira lista todos os diretórios dentro de um diretório específico e a segunda retorna o tamanho utilizado por um diretório.

A chave **ds.subdirs** está passando até 5 diretórios (pai) para o executável. Caso deseje mais diretórios basta incluir as variaveis no final da linha ($6, $7, etc...)

Edite o caminho do executável **ZabbixDirSize.exe** conforme o seu ambiente. Para que este executável funcione corretamente é necessário estar instalado na maquina o .NET 2.0 ou superior.

Criando o Host no Zabbix, configuração a localização automática de subdiretórios dentro de um diretório específico e criando os itens de captura e gráficos.

Crie o host dentro do Zabbix

[![Inserindo Host]({{ site.baseurl }}/assets/2013/07/001.png)]({{ site.baseurl }}/assets/2013/07/001.png)

Clique no item **Discovery rules**

[![002]({{ site.baseurl }}/assets/2013/07/002.png)]({{ site.baseurl }}/assets/2013/07/002.png)

Clique no item **Create discovery rules**

[![003]({{ site.baseurl }}/assets/2013/07/003.png)]({{ site.baseurl }}/assets/2013/07/003.png)

Configure a regra de descoberta conforme a imagem abaixo, inserindo a chave **ds.subdirs[]** colocando entre colchetes o nome do diretório em que deseja listar todos os subdiretórios. Clique no botão **Save.**

Neste parâmetro pode ser passado mais de um diretório pai, bastando dentro dos colchetes colocar os diretórios separados por virgula, ficando desta forma: **ds.subdirs[d:\dir1,c:\Dir3,d:\dir3]**

[![004]({{ site.baseurl }}/assets/2013/07/004.png)]({{ site.baseurl }}/assets/2013/07/004.png)

Após salvo será aberto a tela conforma a imagem abaixo. Clique em **Item prototypes**.

[![005]({{ site.baseurl }}/assets/2013/07/005.png)]({{ site.baseurl }}/assets/2013/07/005.png)

Clique no botão **Create item prototype**

[![006]({{ site.baseurl }}/assets/2013/07/006.png)]({{ site.baseurl }}/assets/2013/07/006.png)

Configure o item conforme tela abaixo, observando os seguintes items, depois clique em **Save**

- Name: Used space on $1
- Type: Zabbix agent
- Key: ds.subdirs.size[{#DIRPATH}]
- Type information: Numeric (unsigned)
- Data Type: Decimal
- Units: B
- Update interval: 21600
- New application: Directory

[![007]({{ site.baseurl }}/assets/2013/07/007.png)]({{ site.baseurl }}/assets/2013/07/007.png)

Depois clique em **Graph prototype** e clique em **Create graph prototype.** Configure conforme os itens abaixo

- Name: Used space on {#DIRPATH}
- Width: 600
- Height: 340

[![009]({{ site.baseurl }}/assets/2013/07/009.png)]({{ site.baseurl }}/assets/2013/07/009.png)

Depois clique em **Add prototype, s**elecione o item **Used space on {#DIRPATH}**.

[![010]({{ site.baseurl }}/assets/2013/07/010.png)]({{ site.baseurl }}/assets/2013/07/010.png)

Altere o **Draw Style** para **Dashed Line** e clique em **Save**

[![011]({{ site.baseurl }}/assets/2013/07/011.png)]({{ site.baseurl }}/assets/2013/07/011.png)

**Solução de problemas**

Recentemente tivemos alguns reportes de erro no processo de busca e contagem do tamanho, sendo sim fiz algumas alterações na aplicação para melhorar a estratégia de busca bem como de identificação de erros.

Caso encontre algum erro na aplicação basta executa-la conforme o comando abaixo, deste modo será gerado um arquivo de log no mesmo local do executável, conendo o log de processamento e possíveis mensagens de erro.

```text
C:\Zabbix\ZabbixDirSize.exe --sub-dirs --debug c:\diretorio_desejado
C:\Zabbix\ZabbixDirSize.exe --size --debug c:\diretorio_desejado
```

**Timeout em diretórios grandes**

Recebi um feedback bem legal de algumas pessoas que estão usando o aplicativo, de timeout em diretórios grandes. Como solução para este problema implementei uma execução em background onde o aplicativo faz um fork e fica executando até que faça a leitura de todo o diretório para calcular o tamanho. Por segurança o aplicativo controla os seus objetos filhos para evitar que se abra mais de um fork para o mesmo diretório. Após este objeto filho finalizar a leitura do diretório, ele armazena o tamanho em um arquivo texto, para que o aplicativo pai possa realizar a leitura deste valor para o Zabbix.

Para habilitar essa função basta adicionar o parâmetro --bg na linha de comando do aplicativo conforme exemplo abaixo. Esta opção só é válida juntamente com a opção --size.

```text
UserParameter=ds.subdirs.size[*],C:\Zabbix\ZabbixDirSize.exe --size --bg "$1"
```
