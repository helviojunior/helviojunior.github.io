---
layout: post
title: 'Gerenciando grandes bases de dados do BloodHound'
date: 2023-08-21 23:30:00.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Offensive Security
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/offsec/gerenciando-grandes-bases-do-bloodhound/"
excerpt: "Neste post irei descrever um pouco da minha experiencia utilizando o BloodHound, incluindo o principal desafio que encontrei em manipular/importar base de dados grandes. Adicionalmente demonstrarei como resolvi este principal problema (a lentidão de importação dos dados no BloodHound) com a criação de uma ferramenta para manupulação, tratamento e importação dos dados do BloodHound"
---

## Introdução

Muito comumente durante um teste de invasão (Pentest) que envolve ambiente do Microsoft Active Directory (aka AD), utilizamos diversas ferramentas para automatizar e transformar um dado em valor, uma dessas ferramentas é o [BloodHound]( https://github.com/BloodHoundAD/BloodHound). A grande sacada do BloodHound é o fato de obter uma infinidade de informações de um ambiente do Active Directory e os representar de uma forma que deixem de ser apenas informações soltas e as relacione de forma a gerar valor e criar hipóteses de caminhos a serem explorados.
O BloodHound representa os diversos objetos do AD como nós (em inglês Nodes), exemplo, Usuários, Computadores, CPOs, ACLs, ACEs ,entre outros, bem como os seus respectivos relacionamentos são representados como arestas (do inglês Edges), exemplo, MemberOf, Owns, CanRDP, GenericWrite, entre outros. Desta forma é possível identificar os potenciais caminhos para uma cadeia de exploração.
Neste post irei descrever um pouco da minha experiencia utilizando o BloodHound, incluindo o principal desafio que encontrei em manipular/importar base de dados grandes. Adicionalmente demonstrarei como resolvi este principal problema (a lentidão de importação dos dados no BloodHound) com a criação de uma ferramenta para manupulação, tratamento e importação dos dados do BloodHound.


O [GitHub]( https://github.com/BloodHoundAD/BloodHound) do BoodHound o define da seguinte forma:
O BloodHound usa a teoria dos gráficos para revelar os relacionamentos ocultos e muitas vezes não intencionais em um ambiente Active Directory ou Azure. Os invasores podem usar o BloodHound para identificar facilmente caminhos de ataque altamente complexos que, de outra forma, seriam impossíveis de identificar rapidamente. Os defensores podem usar o BloodHound para identificar e eliminar esses mesmos caminhos de ataque. As equipes azul e vermelha podem usar o BloodHound para obter facilmente uma compreensão mais profunda das relações de privilégio em um ambiente Active Directory ou Azure.

Atualmente o BloodHound suporta a extração e tratamento dos dados do Microsoft Active Directory On-Premisses e também do Azure AD. Porém este post foca no procedimento para o AD On-Premisses.

A primeira fase no uso do BloodHound é coletar dados dos servidores do Active Directory através do protocolo LDAP usando um dos coletores disponíveis como o SharpHound (ou as APIs do Azure no caso do AzureHound) e armazená-los em arquivos JSON compactados para reduzir o tamanho do arquivo. Em seguida, esses arquivos podem ser movidos para o sistema no qual a análise será realizada e importados para um banco de dados Neo4j. Por fim, as consultas podem ser realizadas, seja usando a ferramenta BloodHound, outras ferramentas de terceiros ou diretamente usando a linguagem Cypher do Neo4j. Neste artigo vamos passar por essas três etapas.


[![]({{site.baseurl}}/assets/2023/08/ad_001.jpg)]({{site.baseurl}}/assets/2023/08/ad_001.jpg)

## Coletores
A principal ferramenta fornecida com o BloodHound para coletar informações do Active Directory é o SharpHound. SharpHound é um executável .NET 4 que possui diversos parâmetros para configurar quais dados precisam ser coletados. Esses parâmetros influenciam a quantidade de dados coletados e a furtividade da execução. O SharpHound coletará informações do LDAP/LDAPS de um controlador de domínio. Além disso, dependendo dos parâmetros de coleta/enumeração especificados, ele também se conectará a hosts individuais por meio do protocolo RPC usando um `named pipe` (ncacn_np) que ocorre na porta Microsoft-DS (445/TCP) para obter informações sobre membros de grupos locais e usuários conectados .

Além da ferramenta SharpHound, existem várias outras opções para coletar dados conforme listado na tabela abaixo:

| Ferramenta | Linguagem | URL | Notas |
| :---- | :----: | :--- | :--- |
| SharpHound |   .NET   | [https://github.com/BloodHoundAD/SharpHound/](https://github.com/BloodHoundAD/SharpHound/) | Também pode ser refletido/executado em memória
| AzureHound |   PowerShell   | [https://github.com/BloodHoundAD/AzureHound/](https://github.com/BloodHoundAD/AzureHound/) | Especificamente para ambientes do Azure
| SharpHound.ps1 |   PowerShell   | [https://github.com/BloodHoundAD/BloodHound/](https://github.com/BloodHoundAD/BloodHound/) | Disponível na pasta `Collectors`. Utiliza de forma refletida em memória o SharpHouns.exe. Ele expõe a função `Invoke-BloodHound` que chama a função principal do binário SharpHound.
| BloodHound.py |   Python   | [https://github.com/fox-it/BloodHound.py/](https://github.com/fox-it/BloodHound.py/) | Implementação em Python do SharpHound.
| ADExplorerSnapshot.py |   Python   | [https://github.com/c3c/ADExplorerSnapshot.py/](https://github.com/c3c/ADExplorerSnapshot.py/) | Converte os Snapshots do Sysinternals ADExplorer em arquivos JSON compatíveis com BloodHound.
| BOFHound |   Python   | [https://github.com/fortalice/bofhound/](https://github.com/fortalice/bofhound/) | Converte os logs gerados pelos ldapsearch BOF e pyldapsearch em arquivos JSON compatíveis com BloodHound.


Depois de coletar os arquivos de entrada necessários, podemos passar para a próxima etapa: importar os arquivos para o BloodHound.

## Importando

Depois de configurar o BloodHound com o back-end do banco de dados do Neo4j, conforme descrito na seção Instalação em https://bloodhound.readthedocs.io/, os dados coletados podem ser importados.

A maneira usual de importar é simplesmente iniciar a GUI do BloodHound e arrastar os arquivos JSON e/ou zip sobre a janela principal do aplicativo. Como alternativa, o botão Importar à direita pode ser usado para selecionar os arquivos que deseja importar.

Durante o processo de importação, o BloodHound lê o JSON e os traduz em instruções Cypher `CREATE` que criam os vários nós e arestas no banco de dados gráfico Neo4j. Os nós (*nodes*) representam objetos como `Computadores`, `Usuários`, `Grupos`, `GPOs`, etc. com seus respectivos atributos, enquanto as arestas (*edges*) representam as relações como `MemberOf`, `Owns`, `WriteDacl`, `CanRDP`, etc.

A importação geralmente funciona bem, porém às vezes falha. Nesse caso, uma solução pode ser experimentar uma versão diferente do BloodHound que, às vezes, de alguma forma resolve magicamente os problemas de importação. Estas versões do BloodHound também podem ser perfeitamente instaladas lado a lado. Se os arquivos ainda não forem importados, pode ser que haja algum outro problema.


## Dados fictícios

*Nota:* Caso você não tenha um um ambiente do Active Directory disponível, mas ainda gostaria de realizar as consultas Cypher (discutidas na seção Consultas), você também pode carregar alguns dados fictícios no BloodHound usando duas possibilidades:

### Opção 1 - ferramenta DBCreator.py, que pode ser instalada da seguinte maneira:

```bash
git clone https://github.com/BloodHoundAD/BloodHound-Tools/
cd BloodHound-Tools/DBCreator
pip install -r requirements.txt
```

Depois de instalado, o script pode simplesmente ser iniciado para abrir um prompt interativo. No prompt, o comando `dbconfig` pode ser usado para configurar a URL, nome de usuário e senha de sua instância Neo4j. Após esta configuração, conecte-se ao banco de dados usando o comando `connect`. Para criar e inserir os dados fictícios use o comando `generate`. 

### Opção 2 - importando a base do Neo4J:

*Fonte:* https://github.com/BloodHoundAD/BloodHound/issues/336

```bash
cd /tmp/
curl -LO https://github.com/BloodHoundAD/BloodHound/archive/ec277d027cb2cf1e690c3afeb437f9f7fae39fef.zip
unzip ec277d027cb2cf1e690c3afeb437f9f7fae39fef.zip
DATA=`grep -oE '^dbms.directories.data[ =]{1,3}(.*)$' /etc/neo4j/neo4j.conf | cut -d'=' -f2 | tr -d ' '`
mkdir -p "${DATA}/databases/bloodhoundexampledb.db"
rm -rf "${DATA}/transactions/bloodhoundexampledb.db/"
rsync -av BloodHound-ec277d027cb2cf1e690c3afeb437f9f7fae39fef/BloodHoundExampleDB.db/* "${DATA}/databases/bloodhoundexampledb.db"
```

Edite o arquivo de configuração `/etc/neo4j/neo4j.conf`, e inclua/edite a linha abaixo
```bash
dbms.default_database=bloodhoundexampledb.db
dbms.databases.allow_upgrade=true
```

Reinicie o o Neo4J


## Arquivos/ambientes grandes

Comumente nos testes que realizo me deparo com ambientes grandes do AD, que consequentemente geram um volume alto de dados e arquivos de JSON igualmente grandes. E como ja comentei acima, a maneira usual de importar é simplesmente iniciar a GUI do BloodHound e arrastar os arquivos JSON e/ou zip sobre a janela principal do aplicativo, porém da forma com que o importador foi estruturado e desenhado, além de consumir um volume grande de memória ele é extremamente lento (principalmente com arquivos grandes).


Minha primeira tentativa de resolver o problema de importação foi usar o script [bloodhound-importer.py](https://github.com/fox-it/bloodhound-import), no entanto, apenas o formato de dados BloodHound v3 é suportado atualmente, enquanto os arquivos que geramos atualmente são de versões superiores (geralmente v4 ou superior). 

Descobri mais tarde, o formato do arquivo não tem muitas diferenças, mas nem primeiro momento tentei localizar outras soluções para o meu problema, inclusive chegando ao artigo original em que me basei para escrever este post. Basicamente o autor divide o arquivo JSON em vários arquivos menores. Estratégia essa que não me ajudou muito, pois continuava com o problema de lentidão na importação. 


## Nascimento do knowsmore

Com o problema de lentidão na importação e soluções que não me ajudaram muito eu decidi entender mais a fundo a estrutura dos arquivos JSON e escrever o meu próprio importador.

Durante os meus testes de invasão, sempre realizo os seguinte procedimento ao final do comprometimento do AD

1. Extração de todos os hashes através do ntds.dit ou DCSync;
2. Geração de uma wordlist customizada com o nome do cliente (com as senhas mais comuns, ex.: Cliente@2023)
3. Quebra dos hashes (usando hashcat) com a wordlist customizada + senhas encontradas durante o teste + wordlist comuns de marcado (listadas abaixo).

*Minhas wordlists preferidas*

1. [hashesorg2019](https://weakpass.com/wordlist/1851)
2. [weakpass_2](https://weakpass.com/wordlist/1863)

Sempre faço isso para poder gerar os dados de como está a segurança/entropia geral do ambiente do cliente. Por mais que simples, os clientes sempre se surpreendem e amam essa informação.

```
[?] General Statistics
+-------+----------------+-------+
|   top | description    |   qty |
|-------+----------------+-------|
|     1 | Total Users    | 95369 |
|     2 | Unique Hashes  | 74299 |
|     3 | Cracked Hashes | 23177 |
|     4 | Cracked Users  | 35078 |
+-------+----------------+-------+

 [?] General Top 10 passwords
+-------+-------------+-------+
|   top | password    |   qty |
|-------+-------------+-------|
|     1 | password    |  1111 |
|     2 | 123456      |   824 |
|     3 | 123456789   |   815 |
|     4 | guest       |   553 |
|     5 | qwerty      |   329 |
|     6 | 12345678    |   277 |
|     7 | 111111      |   268 |
|     8 | 12345       |   202 |
|     9 | secret      |   170 |
|    10 | sec4us      |   165 |
+-------+-------------+-------+

 [?] Top 10 weak passwords by company name similarity
+-------+--------------+---------+----------------------+-------+
|   top | password     |   score |   company_similarity |   qty |
|-------+--------------+---------+----------------------+-------|
|     1 | company123   |    7024 |                   80 |  1111 |
|     2 | Company123   |    5209 |                   80 |   824 |
|     3 | company      |    3674 |                  100 |   553 |
|     4 | Company@10   |    2080 |                   80 |   329 |
|     5 | company10    |    1722 |                   86 |   268 |
|     6 | Company@2022 |    1242 |                   71 |   202 |
|     7 | Company@2024 |    1015 |                   71 |   165 |
|     8 | Company2022  |     978 |                   75 |   157 |
|     9 | Company10    |     745 |                   86 |   116 |
|    10 | Company21    |     707 |                   86 |   110 |
+-------+--------------+---------+----------------------+-------+
```

Foi neste momento em que decidi agregar na mesma ferramenta os dados vindos do BloodHound, para que o próprio cliente possa verificar informações como senhas fracas que foram apontadas em um relatório anterior e ainda não foram trocadas (uma vez que uma das informações vindas nos dados do BloodHound é a data da troca da senha).

## KnowsMore

Durante o desenvolvimento do KnowsMore, diversos problemas foram encontrados como:

* Entendimento (atualizado) de como os dados são importados e relacionados (pois é o importador que cria os nós e arestas)
* Caractéres não ASCII vindos no JSON
* Trabalhando com arquivos grandes
* Trabalhar com versões diferentes de coletores (v3, v4), uma vez que pequenas diferenças são geradas nos arquivos JSON


Desta forma em minha pesquisa se baseei muito no próprio código fonte do BloodHound [util.js](https://github.com/BloodHoundAD/BloodHound/blob/master/src/js/utils.js) para criar o meu próprio importador. Desta forma eu coloquei as seguintes premissas para o importador:

1. Ser rápido (pois a lentidão foi principal problema que me motivou a começar este trabalho)
2. Importar os dados de forma fidedigna (para não correr o risco de não encontrar um caminho viável para o comprometimento em virtude de falha no meu software)
3. Ser retro-compatível, ou seja, permitir importar dados das versões antigas dos coletores em banco de dados/BloodHound mais atuais.
4. Ser uma ferramenta em que o Blue Team, Auditoria e outros times interessados, possam utilizar para auditar o seu próprio ambiente.

Desta forma o KnowsMore nasceu e atualmente inclui as seguintes funcionalidades:

* [x] Importação dos hashes NTLM do txt vindo do output .ntds (gerado pelo CrackMapExec ou secretsdump.py)
* [x] Importação direta dos hashes NTLM pelos arquivos NTDS.dit e SYSTEM
* [x] Importar e cruzar os hashes NTLM quebrados pelo hashcat
* [x] Importação dos arquivos BloodHound ZIP ou JSON
* [X] Ser um `BloodHound importer` (importar os arquivos JSON para Neo4J sem a interface do BloodHound)
* [x] Analisar a qualidade das senhas quebradas (tamanho , minúsculo, maiusculo, numero, caracteres especiais e caracteres latinos)
* [x] Analisar a similatiedade da senha com o nome da empresa e nome do usuário
* [x] Busca rápida por usuários, senhas e hashes durante o teste
* [x] Exportação para a base de dados do BloodHound (Neo4j) os objetos com as senhas quebradas como 'owned object'
* [x] Exportação para SIEM como Slunk e ELK
* [x] Muito mais...

Para o processo de importação dos arquivos JSON do BloodHound (Objeto deste post) o KnowsMore segue o seguinte fluxo:

1. Criação de uma base de dados local
2. Importação dos arquivos JSON para sua base de dados local na seguinte ordem
   1. Domains
   2. GPOs
   3. OUs
   4. Groups
   5. Computers
   6. Users
3. Exportação (Sync) para o banco de dados do Neo4J

### Instalando o KnowsMore

```bash
pip3 install --upgrade knowsmore
```

### Criando base de dados local

```bash
knowsmore --create-db
```

### Importando arquivos JSON

Embora você possa importar um arquivo JSON diretamente, recomendo realizar a importação através do arquivo ZIP inteiro, pois o KnoesMore irá otimizar a ordem de importação visando um melhor correlacionamento dos dados.

```bash
# Bloodhound ZIP File
knowsmore --bloodhound --import-data ~/Desktop/client.zip

# Bloodhound JSON File
knowsmore --bloodhound --import-data ~/Desktop/20220912105336_users.json
```

### Exportando (sincronizando) os dados para o banco de dados Neo4J do BloodHound

```bash
# Bloodhound ZIP File
knowsmore --bloodhound --sync 10.10.10.10:7687 -d neo4j -u neo4j -p 12345678
```

*Nota:* Para que você possa interagir com o Neo4J remotamente é necessário alterar o seu arquivo de configuração `/etc/neo4j/neo4j.conf` conforme a linha abaixo e reiniciar o seu serviço.

```
server.bolt.listen_address=0.0.0.0:7687
``` 

### Marcando usuário como comprometido

Independente de como, ao ser identificado uma senha de usuário você pode indicar ao KnowsMore que este usuário foi comprometido através do comando abaixo:

```bash
knowsmore --user-pass --username administrator --password Sec4US@2023

# ou adicionando o nome da empresa

--company sec4us --user-pass --username administrator --password Sec4US@2023 --company sec4us
```

Posteriormente é possível sincronizar com o Neo4J

```bash
knowsmore --bloodhound --mark-owned 10.10.10.10 -d neo4j -u neo4j -p 123456
```

## Conslusão

BloodHound é uma ferramenta muito poderosa para atacantes e defensores identificarem caminhos não intencionais em ambientes do Active Directory. Isso é facilitado pelo banco de dados de gráficos Neo4j, que pode ser consultado diretamente usando o Cypher para extrair e pós-processar eficientemente qualquer informação para que possa ser usada pelos atacantes, administradores e defensores para aumentar o jogo contínuo de ataque e defesa.

O ódigo fonte do KnowsMore pode ser encontrado no meu GitHub

https://github.com/helviojunior/knowsmore

Obrigado pela leitura e espero que você consiga usar alguns dos truques em suas futuras atribuições do Active Directory!
