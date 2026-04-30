---
layout: post
title: Restaurando MySQL com informações de progresso
date: 2017-12-29 13:22:43.000000000 -02:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- MySQL
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/mysql/restaurando-mysql-com-informacoes-de-progresso/"
---

Uma das formas mais comuns de realização de Backup de uma base de Dados MySQL é através do mydqldump, porém quando necessita restaurar uma base de dados você fica sem um status de quanto ja foi processado para saber a final quanto tempo levará o processo todo.

Este artigo entende que fizemos o backup com mysqldump e o arquivo está compactado com Zgip.

Sendo assim a forma mais comum de realizar um restore é com um dos comandos abaixo:

```bash
cat backup.sql.gz | grep gunzip | mysql -u usuario -p
ou
zcat backup.sql.gz | mysql -u usuario -p
```

Porém nestes casos não temos nenhum status de quanto ja foi restaurado, sendo assim podemos usar a ferramenta DD (ja abordada em outro post aqui) para realizar a leitura do arquivo, e assim utilizar um sinal do linux para saber o quanto o DD ja leu o arquivo. Confuso? Então vamos aos comandos que tudo ficará mais claro.

Comando de restauração:

```bash
dd if=backup.sql.gz | grep gunzip | mysql -u usuario -p
```

Até aqui nenhuma novidade, só substituímos o cat pelo DD, a novidade vem agora, podemos usar o sinal -USR1 no processo do DD que ele imprimirá em tela o quanto ja leu do arquivo backup.sql.gz.

Primeiramente vamos descobrir o Process ID (PID) do DD com o comando:

```bash
ps aux | grep -i "command\|dd if" | grep -v mysql | grep -v grep
```

O Resultado do comando será algo parecido com a imagem abaixo:

[![ps]({{ site.baseurl }}/assets/2017/12/ps.jpg)]({{ site.baseurl }}/assets/2017/12/ps.jpg)

Agora de posse do PID podemos executar o comando mágico que trará quanto o nosso DD ja leu do arquivo

```bash
kill -USR1 26711
```

Quando executado este comando, na janela em que está sendo executado o DD ele irá trazer um resultado semelhante a imagem abaixo:

[![kill]({{ site.baseurl }}/assets/2017/12/kill.jpg)]({{ site.baseurl }}/assets/2017/12/kill.jpg)

Agora para fechar com chave de outro vamos criar um comando que fica enviando este sinal a nosso processo de tempo em tempo.

```bash
 while :; do kill -USR1 26711; sleep 30; done
```
