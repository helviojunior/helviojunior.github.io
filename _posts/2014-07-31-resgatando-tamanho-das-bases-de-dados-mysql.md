---
layout: post
title: Resgatando tamanho das bases de dados MySQL
date: 2014-07-31 17:56:52.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
- MySQL
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/resgatando-tamanho-das-bases-de-dados-mysql/"
---

Segue abaixo o comando para listar todas as bases de dados do MySQL com seu respectivo tamanho e espaço livre.

```bash
SELECT table_schema "Data Base Name",
sum( data_length + index_length ) / 1024 /
1024 "Data Base Size in MB",
sum( data_free )/ 1024 / 1024 "Free Space in MB"
FROM information_schema.TABLES
GROUP BY table_schema;
```
