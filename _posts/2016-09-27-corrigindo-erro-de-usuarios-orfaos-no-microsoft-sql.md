---
layout: post
title: Corrigindo erro de usuários órfãos no Microsoft SQL
date: 2016-09-27 17:23:23.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories: []
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/uncategorized/corrigindo-erro-de-usuarios-orfaos-no-microsoft-sql/"
---

Um Erro muito comum é quando se restaura uma base de dados, ou até mesmo ao anexar uma nova base é que os usuários dessa base perdem i vínculo com o usuário de segurança do Microsoft SQL Server.

Para resolver este problema tem um comando simples e rápido.

Estes de mais nada garanta que o usuário exista no SQL server e depois execute o comando abaixo dentro da base de dados desejada.

```sql
EXEC sp_change_users_login 'Auto_Fix', 'usuario_orfao'
```
