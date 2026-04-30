---
layout: post
title: Criando usuário no MySQL
date: 2014-11-06 12:11:54.000000000 -02:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- MySQL
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/mysql/criando-usuario-mysql/"
---

### Criando usuário

```bash
CREATE USER 'nome_do_usuario'@'localhost' IDENTIFIED BY 'senha_do_usuario';
```

Este exemplo demostra como criar um usuário que terá permissão de acesso somente da própria maquina (localhost) e definindo sua senha.

Veremos no próximo exemplo como criar um usuário que tenha permissão de acesso (como origem do acesso) vindo de qualquer endereço IP.

```bash
CREATE USER 'nome_do_usuario'@'%' IDENTIFIED BY 'senha_do_usuario';
```

### Definindo permissão de acesso a uma base de dados

Neste primeiro exemplo veremos como definir as permissões para que o usuário tenha acesso total porém somente a uma base de dados e o acesso vindo da própria maquina.

```bash
GRANT ALL PRIVILEGES ON database_name.* TO 'nome_do_usuario'@'localhost';
```

Seguindo a mesma lógica, será definido a permissão porém para acesso a partir de qualquer IP.

```bash
GRANT ALL PRIVILEGES ON database_name.* TO 'nome_do_usuario'@'%';
```

### Definindo permissão de acesso como root

Por fim veremos como dar permissão como root a este usuário mas com o acesso vindo da própria maquina.

```bash
GRANT ALL PRIVILEGES ON *.* TO 'nome_do_usuario'@'localhost';
```

Seguindo a mesma lógica, será definido a permissão porém para acesso a partir de qualquer IP.

```bash
GRANT ALL PRIVILEGES ON *.* TO 'nome_do_usuario'@'%';
```
