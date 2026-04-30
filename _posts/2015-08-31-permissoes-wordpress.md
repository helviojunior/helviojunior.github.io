---
layout: post
title: Permissões WordPress
date: 2015-08-31 23:01:30.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Linux
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/linux/permissoes-wordpress/"
---

Segue abaixo o correto permissionamento de arquivos do WordPress

```bash
chown www-data:www-data -R *          # Let apache be owner
find . -type d -exec chmod 755 {} \;  # Change directory permissions rwxr-xr-x
find . -type f -exec chmod 644 {} \;  # Change file permissions rw-r--r--
```
