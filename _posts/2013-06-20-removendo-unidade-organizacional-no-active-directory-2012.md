---
layout: post
title: Removendo Unidade Organizacional no Active Directory 2012
date: 2013-06-20 11:21:40.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/removendo-unidade-organizacional-no-active-directory-2012/"
---

Por padrão no AD 2012 as OUs (Unidade Organizacional) tem uma proteção de exclusão acidental. Quando este bloqueio está ativado e ao tentar remover uma OU protegida a seguinte mensagem é exibida:

```text
Você não tem privilégios suficiente pata excluir ... ou este objeto está protegido contra exclusão acidental
```

```text
You do not have sufficient privileges to delete ... or this object is protected from accidental deletion
```

<!--more-->

Para realizar a exclusão basta seguir os passos abaixo:

Vá em **Exibir** > **Recursos Avançados**

[![004]({{ site.baseurl }}/assets/2013/06/004.png)]({{ site.baseurl }}/assets/2013/06/004.png)

Clique na OU que deseja excluir e clique em propriedades

[![005]({{ site.baseurl }}/assets/2013/06/005.png)]({{ site.baseurl }}/assets/2013/06/005.png)

Selecione a aba **Objeto** e desmarque a opção **Proteger objeto contra exclusão aciental**

[![006]({{ site.baseurl }}/assets/2013/06/006.png)]({{ site.baseurl }}/assets/2013/06/006.png)

Basta Clicar em OK e depois realizar a exclusão normal da OU.
