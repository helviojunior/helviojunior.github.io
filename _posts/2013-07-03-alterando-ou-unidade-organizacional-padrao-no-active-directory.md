---
layout: post
title: Alterando OU (Unidade organizacional) padrão no Active Directory
date: 2013-07-03 18:15:36.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
tags:
- active directory
- ou
author: Helvio Junior (m4v3r1ck)
permalink: "/it/alterando-ou-unidade-organizacional-padrao-no-active-directory/"
---

Quando você ingressa um computador no domínio por padrão ele é adicionado no container Conputadores (no qual não pode ser utilizado uma GPO neste container), desta forma uma boa pratica é alterar a OU padrão para que todo computador que ingresse no domínio possa receber as diretivas de segurança (GPO) desta OU, como por exemplo, regras de firewall, aplicativos instalados por padrão e etc.

Desta forma este post demonstra como realizar a alteração da OU padrão para ingresso dos computadores.

<!--more-->

Primeiramente é necessário capturar o DN (Distinguished Name) da OU que se deseja manter como padrão.

Abra o aplicativo **Active Directory Users and Computers,** clique em **View** e selecione ****Advanced Features.****

[![001]({{ site.baseurl }}/assets/2013/07/0012.png)]({{ site.baseurl }}/assets/2013/07/0012.png)

Clique com o botão direito na OU que se deseja manter como padrão e selecione **Properties**.

[![002]({{ site.baseurl }}/assets/2013/07/0022.png)]({{ site.baseurl }}/assets/2013/07/0022.png)

Nas propriedades da OU selecione a aba Atribute Editor, selecione a opção **distinguishedName** e clique em **View**.

[![003]({{ site.baseurl }}/assets/2013/07/0032.png)]({{ site.baseurl }}/assets/2013/07/0032.png)

Clique com o botão direito na área selecionada e clique em **Copy**. Posteriormente clique em Cancel  e OK para fechar as janelas.

Execute o PowerShell com permissões de administrador clicando com o botão direito no ícone do PowerShell na barra de tarefas, e selecionando **Run as Administrator**.

[![004]({{ site.baseurl }}/assets/2013/07/0041.png)]({{ site.baseurl }}/assets/2013/07/0041.png)

No Prompt do PowerShell digite o seguinte comando: **redircmp <Container-DN>** onde Container-DN é o **distinguishedName**  da OU copiado, no passo anterior, contendo o caminho completo da OU.

```bash
redircmp "OU=Tutorial,DC=helviojunior,DC=com,DC=br"
```

Caso haja algum espano no nome da sua OU garanta que o **distinguishedName**  estará entre duplas aspas.

Pressione **Enter**.

[![005]({{ site.baseurl }}/assets/2013/07/0052.png)]({{ site.baseurl }}/assets/2013/07/0052.png)

Se o retorno do comando for **Redirection was successful**, o procedimento está completo.
