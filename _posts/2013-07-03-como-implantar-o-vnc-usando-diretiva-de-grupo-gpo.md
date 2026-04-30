---
layout: post
title: Como implantar o VNC usando Diretiva de Grupo (GPO)
date: 2013-07-03 15:47:46.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/como-implantar-o-vnc-usando-diretiva-de-grupo-gpo/"
---

O VNC é um aplicativo de gerência remota de equipamentos (teclado, mouse e monitor), seu funcionamento é bem simples. Instala-se um servidor na maquina que se deseja gerenciar e através de um cliente se conecta neste servidor e realiza as atividades necessárias. A grande diferença entre o VNC e o Remote Desktop é que o VNC captura a tela atual do usuário sem desconectar a sessão do usuário de forma que o usuário pode acompanhar o que o gestor remoto está realizando.

O que veremos neste post é como realizar a configuração de publicação em várias maquinas do domínio com Microsoft Active Directory através de GPO. Pois este procedimento ajuda em muito a instalação em diversas maquinas simultaneamente.

<!--more-->

Requisitos

- Domínio Microsoft Active Directory;
- [UltaVNC](http://www.uvnc.com/downloads/ultravnc.html)
- [VNCed UltraVNC MSI Creator](http://vnced.sourceforge.net/downloads.php)
- Group Policy Management Console

Primeiramente acesse a página do VNCed Ultra MSI Creator e verifique a versão suportada do UltraVNC, no momento da elaboração deste post é a versão 1.0.9.6.1, desta forma será realizado com esta versão.

Primeiro realize o download e instalação do UltraVNC 1.0.9.6.1 na sua maquina (pode ser somente o viewer).

Depois, extraia os arquivos do VNCed e execute o arquivo *UltraVNC 1.0.9.6.1 - STEP1.config_ultravnc_settings.bat*. Será aberto uma janela para que você selecione as configurações:

[![001]({{ site.baseurl }}/assets/2013/07/0011.png)]({{ site.baseurl }}/assets/2013/07/0011.png)

Nesta janela você deve definir sua senha e outras opções desejadas, depois clique em OK.

Para habilitar autenticação por grupo de usuários do domínio, na aba segurança selecione a opção *Require MS logon*, clique no botão *Configure MS Logon Groups* e selecione os grupos que terão permissão para autenticar nas maquinas cliente.

Agora execute o arquivo *UltraVNC 1.0.9.6.1 - STEP2.build_ultravnc_msi.bat*, neste passo será criado um arquivo nomeado *UltraVNC.msi*.

Os passos a seguir são necessários para a publicação deste msi através da GPO. Primeiramente copie o MSI gerado no passo anterior para seu servidor de compartilhamento. É necessário que os clientes onde serão instalados o VNS tenham acesso a este compartilhamento. Ex.: *\\FILESERVER\GPINSTALLS*

Agora com  msi criado, salvo no compartilahento e com acesso aos clientes vá em seu servidor do AD (Active Directory), abra o *Group Policy Managment*, selecione o domínio e a OU (unidade organizacional) onde estão suas maquinas, clique com o botão direito (na OU) e selecione a opção *Create a GPO in this domain, and Link it here...*

[![002]({{ site.baseurl }}/assets/2013/07/0021.png)]({{ site.baseurl }}/assets/2013/07/0021.png)

Digite o nome da sua nova GPO e clique em OK.

[![003]({{ site.baseurl }}/assets/2013/07/0031.png)]({{ site.baseurl }}/assets/2013/07/0031.png)

Clique com o botão direito no nome da GPO e clique em *Edit*. Agora vá em *Computer Configuration -> Policies -> Software Settings -> Software Installation*, clique com o botão direito e crie um novo pacote, navegue em sua rede definindo o caminho completo do seu pacote msi*\\FILESERVER\GPINSTALLS\*UltraVNC.msi,** clique em **ok** e depois em **Assigned.**

[![005]({{ site.baseurl }}/assets/2013/07/0051.png)]({{ site.baseurl }}/assets/2013/07/0051.png)

Você também pode necessitar criar regras de firewall liberando o acesso a portas do VNC. Para isso vá em *Configuration -> Policies -> Administrative Templates -> Network -> Network Connections -> Windows Firewall -> Standard Profile*.

Edite a opção *Windows Firewall: Allow local port exceptions* para *Enabled.*

Abra a opção *Windows Firewall: Define inbound port exceptions,* selecione a opção *Enabled* e posteriormente clique no botão *Show* em *Define port exceptions* e adicione a exceção para a porta do VNC (5900) com o texto **5900:TCP:x.x.x.x/x:enabled:VNC** onde **x.x.x.x/x** é o escopo de rede que poderá acessar o VNC**.**

[![008]({{ site.baseurl }}/assets/2013/07/0081.png)]({{ site.baseurl }}/assets/2013/07/0081.png)

Agora basta entrar no cliente e executar o comando *GPUpdate /force* para atualizar a política.
