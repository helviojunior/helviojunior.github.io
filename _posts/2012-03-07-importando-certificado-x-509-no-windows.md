---
layout: post
title: Importando certificado X.509 no Windows
date: 2012-03-07 03:50:34.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
- Segurança da Informação
tags:
- certificado digital
- x.509
author: Helvio Junior (m4v3r1ck)
permalink: "/it/security/importando-certificado-x-509-no-windows/"
---

A importação deste certificado na base do Windows tem efeito em todos os aplicativos que consultam esta base como base dos certificados confiáveis. Na lista destes aplicativos estão:

- Internet Explorer
- Google Chrome
- Windows live messager (MSN)

<!--more-->

1 – Abra o Microsoft Managment Console. Vá em **Iniciar > Executa**r e digite **mmc** e clique em OK.

[![mmc]({{ site.baseurl }}/assets/2012/03/image1.png)]({{ site.baseurl }}/assets/2012/03/image1.png)

2 - Na tela do MMC clique em **File (Arquivo)** depois clique em **Add/Remove snap-in... (Adicionar/remover snap-in...)**

3 - Selecione a opção **Certificates (Certificados)** e clique em **Add (Adicionar)**

[![image2]({{ site.baseurl }}/assets/2012/03/image2.png)]({{ site.baseurl }}/assets/2012/03/image2.png)

4 – Selecione a opção **Computer account (Conta de computador)**, selecione a opção **Local Computer (Computador local).**

5 – Na **opção Certificates > Trusted Root Certification Authorities > Certificates (Certificados > Autoridade de certificação raiz confiáveis > Certificados)** clique com o botão direito e clique em **All tasks > Import (Todas as tarefas > Importar).**

**[![image3]({{ site.baseurl }}/assets/2012/03/image3.png)]({{ site.baseurl }}/assets/2012/03/image3.png) [{{ site.baseurl }}/assets/2012/03/image5.png]({{ site.baseurl }}/assets/2012/03/image5.png)**

6 – Selecione o arquivo X.509, ou seja, o arquivo com a extensão **.cer.**

[![image4]({{ site.baseurl }}/assets/2012/03/image4.png)]({{ site.baseurl }}/assets/2012/03/image4.png)[{{ site.baseurl }}/assets/2012/03/image6.png]({{ site.baseurl }}/assets/2012/03/image6.png)

## Importando certificado X.509 no Mozilla Firefox

1 – Clique em **Ferramentas > Opções**

[![image5]({{ site.baseurl }}/assets/2012/03/image5.png)]({{ site.baseurl }}/assets/2012/03/image5.png)

2 – Selecione a opção **Avançado > Criptografia**

[![image6]({{ site.baseurl }}/assets/2012/03/image6.png)]({{ site.baseurl }}/assets/2012/03/image6.png)

3 – Selecione a opção **Certificados,** na tela de certificados selecione a aba **Autoridades** e clique no botão Importar.

[![image7]({{ site.baseurl }}/assets/2012/03/image7.png)]({{ site.baseurl }}/assets/2012/03/image7.png)

4 – Selecione o arquivo X.509, ou seja, o arquivo com a extensão **.cer.**
