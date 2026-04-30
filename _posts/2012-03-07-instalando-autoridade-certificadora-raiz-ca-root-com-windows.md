---
layout: post
title: Instalando autoridade certificadora raiz (CA Root) com windows
date: 2012-03-07 13:08:58.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
- Segurança da Informação
tags:
- autoridade certificadora
- ca
- certificate authority
- openssl
- windows
author: Helvio Junior (m4v3r1ck)
permalink: "/it/security/instalando-autoridade-certificadora-raiz-ca-root-com-windows/"
---

1 - Para efetuar a instalação da Autoridade certificadora (CA - Certificate Authority) vá até o Windows 2003, entre no **Painel de controle**, selecione a opção de **Adicionar e remover programas** e clique no item **Adicionar/remover componentes do Windows**. Ao aparecer a lista de opções, selecione a opção **“Certificate services”** e clique em **“next”**. Se for questionado com relação à instalação do IIS (Internet Information Services), selecione a opção de instalar, pois será necessário para que possa ser feito as requisições e downloads dos certificados.

<!--more-->

[![low_image2]({{ site.baseurl }}/assets/2012/03/low_image21.jpg)]({{ site.baseurl }}/assets/2012/03/low_image21.jpg)

2 - Quando solicitado o tipo de CA a ser instalada selecione a opção “Stand-alone CA” e clique em “next”.

[![low_image3]({{ site.baseurl }}/assets/2012/03/low_image31.jpg)]({{ site.baseurl }}/assets/2012/03/low_image31.jpg)

3 - Preencha os dados solicitados para o cadastramento da CA conforme ilustra a imagem abaixo.

### [![low_image4]({{ site.baseurl }}/assets/2012/03/low_image41.jpg)]({{ site.baseurl }}/assets/2012/03/low_image41.jpg)

### Exportando o certificado PKCS#12 da CA

1 – Abra a console de gerenciamento de autoridade certificadora em **Start > Administrative Tools > Certification Authority (Iniciar > Ferramentas Administrativas > Autoridade de certificação)**

[![low_image5]({{ site.baseurl }}/assets/2012/03/low_image51.jpg)]({{ site.baseurl }}/assets/2012/03/low_image51.jpg)

2 – Selecione a sua CA

[![low_image6]({{ site.baseurl }}/assets/2012/03/low_image61.jpg)]({{ site.baseurl }}/assets/2012/03/low_image61.jpg)

3 – Nestes próximos passos iremos exportar o certificado X.509 da CA.

Clique com o botão direito do mouse e clique em **Properties (Propriedades)**

[![low_image7]({{ site.baseurl }}/assets/2012/03/low_image71.jpg)]({{ site.baseurl }}/assets/2012/03/low_image71.jpg)

4 – Selecione o último certificado da CA e clique em **View Certificate (Exibir certificado)**

![low_image8]({{ site.baseurl }}/assets/2012/03/low_image81.jpg)

4 – Na tela de visualização do certificado clique em **Details (detalhes)** e depois em **Copy to file (Copiar para arquivo)**

[![low_image9]({{ site.baseurl }}/assets/2012/03/low_image91.jpg)]({{ site.baseurl }}/assets/2012/03/low_image91.jpg)

5 – Selecione um local para salvar o arquivo. Este é o arquivo que será utilizado futuramente.

6 – Nestes próximos passos iremos Exportar o arquivo no formato PKCS#12.

Volte para a tela principal da autoridade certificadora. Clique com o botão direito do mouse no nome da CA e clique em **All Tasks (Todas as tarefas)** e clique em **Back up CA (Fazer Backup da autoridade de cert...)**

[![low_image10]({{ site.baseurl }}/assets/2012/03/low_image101.jpg)]({{ site.baseurl }}/assets/2012/03/low_image101.jpg)

7 - Na próxima tela clique em **Avançar**. Na tela subseqüente selecione somente o item **Private key and CA certificate (Chave particular e certificado de autoridade de certificação)**, indique o diretório onde será salvo o arquivo, clique em **avançar**.

[![low_image11]({{ site.baseurl }}/assets/2012/03/low_image111.jpg)]({{ site.baseurl }}/assets/2012/03/low_image111.jpg)

8 - Nesta tela (baixo) indique a senha de proteção do arquivo PKCS#12. Esta senha será utilizada no momento da importação do arquivo PKCS#12 em outros sistemas.

[![low_image12]({{ site.baseurl }}/assets/2012/03/low_image121.jpg)]({{ site.baseurl }}/assets/2012/03/low_image121.jpg)

Após este processo será gerado o arquivo PKCS#12 com a chave privada e o certificado desta CA.

### Efetuando o download do certificado X.509 da CA

1 - Para acessar a console de usuário, onde efetuaremos os downloads e requisições, basta entrar em um navegador como o Internet Explorer, Firefox, etc, e acessar o endereço “http://ip_do_servidor/CertSrv/”.

[![low_image13]({{ site.baseurl }}/assets/2012/03/low_image131.jpg)]({{ site.baseurl }}/assets/2012/03/low_image131.jpg)

2 - Após acessar esta tela, selecione o link **Download a CA certificate, certificate chain, or CRL** para acessar a tela de download do certificado root.

[![low_image14]({{ site.baseurl }}/assets/2012/03/low_image141.jpg)]({{ site.baseurl }}/assets/2012/03/low_image141.jpg)

3 - Selecione o certificado, geralmente há somente um, selecione o método de compactação (Base 64), clique em **Download CA certificate** e salve o arquivo.

Alguns produtos de mercado só trabalham com certificados o formato **Base 64**, desta forma todos os arquivos devem ser feito com esta codificação.
