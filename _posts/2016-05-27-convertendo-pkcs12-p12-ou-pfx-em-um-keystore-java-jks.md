---
layout: post
title: Convertendo PKCS#12 (.p12 ou .pfx) em um KeyStore Java JKS
date: 2016-05-27 12:37:03.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/convertendo-pkcs12-p12-ou-pfx-em-um-keystore-java-jks/"
---

Neste post mostrarei como converter um arquivo PKCS#12 (.p12 ou .pfx) para um KeyStore Java no formato JKS.

Tanto o arquivo PKCS#12 como o JSK contem o certificado X509 a chave privada assiciada ao mesmo.

Então mãos na massa!

Caso você tenha alguma dúvida de como gerar o arquivo PKCS#12 basta dar uma olhadinha nestes 2 outros posts aqui no site mesmo, eles podem lhe ajudar.

- [Instalando autoridade certificadora raiz (CA Root) com OpenSSL](http://www.helviojunior.com.br/it/security/instalando-autoridade-certificadora-raiz-ca-root-com-openssl/)
- [Criando arquivo PKCS#12 (pfx) com a cadeia de certificação](http://www.helviojunior.com.br/it/security/criando-arquivo-pkcs12-pfx-com-a-cadeia-de-certificacao/)

Antes de tentar realizar a conversão é necessário realizar a instalação do JAVA JDK e configuração para que no Path do sistema operacional tenha o caminho ***%programfiles%\java\jdk1.6.0_21\bin***. Vale a pena observar que o caminho pode se alterar conforme a versão do JDK que está instalado.

```bash
keytool -importkeystore -srckeystore mykeystore.p12 -destkeystore clientcert.jks -srcstoretype pkcs12 -deststoretype JKS -srcstorepass mystorepass -deststorepass myotherstorepass -srcalias myserverkey -destalias myotherserverkey -srckeypass mykeypass -destkeypass myotherkeypass
```

Caso necessite você pode listar o certificado do KeyStore com o comando

```bash
keytool -v -list -keystore mykeystore.p12
```
