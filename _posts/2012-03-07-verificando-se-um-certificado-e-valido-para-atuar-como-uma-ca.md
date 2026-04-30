---
layout: post
title: Verificando se um certificado é valido para atuar como uma autoridade certificadora
  (CA)
date: 2012-03-07 13:29:34.000000000 -03:00
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
author: Helvio Junior (m4v3r1ck)
permalink: "/it/security/verificando-se-um-certificado-e-valido-para-atuar-como-uma-ca/"
---

No campo **Basic Constraints (Restições básicas)** dentro do campo **Extensions (Extensões)** do certificado digital é necessário haver algumas informações para que este possa atuar como uma CA, ou seja, assinar novos certificados.

Para poder visualizar esta informação é necessário ter o certificado X.509, desta forma se o único certificado que temos é o PKCS#12 é preciso extrair dele o certificado X.509.

<!--more-->

### Extraindo o certificado X.509 de um arquivo PKCS#12

Utilize o comando abaixo:

```text
openssl pkcs12 -in cert.pfx -nokeys -clcerts -out cert.cer
```

Onde **cert.pfx** é o arquivo PKCS#12 e **cert.cer** é o certificado X.509.

### Visualizando as informações do certificado

Utilize o comando abaixo:

```text
openssl x509 -noout -text -in cert.cer
```

Onde **cert.cer** é o certificado X.509 que se deseja verificar as informações. Neste momento as seguintes informações serão mostradas:

```text
Certificate:
Data:
Version: 3 (0x2)
Serial Number: 32 (0x20)
Signature Algorithm: sha1WithRSAEncryption
Issuer: CN=teste.meudominio.com.br
Validity
Not Before: May 19 19:19:00 2011 GMT
Not After : May 18 19:19:00 2012 GMT
Subject: CN=im.meudominio.com.br, C=BR
Subject Public Key Info:
Public Key Algorithm: rsaEncryption
RSA Public Key: (1024 bit)
Modulus (1024 bit):
00:b2:29:86:71:48:a5:77:49:f8:6c:6e:6b:46:71:
08:46:59:2f:fe:c3:ef:d7:69:4c:ea:ec:5a:da:a1:
e6:45:26:e3:46:ab:85:b9:73:60:e9:4d:a9:72:3e:
7c:53:7d:80:a5:4b:2e:7a:dc:47:bc:0c:cd:cc:e7:
7d:82:00:fb:97:4a:c5:c3:ff:1b:57:a3:2a:13:f6:
41:f7:37:9c:a7:b8:87:31:b5:28:8f:f9:5c:9d:80:
20:43:dc:88:aa:1b:e0:4b:8b:40:ce:26:ca:d8:f2:
63:09:74:76:f0:14:6d:e9:dc:2f:76:dc:9d:74:5e:
9e:91:dc:2c:1f:c1:e5:79:85
Exponent: 65537 (0x10001)
X509v3 extensions:
X509v3 Certificate Policies:
Policy: X509v3 Any Policy

X509v3 Subject Key Identifier:
4B:64:70:6B:5A:71:E2:C5:A0:3D:88:7A:63:1E:C4:59:E4:2E:62:16
X509v3 Authority Key Identifier:
keyid:0F:BC:D2:E6:35:1F:7D:35:D2:22:FE:70:9A:EC:BF:7B:FB:F6:32:77

X509v3 Basic Constraints: critical
CA:TRUE
X509v3 Key Usage: critical
Digital Signature, Certificate Sign, CRL Sign
Signature Algorithm: sha1WithRSAEncryption
63:19:87:b0:de:11:d3:7c:58:98:20:a5:fc:cd:4c:b7:7c:5c:
1a:e6:df:1e:a4:73:bc:71:9e:71:5d:cf:c5:51:41:a1:40:31:
38:37:dc:7e:48:39:6b:bc:6b:13:88:8b:17:e8:9f:b9:12:7c:
38:68:03:4c:aa:ad:cf:f5:95:0e:3b:01:93:43:11:8f:91:ca:
8d:57:8e:cc:99:3f:0d:76:4f:21:a3:34:48:e2:a7:d3:45:3a:
8c:83:cb:49:e4:4e:e9:67:fa:12:cc:a3:0e:df:36:30:ec:e2:
6f:bc:6f:4b:9b:91:98:13:be:27:f8:50:50:18:2f:52:47:ee:
92:35
```

Dentre todas essas informações, neste momento, duas são importantes e ambas estão dentro das extensões do certificado.

```text
Certificate:
Data:
X509v3 extensions:
X509v3 Certificate Policies:
Policy: X509v3 Any Policy
X509v3 Basic Constraints: critical
CA:TRUE
```

A extensão **Certificate Policies (poiticas do certificado)** indica o que este certificado pode fazer. Para que o certificado possa atuar como CA neste campo deve estar presente o item **X509v3 Any Policy** indicando que este certificado pode ser utilizado para qualquer finalidade.

Outra extensão a ser observada é a **Basic Constraints (Restições básicas)**. Para que este certificado possa assinar novos certificados neste campo deve estar presente o item **CA:TRUE** indicando que este certificado é de uma CA.

Somente quando estes dois itens estiverem presentes no certificado o mesmo pode ser utilizado como certificado de uma CA.

```
Download do OpenSSL Standalone ({{ site.baseurl }}/assets/2012/03/OpenSSL.zip)
```
