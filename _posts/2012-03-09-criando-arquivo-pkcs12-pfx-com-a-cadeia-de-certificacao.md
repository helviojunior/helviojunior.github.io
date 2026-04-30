---
layout: post
title: Criando arquivo PKCS#12 (pfx) com a cadeia de certificação
date: 2012-03-09 14:57:58.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- IT
- Segurança da Informação
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/security/criando-arquivo-pkcs12-pfx-com-a-cadeia-de-certificacao/"
---

Este post objetiva mostrar como gerar um arquivo PKCS#12 (comumente conhecido pela extensão .pfx) embutindo toda a cadeia de certificação.

<!--more-->

Para gerar o arquivo PKCS#12 com a cadeia de certificação completa é necessário obter todos os certificados X.509 (.cer) do caminho.

[![Cert-chain]({{ site.baseurl }}/assets/2012/03/Cert-chain.jpg)]({{ site.baseurl }}/assets/2012/03/Cert-chain.jpg)

Para este post vamos supor que há 4 níveis na cadeia de certificação. Onde o N1 é a CA Root, N2 e N3 são as CAs intermediarias e N4 é o certificado final.

Tendo todos os certificados no formato X.509 (.cer) e a Chave privada do certificado N4 podemos gerar o PKCS#12 (pfx) com a cadeia completa.

Para isso é necessário primeiro criar um arquivo com toda a cadeia. Execute o comando abaixo para gerar este arquivo.

```bash
#Windows
copy n3.cer +n2.cer + n1.cer chain.pem

#Linux
cat n3.cer n2.cer n1.cer > chain.pem
```

Depois realize a geração do PKCS#12 com a cadeia executando o comando

```bash
openssl pkcs12 -export  -chain -out certificado.pfx -in n4.cer -inkey n4.key -CAfile chain.pem
```

[Download do OpenSSL Standalone]({{ site.baseurl }}/assets/2012/03/OpenSSL.zip)
