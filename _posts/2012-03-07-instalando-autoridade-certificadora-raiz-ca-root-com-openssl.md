---
layout: post
title: Instalando autoridade certificadora raiz (CA Root) com OpenSSL
date: 2012-03-07 12:56:35.000000000 -03:00
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
- ca root
- certificate authority
- openssl
author: Helvio Junior (m4v3r1ck)
permalink: "/it/security/instalando-autoridade-certificadora-raiz-ca-root-com-openssl/"
---

Este método de geração de uma CA utiliza-se do aplicativo OpenSSL disponível para Windows e linux, não tendo alteração dos comandos para os diferentes sistemas operacionais.

<!--more-->

1 – Efetue a instalação do OpenSSL;

2 – Crie um diretório para utilizações durante este processo.

3 – Crie um arquivo, dentro deste diretório, vazio, com o nome “database.txt”

4 – Crie um arquivo, dentro deste diretório, contendo o texto 01, com o nome “serial.txt”

5 – Crie um arquivo nomeado “openssl.conf” e adicione o seguinte conteúdo:

```text
RANDFILE  = .rnd

[ ca ]
default_ca       = CA_default

[ CA_default ]
certs            = certs
crl_dir          = crl
database  = database.txt
new_certs_dir    = certs
certificate      = cacert.pem
serial           = serial.txt
crl       = crl.pem
private_key      = private\cakey.pem
RANDFILE  = private\private.rnd
default_days     = 365
default_crl_days= 3
default_md       = sha1
preserve  = no
policy           = policy_match

[ policy_match ]
commonName              = supplied
emailAddress            = optional
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName = optional
organizationalUnitName  = optional

[ req ]
default_bits            = 1024
default_keyfile = privkey.pem
distinguished_name      = req_distinguished_name

[ req_distinguished_name ]
commonName                    = Common Name (eg, your website's domain name)
commonName_max                = 64
emailAddress                  = Email Address
emailAddress_max        = 40
countryName                   = Country Name (2 letter code)
countryName_min               = 2
countryName_max               = 2
countryName_default           = BR
stateOrProvinceName           = State or Province Name (full name)
localityName                  = Locality Name (eg, city)
0.organizationName            = Organization Name (eg, company)
organizationalUnitName        = Organizational Unit Name (eg, section)
countryName_default           = BR

[ v3_ca ]
certificatePolicies=2.5.29.32.0
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints=critical,CA:TRUE
keyUsage = critical,cRLSign, keyCertSign, digitalSignature
```

6 – Crie a chave privada da CA root que será utilizada futiramente

```bash
openssl genrsa -des3 -out ca.key 1024
```

Neste momento será solicitado a senha para armazenamento da chave, está senha será utilizada posteriormente para abertura da chave privada.

```text
Loading 'screen' into random state - done
Generating RSA private key, 1024 bit long modulus
..............++++++
...............++++++
e is 65537 (0x10001)
Enter pass phrase for ca.key:
```

7 – Crie o certificado X.509. Este é o arquivo que será utilizado futuramente para instalação nos clientes.

```bash
openssl req -extensions v3_ca -config openssl.conf -new -x509 -days 3650 -key ca.key -out ca.cer
```

Neste momento algumas informações serão solicitadas, a primeira delas é a senha da chave privada criada no passo anterior.

```text
Enter pass phrase for ca.key:
```

Agora serão solicitados os dados do certificado, o único item obrigatório é o Common Name (CN), nele adicione o nome como deseja que a sua CA seja identificada.

Após a finalização deste processo temos o nosso certificado conforme imagem abaixo:

[![Certificado digital root]({{ site.baseurl }}/assets/2012/03/low_image15.jpg)]({{ site.baseurl }}/assets/2012/03/low_image15.jpg)

Porém temos 2 arquivos, um para a chave privada e outro para o certificado, desta forma será necessário coloca-los em um único arquivo no formato PKCS#12.

8 – Crie o arquivo PKCS#12 com a chave privada e o certificado

```bash
openssl pkcs12 -export -out ca.pfx -in ca.cer -inkey ca.key
```

Neste processo serão solicitadas 2 senhas, a primeira para abertura da chave privada e a segunda para a exportação do arquivo PKCS#12. Esta segunda senha será utilizada no momento da importação do arquivo PKCS#12 no firewall.

```text
Enter pass phrase for ca.key:
Enter Export Password:
Verifying - Enter Export Password:
```

Pronto! O Certificado root foi gerado com sucesso.

```
Download do OpenSSL Standalone ({{ site.baseurl }}/assets/2012/03/OpenSSL.zip)
```
