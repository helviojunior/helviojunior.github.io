---
layout: post
title: Instalando uma autoridade certificadora (CA) intermediária com OpenSSL
date: 2012-03-07 13:22:31.000000000 -03:00
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
permalink: "/it/security/instalando-uma-ca-intermediaria-com-openssl/"
---

Este post demonstra como realizar a criação de uma autoridade certificadora intermediária.

<!--more-->

### 1.           Ambiente

[![image15]({{ site.baseurl }}/assets/2012/03/image15.jpeg)]({{ site.baseurl }}/assets/2012/03/image15.jpeg)

Conforme pode-se observar na imagem acima há uma CA raiz e neste momento iremos criar a CA1 para que esta possa posteriormente assinar os certificados.

Para a criação de uma CA intermediária é necessário o certificado X.509 da CA raiz.

<!--more-->

### 2.           Instalando no windows

Para a instalação deste processo no Windows basta efetuar os mesmos passos indicados POST [Instalando Autoridade certificadora raiz (CA Root) com windows](http://www.helviojunior.com.br/uncategorized/instalando-autoridade-certificadora-raiz-ca-root-com-windows/), porém alterando de **Stand-alone CA** para **Stand-alone subordinate CA**.

### 3.           Instalando com OpenSSL

Este ambiente considera que há uma estrutura de diretórios da seguinte forma:

```text
C:\treinamentocas
C:\treinamentocas\Root
C:\treinamentocas\IM1
```

Onde **C:\treinamentocas\Root** objetiva armazenar os arquivo da CA raiz e **C:\treinamentocas\IM1** os arquivos da CA intermediaria.

### 3.1.     Criando o arquivo de configuração do openssl

Crie nos diretórios **C:\treinamentocas\Root** e **C:\treinamentocas\IM1** um arquivo nomeado **openssl.conf** com o conteúdo abaixo:

```bash
# Início do arquivo openssl.conf
#

RANDFILE        = .rnd

####################################################################
[ ca ]
default_ca    = CA_default        # The default ca section

####################################################################
[ CA_default ]
certs        = certs            # Where the issued certs are kept
crl_dir        = crl            # Where the issued crl are kept
database    = database.txt        # database index file.
new_certs_dir    = certs            # default place for new certs.
certificate    = cacert.pem            # The CA certificate
serial        = serial.txt         # The current serial number
crl        = crl.pem         # The current CRL
private_key    = private\cakey.pem       # The private key
RANDFILE    = private\private.rnd     # private random number file
x509_extensions    = x509v3_extensions    # The extentions to add to the cert
default_days    = 365            # how long to certify for
default_crl_days= 30            # how long before next CRL
default_md    = md5            # which md to use.
preserve    = no            # keep passed DN ordering
policy        = policy_match

# For the CA policy
[ policy_match ]
commonName        = supplied
emailAddress        = optional
countryName        = optional
stateOrProvinceName    = optional
organizationName    = optional
organizationalUnitName    = optional

# For the 'anything' policy
[ policy_anything ]
commonName        = supplied
emailAddress        = optional
countryName        = optional
stateOrProvinceName    = optional
localityName        = optional
organizationName    = optional
organizationalUnitName    = optional

####################################################################
[ req ]
default_bits        = 1024
default_keyfile     = privkey.pem
distinguished_name    = req_distinguished_name
attributes        = req_attributes

[ req_distinguished_name ]
commonName            = Common Name (eg, your website's domain name)
commonName_max            = 64
emailAddress            = Email Address
emailAddress_max        = 40
countryName            = Country Name (2 letter code)
countryName_min            = 2
countryName_max            = 2
countryName_default        = BR
stateOrProvinceName        = State or Province Name (full name)
localityName            = Locality Name (eg, city)
0.organizationName        = Organization Name (eg, company)
organizationalUnitName        = Organizational Unit Name (eg, section)

[ req_attributes ]
challengePassword        = A challenge password
challengePassword_min        = 4
challengePassword_max        = 20

[ v3_ca ]
certificatePolicies=2.5.29.32.0
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints=critical,CA:TRUE
keyUsage = critical,cRLSign, keyCertSign, digitalSignature

[ v3_ca_req ]
certificatePolicies=2.5.29.32.0
basicConstraints=critical,CA:TRUE

#
# Final do arquivo openssl.conf
```

### 3.2.     Extraindo a chave privada e o certificado X.509 do arquivo PKCS#12 da CA raiz

Copie o arquivo PKCS#12 da CA raiz para o diretório **C:\treinamentocas\Root**

Extraia do PKCS#12 a chave privada. Neste momento serão solicitadas duas senhas, a primeira para abertura do arquivo PKCS#12 e a segunda para a segurança da chave privada.

```text
openssl pkcs12 -in ca.pfx -out ca.key -nocerts
```

Extrais do PKCS#12 o certificado X.509. Neste momento será solicitada a senha do arquivo PKCS#12

```text
openssl pkcs12 -in ca.pfx -nokeys -clcerts -out ca.cer
```

### 4.     Criando a CA intermediaria

Entre no diretório **C:\treinamentocas\IM1**

Gere a chave privada da CA intermediaria. Neste passo será solicitado uma senha para segurança da chave privada.

```text
openssl genrsa -des3 -out imca.key 1024
```

Gere a requisição do certificado desta CA. A requisição deste certificado necessita passar alguns parâmetros de forma a possibilitar que o certificado X.509 gerado a partir da assinatura (por parte da CA raiz) desta requisição permita a utilização como uma CA, ou seja, assine novos certificados. Para isso é utilizado a seção **v3_ca_req** do arquivo openssl.conf.

Neste passo será solicitado a senha de abertura da chave privada.

```text
openssl req -reqexts v3_ca_req -new -sha1 -key imca.key -out imcarequest.csr -config openssl.conf
```

Copie o arquivo **imcarequest.csr** para o diretorio **C:\treinamentocas\Root**

Entre no diretório **C:\treinamentocas\Root**

Faça a assinatura da requisição do certificado da autoridade certificadora intermediaria. Neste passo será solicitada a senha da chave privada da CA raiz (a mesma cadastrada no item 5.3.2 deste documento).

```text
openssl ca -days 365 -md sha1 -cert ca.cer -keyfile ca.key -out imca.cer -in imcarequest.csr -config openssl.conf
```

Copie o arquivo imca.cer (arquivo X.509 da CA intermediaria) para o diretório **C:\treinamentocas\IM1**

Entre no diretório **C:\treinamentocas\IM1**

Gere o arquivo PKCS#12 da CA intermediaria

```text
openssl pkcs12 -export -out imca.pfx -in imca.cer -inkey imca.key
```

[Download do OpenSSL Standalone]({{ site.baseurl }}/assets/2012/03/OpenSSL.zip)
