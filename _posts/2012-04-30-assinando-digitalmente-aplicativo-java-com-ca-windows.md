---
layout: post
title: Assinando digitalmente aplicativo JAVA com CA Windows
date: 2012-04-30 14:29:53.000000000 -03:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Desenvolvimento
- IT
- Segurança da Informação
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/devel/assinando-digitalmente-aplicativo-java-com-ca-windows/"
---

O Objetivo deste post é demonstrar como realizar a assinatura de um aplicativo JAVA utilizando uma Autoridade Certificadora (CA) Windows.

### **Motivação**

Em um ambiente corporativo com infraestrutura de domínio e Active Directory já existe uma autoridade certificadora e todos os membros do domínio já confiam nos certificados assinados por esta CA. Desta forma facilita o trabalho de publicação do aplicativo e confiança da assinatura digital deste.

<!--more-->

### **Pré-requisito**

Este post tem como pré-requisito o Windows 2003 Enterprise Edition ou DataCenter Edition. E Acredite não adianta tentar no Standard Edition que não funciona.

### **Passos de uma assinatura de aplicativo:**

Para realizar a assinatura digital de um aplicativo alguns passos são necessários:

1. Gerar requisição do certificado;
2. Assinar o certificado através da CA;
3. Gerar o arquivo no padrão PKCS#12;
4. Assinar o aplicativo;
5. Verificação da assinatura do aplicativo.

## 1.  Gerando requisição do certificado

Para a geração da requisição do certificado será utilizado o OpenSSL (download do OpenSSL no final do post) por se tratar de um aplicativo OpenSource, de fácil utilização, e com uma completa documentação.

### 1.1. Configurando OpenSSL

Para a realização deste procedimento é necessário criar um diretório onde serão salvos diversos arquivos. Neste post o diretório criado foi **C:\CodSign**

Crie um arquivo nomeado openssl.conf neste diretório com o seguinte conteúdo:

```bash
# Início do arquivo openssl.conf
#
# Criado por Helvio Junior
# helvio_junior@hotmail.com

RANDFILE        = openssl/.rnd

####################################################################
[ ca ]
default_ca    = CA_default        # The default ca section

####################################################################
[ CA_default ]

certs        = openssl/certs            # Where the issued certs are kept
crl_dir        = openssl/crl            # Where the issued crl are kept
database    = openssl/database.txt        # database index file.
new_certs_dir    = openssl/certs            # default place for new certs.

certificate    = cacert.pem            # The CA certificate
serial        = openssl/serial.txt         # The current serial number
crl        = crl.pem         # The current CRL
private_key    = private/cakey.pem       # The private key
RANDFILE    = private/private.rnd     # private random number file

x509_extensions    = x509v3_extensions    # The extentions to add to the cert
default_days    = 365            # how long to certify for
default_crl_days= 30            # how long before next CRL
default_md    = md5            # which md to use.
preserve    = no            # keep passed DN ordering

# A few difference way of specifying how similar the request should look
# For type CA, the listed attributes must be the same, and the optional
# and supplied fields are just that :-)
policy        = policy_match

# For the CA policy
[ policy_match ]
commonName        = supplied
emailAddress        = optional
countryName        = optional
stateOrProvinceName    = optional
organizationName    = optional
organizationalUnitName    = optional

# For the 'anything' policy
# At this point in time, you must list all acceptable 'object'
# types.
[ policy_anything ]
commonName        = supplied
emailAddress        = optional
countryName        = optional
stateOrProvinceName    = optional
localityName        = optional
organizationName    = optional
organizationalUnitName    = optional

####################################################################
[ req ]
default_bits        = 1024
default_keyfile     = privkey.pem
distinguished_name    = req_distinguished_name
attributes        = req_attributes

[ req_distinguished_name ]
commonName            = Common Name (eg, your application name)
commonName_max            = 64
emailAddress            = Email Address
emailAddress_max        = 40
countryName            = Country Name (2 letter code)
countryName_min            = 2
countryName_max            = 2
countryName_default        = BR
stateOrProvinceName        = State or Province Name (full name)
localityName            = Locality Name (eg, city)
0.organizationName        = Organization Name (eg, company)
organizationalUnitName        = Organizational Unit Name (eg, section)

[ req_attributes ]
challengePassword        = A challenge password
challengePassword_min        = 4
challengePassword_max        = 20

[ v3_code_sign ]
#Code Sign Object Identifier
certificatePolicies=1.3.6.1.5.5.7.3.3

#
# Final do arquivo openssl.conf
```

[![022]({{ site.baseurl }}/assets/2012/04/022.jpg)]({{ site.baseurl }}/assets/2012/04/022.jpg)

### 1.2. Gerando a chave privada do certificado

```bash
openssl genrsa -des3 -out .\app.key 2048
```

Ao executar este comando uma senha será solicitada, esta senha é de proteção da chave privada.

[![023]({{ site.baseurl }}/assets/2012/04/023.jpg)]({{ site.baseurl }}/assets/2012/04/023.jpg)

### 1.3. Gerando a requisição

```bash
openssl req -reqexts v3_code_sign -new -sha1 -key .\app.key -out .\app.csr -config .\openssl.conf
```

Ao executar este comando a senha da chave privada é solicitada.

[![024]({{ site.baseurl }}/assets/2012/04/024.jpg)]({{ site.baseurl }}/assets/2012/04/024.jpg)

Após a senha da chave são solicitados as informações do certificado.

[![025]({{ site.baseurl }}/assets/2012/04/025.jpg)]({{ site.baseurl }}/assets/2012/04/025.jpg)

### 1.4. Visualizando os arquivos e a requisição

Pode-se visualizar no diretório que 2 arquivos foram criados (app.key e app.csr), onde app.key é a chave privada que do certificado da aplicação e app.csr é a requisição de certificado.

[![026]({{ site.baseurl }}/assets/2012/04/026.jpg)]({{ site.baseurl }}/assets/2012/04/026.jpg)

Abrindo o arquivo app.csr no Bloco de Notas se pode ver a requisição em formato Base64.

[![027]({{ site.baseurl }}/assets/2012/04/027.jpg)]({{ site.baseurl }}/assets/2012/04/027.jpg)

## 2. Assinar o certificado através da CA

Para realizar a assinatura do certificado é necessário realizar algumas configurações prévias na CA. Este post considera que a CA está instalada e operacional no Windows 2003 Enterpreise Edition ou no Windows 2003 Data Center Edition.

### 2.1. Criando template na CA

Abra o gerenciador da Autoridade Certificadora

[![002]({{ site.baseurl }}/assets/2012/04/002.jpg)]({{ site.baseurl }}/assets/2012/04/002.jpg)

Clique no nome da sua CA, expanda a arvore, vá em ***Certificate Templates****,* Clique com o botão direito e clique em ***Manage****.*

[![003]({{ site.baseurl }}/assets/2012/04/003.jpg)]({{ site.baseurl }}/assets/2012/04/003.jpg)

Neste momento será aberto o gerenciador de templates. Selecione o Template ***Code Signing*** e clique em ***Duplicate Template***.

[![004]({{ site.baseurl }}/assets/2012/04/004.jpg)]({{ site.baseurl }}/assets/2012/04/004.jpg)

Na Aba General digite o nome do template, em nosso exemplo digitei ***Code Sigining Test***.

[![005]({{ site.baseurl }}/assets/2012/04/005.jpg)]({{ site.baseurl }}/assets/2012/04/005.jpg)

Vá até a aba ***Subject Name*** e altere a opção para ***Supply in the request*** para permitir que os dados da geração do certificado seja os dados informados no momento da geração da requisição.

[![005.2]({{ site.baseurl }}/assets/2012/04/005.2.jpg)]({{ site.baseurl }}/assets/2012/04/005.2.jpg)

E por último verifique a permissão de utilização deste template. Estas permissões definem os usuários que podem, entre outras coisas, assinar e ler  um certificado utilizando este template.

[![005.1]({{ site.baseurl }}/assets/2012/04/005.1.jpg)]({{ site.baseurl }}/assets/2012/04/005.1.jpg)

Clique em OK para finalizar a criação do template e feche o gerenciador de templates.

Até este ponto foi criado o template porém não foi disponibilizado na console WEB para utilização, desta forma os próximos passos objetiva realizar esta liberação.

Clique em ***Certificate Template*** com o botão direito e clique em ***new*** e ***Certificate Template to Issue***.

[![006]({{ site.baseurl }}/assets/2012/04/006.jpg)]({{ site.baseurl }}/assets/2012/04/006.jpg)

Selecione o template criado nos passos anteriores e clique em OK.

[![007]({{ site.baseurl }}/assets/2012/04/007.jpg)]({{ site.baseurl }}/assets/2012/04/007.jpg)

Pronto. Toda a configuração necessária na CA está concluída. Agora vamos aos passos de assinatura do certificado.

### 2.2. Assinando o certificado

Acesse a console web da CA.

[![008]({{ site.baseurl }}/assets/2012/04/008.jpg)]({{ site.baseurl }}/assets/2012/04/008.jpg)

Clique no link ***Request a Certificate***.

[![009]({{ site.baseurl }}/assets/2012/04/009.jpg)]({{ site.baseurl }}/assets/2012/04/009.jpg)

Clique no link ***advanced certificate request***.

[![010]({{ site.baseurl }}/assets/2012/04/010.jpg)]({{ site.baseurl }}/assets/2012/04/010.jpg)

Clique no link ***Submit a certificate request by using***...

[![011]({{ site.baseurl }}/assets/2012/04/011.jpg)]({{ site.baseurl }}/assets/2012/04/011.jpg)

Selecione o template criado nos passos anteriores, copie o conteúdo do arquivo ***app.csr*** (criado no passo 1), cole no campo ***Saved Request*** e clique em ***Submit***.

[![012]({{ site.baseurl }}/assets/2012/04/012.jpg)]({{ site.baseurl }}/assets/2012/04/012.jpg)

Se a assinatura for bem sucedida a tela abaixo deve ser exibida, selecione a opção de ***Base 64 encoded*** e clique em ***Download certificate*** e salve o certificado no mesmo local da requisição com o nome de ***app.cer***.

[![013]({{ site.baseurl }}/assets/2012/04/013.jpg)]({{ site.baseurl }}/assets/2012/04/013.jpg)

Nas imagens abaixo podemos ver as propriedades do certificado assinado.

[![014]({{ site.baseurl }}/assets/2012/04/014.jpg)]({{ site.baseurl }}/assets/2012/04/014.jpg)

[![015]({{ site.baseurl }}/assets/2012/04/015.jpg)]({{ site.baseurl }}/assets/2012/04/015.jpg)

[![016]({{ site.baseurl }}/assets/2012/04/016.jpg)]({{ site.baseurl }}/assets/2012/04/016.jpg)

[![017]({{ site.baseurl }}/assets/2012/04/017.jpg)]({{ site.baseurl }}/assets/2012/04/017.jpg)

Por último, volte a tela inicial da console web da CA e realize o download do certificado da CA clicando em ***Download a CA certificate***.

[![018]({{ site.baseurl }}/assets/2012/04/018.jpg)]({{ site.baseurl }}/assets/2012/04/018.jpg)

Selecione o certificado atual da CA, depois o Encoding ***Base 64*** e clique em ***Download CA Certificate.***

Salve o arquivo no mesmo local da requisição com o nome de ***ca.cer***.

## [![020]({{ site.baseurl }}/assets/2012/04/020.jpg)]({{ site.baseurl }}/assets/2012/04/020.jpg)

[![021]({{ site.baseurl }}/assets/2012/04/021.jpg)]({{ site.baseurl }}/assets/2012/04/021.jpg)

## 3. Geração do arquivo PKCS#12

Para a geração do PKCS#12 será utilizado o OpenSSL e é necessário a ***chave privada*** (app.key) + o ***certificado assinado*** (app.cer) + o **certificado da CA** (ca.cer).

Execute o comando abaixo

```bash
openssl pkcs12 -export -chain -name "APPSign001" -out .\app.pfx -in .\app.cer -inkey .\app.key -CAfile .\ca.cer
```

Ao executar este commando duas senhas serão solicitadas, a primeira é para abrir a chave privada, já a segunda (e sua confirmação) é a senha de exportação do PKCS#12. A senha da exportação pode ser diferente da senha da chave privada.

[![030]({{ site.baseurl }}/assets/2012/04/030.jpg)]({{ site.baseurl }}/assets/2012/04/030.jpg)

Neste comando há um item de importante que deve variar conforme  o seu ambiente **–name “AppSign001”** este define um apelido para o seu certificado, e este apelido que será utilizado na assinatura do JAVA, desta forma não pode ser suprimido. Este apelido pode ser alterado para o nome que desejar.

Neste ponto nosso diretório deve conter os seguintes arquivos

[![031]({{ site.baseurl }}/assets/2012/04/031.jpg)]({{ site.baseurl }}/assets/2012/04/031.jpg)

## 4. Assinado o aplicativo JAVA com o certificado gerado.

Para a assinatura é necessário a instalação do JAVA JDK e configuração para que no Path do sistema operacional tenha o caminho ***%programfiles%\java\jdk1.6.0_21\bin***. Vale a pena observar que o caminho pode se alterar conforme a versão do JDK que está instalado.

O Aplicativo que iremos assinar é um teste simples que mostra em tela um Hello World conforme demonstrado na imagem abaixo. O Aplicativo está disponível para download no final do post.

Copie o **teste.jar** para o diretório onde está o certificado digital.

[![032]({{ site.baseurl }}/assets/2012/04/032.jpg)]({{ site.baseurl }}/assets/2012/04/032.jpg)

Agora vamos verificar as classes do aplicativo bem como se há algum certificado assinando este aplicativo. Execute o comando abaixo:

```bash
jarsigner -verify -verbose -certs Teste.jar
```

[![033]({{ site.baseurl }}/assets/2012/04/033.jpg)]({{ site.baseurl }}/assets/2012/04/033.jpg)

Podemos observar que este aplicativo ainda não foi assinado. Para assinar este aplicativo execute o comando abaixo. Ao executar-lo a senha do PKCS#12 é solicitada.

```bash
jarsigner -storetype pkcs12 -keystore app.pfx Teste.jar APPSign001
```

[![034]({{ site.baseurl }}/assets/2012/04/034.jpg)]({{ site.baseurl }}/assets/2012/04/034.jpg)

Agora iremos novamente realizar a verificação da assinatura do aplicativo com o comando

```bash
jarsigner -verify -verbose -certs Teste.jar
```

[![035]({{ site.baseurl }}/assets/2012/04/035.jpg)]({{ site.baseurl }}/assets/2012/04/035.jpg)

Pronto o aplicativo está assinado digitalmente.

### Arquivos para download

[OpenSSL]({{ site.baseurl }}/assets/2012/03/OpenSSL.zip)

[OpenSSL.conf e teste.jar]({{ site.baseurl }}/assets/2012/04/CodeSign.zip)
