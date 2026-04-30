---
layout: post
title: Configurando Postfix para usar SMTP do Gmail no Ubuntu
date: 2015-10-20 11:06:28.000000000 -02:00
type: post
parent_id: '0'
published: true
password: ''
status: publish
categories:
- Linux
tags: []
author: Helvio Junior (m4v3r1ck)
permalink: "/it/linux/configurando-postfix-para-usar-smtp-do-gmail-no-ubuntu/"
---

Este post tem por objetivo demonstrar como configurar o Postfix para enviar e-mails através do SMTP do Gmail como relay. Como ambiente para este post foi utilizado o Ununti 14.04. Caso tenha algum problema por favor utilize a sessão de comentários para posta-lo.

<!--more-->

## Fazendo relay do Postfix via smtp.gmail.com:

Primeiramente realize a instalação dos pacotes necessários

```bash
sudo apt-get install postfix mailutils libsasl2-2 ca-certificates libsasl2-modules
```

Caso você ainda não tenha uma instalação do Postfix em seu sistema ele fará alguns questionamentos a você. Basta selecionar a opção **Servidor para a internet** e usar um nome completo (FQDN) para o seu servidor como **mail.exemplo.com.br**.

Edite o arquivo de configuração **/etc/postfix/main.cf** e adicione as seguintes linhas:

```bash
relayhost = [smtp.gmail.com]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/postfix/cacert.pem
smtp_use_tls = yes
```

Edite/crie o arquivo **/etc/postfix/sasl_passwd** e deixe ele com a seguinte informação:

```bash
[smtp.gmail.com]:587    USERNAME@gmail.com:PASSWORD
```

Caso você utilize o Google Apps, basta alterar o domínio @gmail.com para o seu domínio exemplo @helviojunior.com.br

Corrija as permissões do arquivo e atualize o postfix para utilizar o arquivo **/etc/postfix/sasl_passwd** com os comandos abaixo:

```bash
sudo chmod 400 /etc/postfix/sasl_passwd
sudo postmap /etc/postfix/sasl_passwd
```

Valide o certificado digital para avitar erros rodando o seguinte comando:

```bash
cat /etc/ssl/certs/Thawte_Premium_Server_CA.pem | sudo tee -a /etc/postfix/cacert.pem
```

Por fim reinicie o serviço do Postfix

```bash
sudo /etc/init.d/postfix reload
```

## Testando

Verifique se os e-mails estão sendo enviado através do Gmail, se tudo estiver correto através do comando abaixo você enviará um e-mail para sua caixa postal usando o Gmail como relay.

```bash
echo "Teste de e-mail com postfix" | mail -s "Teste Postfix" voce@exemplo.com.br
```

### Referência

Este artigo foi baseado no artigo: [https://rtcamp.com/tutorials/linux/ubuntu-postfix-gmail-smtp/](https://rtcamp.com/tutorials/linux/ubuntu-postfix-gmail-smtp/)
