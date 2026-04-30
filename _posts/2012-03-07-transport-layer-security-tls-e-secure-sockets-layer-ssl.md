---
layout: post
title: Transport Layer Security (TLS) e Secure Sockets Layer (SSL)
date: 2012-03-07 12:07:51.000000000 -03:00
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
- ssl
- tls
author: Helvio Junior (m4v3r1ck)
permalink: "/it/security/transport-layer-security-tls-e-secure-sockets-layer-ssl/"
---

O TLS/SSL é utilizado para garantir a confidencialidade e autenticidade de servidores e clientes na internet, o seu uso é mais comum em protocolos como HTTP e SMTP comumente chamados de HTTPS e SMTPS.

<!--more-->

## O que é TLS/SSL?

O Transport Layer Security - TLS (Segurança da Camada de Transporte) e o seu predecessor, Secure Sockets Layer - SSL (Protocolo de Camada de Sockets Segura), são protocolos criptográficos que conferem segurança de comunicação na Internet para serviços como email (SMTP), navegação por páginas (HTTP) e outros tipos de transferência de dados. Há algumas pequenas diferenças entre o SSL 3.0 e o TLS 1.0, mas o protocolo permanece substancialmente o mesmo. O termo "SSL" usado aqui aplica-se a ambos os protocolos.

O SSL é um protocolo que se utiliza de dois tipos de criptografia (Assimétrica e Simétrica). Onde inicialmente estabelece a conexão com uma criptografia assimétrica e através desta conexão segura realiza a troca de chave da criptografia simétrica e por fim continua a comunicação dos dados com uma criptografia simétrica.

Este fluxo resolve diversos problemas que se tem utilizando os modelos de criptografia simétrica/assimétrica separadamente:

- Criptografia simétrica
  - Rápido;
  - Uma só chave para cifrar e decifrar;
  - Problema para a troca de chaves (pois o cliente e servidor precisam conhecer a chave).
- Criptografia assimétrica
  - Lento;
  - Usa um par de chaves. Onde uma chave cifra e outra decifra;
  - O cliente precisa apenas conhecer a chave pública para cifrar e enviar os dados ao servidor, que por sua vez consegue decifrar a informação com a chave privada.

Para maiores detalhes sobre criptografia verifique o post [Certificação digital](http://www.helviojunior.com.br/security/certificacao-digital/)

O SSL foi criado como um protocolo separado para segurança, sendo considerado como uma nova camada na arquitetura TCP/IP conforme demonstrado na figura abaixo:

[![TLS]({{ site.baseurl }}/assets/2012/03/image1.jpg)]({{ site.baseurl }}/assets/2012/03/image1.jpg)

Esta metodologia permite que o SSL seja utilizado para outras aplicações que não sejam o HTTP, como por exemplo, o FTP, POP3 e SMTP.

[![Protocolo + TLS]({{ site.baseurl }}/assets/2012/03/image2.jpg)]({{ site.baseurl }}/assets/2012/03/image2.jpg)

Sem a utilização do SLL uma conexão é estabelecida com o seguinte fluxo:

1. Handshake TCP
2. O cliente e o servidor iniciam o processo normal definido pelo protocolo de camada de aplicação (HTTP, SMTP, FTP, POP3 e outros)

Com a utilização do SSL a conexão é estabelecida com o seguinte fluxo:

1. Handshake TCP
2. Processo de **autenticação** e **encriptação** (descritos detalhadamente no próximo item)
3. O cliente e o servidor iniciam o processo normal definido pelo protocolo de camada de aplicação (HTTP, SMTP, FTP, POP3 e outros)

Observe que a conexão com o SSL adicionou um passo antes que o protocolo de aplicação fosse iniciado.

## Estabelecimento de uma conexão segura

A figura abaixo demonstra de forma sintetizada os passos do processo de negociação para que se estabeleça uma conexão segura.

[![TLS Steps]({{ site.baseurl }}/assets/2012/03/image3.jpg)]({{ site.baseurl }}/assets/2012/03/image3.jpg)

| **Passo** | **Ação** |
| --- | --- |
| **1** | O Cliente envia a mensagem *ClientHello* propondo uma conexão segura com as opções SSL |
| **2** | O servidor responde com uma mensagem *ServerHello* selecionando a opção SSL |
| **3** | O servidor envia seu certificado de chave pública (certificado X.509) na mensagem *Certificate.* |
| **4** | O servidor conclui essa parte da negociação com a mensagem *ServerHelloDone* |
| **5** | O cliente envia a chave de sessão (encriptado com a chave pública do servidor) na mensagem *ClientKeyExchange* |
| **6** | O Cliente envia a mensagem *ChangeCipherSpec* para ativar as opções previamente negociadas para as próximas mensagens enviadas |
| **7** | O Cliente envia a mensagem *Finished* para que o servidor verifique as opções recentemente ativadas |
| **8** | O servidor envia a mensagem *ChangeCipherSpec* para ativar as opções previamente negociadas para as próximas mensagens enviadas |
| **9** | O Servidor envia a mensagem *Finished* para que o cliente as opções recentemente ativadas |

## Referencias bibliográficas

THOMAS, Stephen A, **SLL & TLS Essential: Securing the Web**. Ed. New York: Elsevier, 2000.
