---
layout: post
title: Instalando certificado digital no windows com C#
date: 2012-03-09 15:08:54.000000000 -03:00
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
permalink: "/it/devel/instalando-certificado-digital-no-windows-com-c/"
---

Este post objetiva mostrar como realizar a instalação de um certificado digital na base de certificados pessoais do usuário através de um aplicativo C#.

<!--more-->

Quando executado o aplicativo o certificado será instalado na base de certificados pessoais do usuário executor do aplicativo.

Segue o código:

```csharp
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace InstallCertificate
{
 class Program
 {
 public static void Main(string[] args)
 {
 try {
 InstallCertificate(args[0], args[1]);

 } catch (Exception ex) {
 Console.WriteLine( ex.Message);
 }

 Console.Write("");
 Console.Write("Press any key to continue . . . ");
 Console.ReadKey(true);
 }

 private static void InstallCertificate(string certificatePath, string certificatePassword)
 {
 try
 {
 var serviceRuntimeUserCertificateStore = new X509Store(StoreName.My);
 serviceRuntimeUserCertificateStore.Open(OpenFlags.ReadWrite);

 X509Certificate2 cert;

 try
 {
 cert = new X509Certificate2(certificatePath, certificatePassword);
 }
 catch(Exception ex)
 {
 Console.WriteLine("Failed to load certificate " + certificatePath + ": " + ex.Message);
 throw new Exception("Certificate appeared to load successfully but also seems to be null.", ex);
 }

 serviceRuntimeUserCertificateStore.Add(cert);
 serviceRuntimeUserCertificateStore.Close();
 Console.WriteLine("Installation OK!");
 }
 catch(Exception ex)
 {
 Console.WriteLine("Failed to install {0}. Check the certificate index entry and verify the certificate file exists.\n {1}", certificatePath, ex.Message);
 }
 }

 }
}
```
